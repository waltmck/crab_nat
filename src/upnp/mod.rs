use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU16,
    time::Duration,
};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::{
    helpers, GatewayAddress, InternetProtocol, PortMapping, PortMappingOptions, PortMappingType,
    TimeoutConfig, RECOMMENDED_MAPPING_LIFETIME_SECONDS, SANE_MAX_REQUEST_RETRIES,
};

/// The port UPnP devices are required to listen on for SSDP search requests.
/// See section 1.2 of the UPnP Device Architecture, <https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v1.1.pdf>.
pub const DISCOVERY_PORT: u16 = 1900;

/// The maximum number of seconds a device may wait before responding to a search request.
/// Used as both the SSDP `MX` header value and the initial response timeout.
pub const SEARCH_WINDOW_SECONDS: u64 = 2;

/// The search targets identifying an internet gateway device, in the order they are sent.
/// Devices are required to respond to searches for lower versions of their supported device
/// and service types, so a single `InternetGatewayDevice:1` search should be sufficient.
/// However, some implementations only match specific device, service, or generic targets,
/// so a search is sent for each of these targets and all responses are considered.
pub const SEARCH_TARGETS: [&str; 3] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "upnp:rootdevice",
];

/// The maximum number of bytes we allow in an HTTP response, as protection against misbehaving devices.
/// Device descriptions observed in practice are tens of kilobytes at most.
pub const MAX_HTTP_RESPONSE_SIZE: usize = 256 * 1024;

/// The description reported to the gateway for port mappings created by this library.
/// Gateways commonly display this string in their management interfaces.
pub const PORT_MAPPING_DESCRIPTION: &str = "crab_nat";

/// The default `TimeoutConfig` for UPnP requests.
/// The initial timeout matches the `MX` response window given in SSDP search requests, and
/// retries are not delayed further, since a compliant device responds within the `MX` window.
/// TCP exchanges with the gateway are made once, with a total timeout of
/// `initial_timeout * (max_retries + 1)`, since TCP performs its own retransmission.
pub const TIMEOUT_CONFIG_DEFAULT: TimeoutConfig = TimeoutConfig {
    initial_timeout: Duration::from_secs(SEARCH_WINDOW_SECONDS),
    max_retries: SANE_MAX_REQUEST_RETRIES,
    max_retry_timeout: Some(Duration::from_secs(SEARCH_WINDOW_SECONDS)),
};

/// Error codes from a UPnP device error response.
/// Codes in the 700 range are specific to the WAN connection services, see the `WANIPConnection`
/// specifications <https://openconnectivity.org/upnp-specs/UPnP-gw-WANIPConnection-v1-Service.pdf>
/// and <https://openconnectivity.org/upnp-specs/UPnP-gw-WANIPConnection-v2-Service.pdf>.
#[derive(
    Clone, Copy, Debug, displaydoc::Display, PartialEq, thiserror::Error, num_enum::TryFromPrimitive,
)]
#[repr(u16)]
pub enum ErrorCode {
    /// The requested action is not supported by the service.
    InvalidAction = 401,

    /// The arguments given for the action are invalid.
    InvalidArgs = 402,

    /// The action failed for a service specific reason.
    ActionFailed = 501,

    /// The requested action is optional and not implemented by the device.
    OptionalActionNotImplemented = 602,

    /// The sender is not authorized to perform the action.
    ActionNotAuthorized = 606,

    /// The specified array index is out of bounds.
    SpecifiedArrayIndexInvalid = 713,

    /// No port mapping exists matching the given parameters.
    NoSuchEntryInArray = 714,

    /// The source IP address cannot be wild-carded.
    WildCardNotPermittedInSrcIp = 715,

    /// The external port cannot be wild-carded.
    WildCardNotPermittedInExtPort = 716,

    /// The requested mapping conflicts with a mapping assigned to another client.
    ConflictInMappingEntry = 718,

    /// The internal and external ports must have the same value.
    SamePortValuesRequired = 724,

    /// The gateway only supports permanent lifetimes on port mappings.
    OnlyPermanentLeasesSupported = 725,

    /// The remote host must be a wildcard and cannot be a specific IP address.
    RemoteHostOnlySupportsWildcard = 726,

    /// The external port must be a wildcard and cannot be a specific port.
    ExternalPortOnlySupportsWildcard = 727,

    /// The gateway does not have any free external ports available.
    NoPortMapsAvailable = 728,

    /// Mappings are not allowed due to a conflict with other mechanisms, e.g. administrative restrictions.
    ConflictWithOtherMechanisms = 729,

    /// The internal port cannot be wild-carded.
    WildCardNotPermittedInIntPort = 732,
}

/// Specific reasons why a UPnP response was considered invalid.
#[derive(Debug, thiserror::Error)]
pub enum InvalidResponseKind {
    /// The SSDP search response could not be parsed or was not a success.
    #[error("Invalid search response")]
    SearchResponse,

    /// The SSDP search response did not contain a location header.
    #[error("Search response is missing a location header")]
    MissingLocation,

    /// A URL did not have the expected `http://host[:port][/path]` structure.
    #[error("Invalid HTTP URL: {0}")]
    InvalidUrl(String),

    /// The HTTP response could not be parsed.
    #[error("Invalid HTTP response")]
    HttpResponse,

    /// The HTTP response exceeded the maximum number of bytes we allow.
    #[error("HTTP response is larger than the maximum of {MAX_HTTP_RESPONSE_SIZE} bytes")]
    ResponseTooLarge,

    /// The device description does not contain a supported WAN connection service.
    #[error("No supported WAN connection service in the device description")]
    NoWanConnectionService,

    /// A required XML tag was missing from the response body.
    #[error("Missing XML tag: {0}")]
    MissingTag(&'static str),

    /// The error response did not contain a valid UPnP error code.
    #[error("Invalid UPnP error response")]
    ErrorResponse,

    /// The gateway accepted an event subscription without assigning it an identifier.
    #[error("Subscription response is missing an SID header")]
    MissingSubscriptionId,

    /// A tag in the response contained a value that could not be parsed.
    #[error("Invalid value for {tag}: {value}")]
    InvalidValue { tag: &'static str, value: String },
}

/// Errors that may occur when trying to map a port on the gateway, categorized by the root of the issue.
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    /// Failed to use a UDP or TCP socket to communicate with the gateway.
    #[error("Socket error: {0}")]
    Socket(std::io::Error),

    /// The gateway was unreachable within the timeout.
    #[error("Gateway did not respond within the timeout")]
    Timeout,

    /// The gateway did not give a valid response according to the UPnP standards.
    #[error("Invalid response: {0}")]
    InvalidResponse(#[from] InvalidResponseKind),

    /// The gateway responded to an HTTP request with an unexpected status code.
    #[error("Unexpected HTTP status code: {0}")]
    HttpStatus(u16),

    /// The requested action is not supported by the service.
    #[error("Server responded with code: Invalid action")]
    InvalidAction,

    /// The arguments given for the action are invalid.
    #[error("Server responded with code: Invalid arguments")]
    InvalidArgs,

    /// The action failed for a service specific reason.
    #[error("Server responded with code: Action failed")]
    ActionFailed,

    /// The requested action is optional and not implemented by the device.
    #[error("Server responded with code: Optional action not implemented")]
    OptionalActionNotImplemented,

    /// The server did not authorize the operation.
    #[error("Server responded with code: Action not authorized")]
    ActionNotAuthorized,

    /// The specified array index is out of bounds.
    #[error("Server responded with code: Specified array index invalid")]
    SpecifiedArrayIndexInvalid,

    /// No port mapping exists matching the given parameters.
    #[error("Server responded with code: No such entry in array")]
    NoSuchEntryInArray,

    /// The source IP address cannot be wild-carded.
    #[error("Server responded with code: Wildcard not permitted in source IP")]
    WildCardNotPermittedInSrcIp,

    /// The external port cannot be wild-carded.
    #[error("Server responded with code: Wildcard not permitted in external port")]
    WildCardNotPermittedInExtPort,

    /// The requested mapping conflicts with a mapping assigned to another client.
    #[error("Server responded with code: Conflict in mapping entry")]
    ConflictInMappingEntry,

    /// The internal and external ports must have the same value.
    #[error("Server responded with code: Same port values required")]
    SamePortValuesRequired,

    /// The gateway only supports permanent lifetimes on port mappings.
    #[error("Server responded with code: Only permanent leases supported")]
    OnlyPermanentLeasesSupported,

    /// The remote host must be a wildcard and cannot be a specific IP address.
    #[error("Server responded with code: Remote host only supports wildcard")]
    RemoteHostOnlySupportsWildcard,

    /// The external port must be a wildcard and cannot be a specific port.
    #[error("Server responded with code: External port only supports wildcard")]
    ExternalPortOnlySupportsWildcard,

    /// The gateway does not have any free external ports available.
    #[error("Server responded with code: No port maps available")]
    NoPortMapsAvailable,

    /// Mappings are not allowed due to a conflict with other mechanisms, e.g. administrative restrictions.
    #[error("Server responded with code: Conflict with other mechanisms")]
    ConflictWithOtherMechanisms,

    /// The internal port cannot be wild-carded.
    #[error("Server responded with code: Wildcard not permitted in internal port")]
    WildCardNotPermittedInIntPort,

    /// The gateway responded with an error code that is not part of the UPnP or IGD specifications.
    /// Codes in the 800 range are reserved for vendor specific errors, so they are kept as-is
    /// rather than being treated as an invalid response.
    #[error("Server responded with unknown error code: {0}")]
    UnknownErrorCode(u16),
}

/// Helper to map UPnP error codes from an error response to a `Failure`.
#[must_use]
pub fn code_to_failure(error_code: u16) -> Failure {
    // Map recognized error codes to their failure, otherwise keep the raw code.
    match ErrorCode::try_from(error_code) {
        Ok(ErrorCode::InvalidAction) => Failure::InvalidAction,
        Ok(ErrorCode::InvalidArgs) => Failure::InvalidArgs,
        Ok(ErrorCode::ActionFailed) => Failure::ActionFailed,
        Ok(ErrorCode::OptionalActionNotImplemented) => Failure::OptionalActionNotImplemented,
        Ok(ErrorCode::ActionNotAuthorized) => Failure::ActionNotAuthorized,
        Ok(ErrorCode::SpecifiedArrayIndexInvalid) => Failure::SpecifiedArrayIndexInvalid,
        Ok(ErrorCode::NoSuchEntryInArray) => Failure::NoSuchEntryInArray,
        Ok(ErrorCode::WildCardNotPermittedInSrcIp) => Failure::WildCardNotPermittedInSrcIp,
        Ok(ErrorCode::WildCardNotPermittedInExtPort) => Failure::WildCardNotPermittedInExtPort,
        Ok(ErrorCode::ConflictInMappingEntry) => Failure::ConflictInMappingEntry,
        Ok(ErrorCode::SamePortValuesRequired) => Failure::SamePortValuesRequired,
        Ok(ErrorCode::OnlyPermanentLeasesSupported) => Failure::OnlyPermanentLeasesSupported,
        Ok(ErrorCode::RemoteHostOnlySupportsWildcard) => Failure::RemoteHostOnlySupportsWildcard,
        Ok(ErrorCode::ExternalPortOnlySupportsWildcard) => {
            Failure::ExternalPortOnlySupportsWildcard
        }
        Ok(ErrorCode::NoPortMapsAvailable) => Failure::NoPortMapsAvailable,
        Ok(ErrorCode::ConflictWithOtherMechanisms) => Failure::ConflictWithOtherMechanisms,
        Ok(ErrorCode::WildCardNotPermittedInIntPort) => Failure::WildCardNotPermittedInIntPort,
        Err(e) => Failure::UnknownErrorCode(e.number),
    }
}

/// The WAN connection service types which can manage port mappings on a gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WanService {
    /// The `WANPPPConnection:1` service, used by gateways which connect upstream over PPP.
    WanPppConnection1,

    /// The `WANIPConnection:1` service, defined by version 1 of the internet gateway device specifications.
    WanIpConnection1,

    /// The `WANIPConnection:2` service, defined by version 2 of the internet gateway device specifications.
    /// Preferred because it can let the gateway choose a free external port with `AddAnyPortMapping`.
    WanIpConnection2,
}
impl WanService {
    /// The full service type URN, used to identify the service in device descriptions and SOAP requests.
    #[must_use]
    pub fn service_type(self) -> &'static str {
        match self {
            WanService::WanPppConnection1 => "urn:schemas-upnp-org:service:WANPPPConnection:1",
            WanService::WanIpConnection1 => "urn:schemas-upnp-org:service:WANIPConnection:1",
            WanService::WanIpConnection2 => "urn:schemas-upnp-org:service:WANIPConnection:2",
        }
    }

    /// How much this service is preferred when a gateway offers several; greater is preferred.
    fn preference(self) -> u8 {
        match self {
            WanService::WanPppConnection1 => 0,
            WanService::WanIpConnection1 => 1,
            WanService::WanIpConnection2 => 2,
        }
    }

    /// Match a service type string from a device description to a supported WAN connection service.
    /// Service versions higher than those defined by the specifications are treated as the latest
    /// supported version, since devices are required to be backwards compatible within a service name.
    /// A missing version, used by some devices predating the standardized descriptions, is treated as `1`.
    fn from_service_type(service_type: &str) -> Option<WanService> {
        if let Some(version) =
            service_type.strip_prefix("urn:schemas-upnp-org:service:WANIPConnection")
        {
            return match parse_service_version(version)? {
                1 => Some(WanService::WanIpConnection1),
                _ => Some(WanService::WanIpConnection2),
            };
        }
        if let Some(version) =
            service_type.strip_prefix("urn:schemas-upnp-org:service:WANPPPConnection")
        {
            parse_service_version(version)?;
            return Some(WanService::WanPppConnection1);
        }
        None
    }
}

/// Parse the `:version` suffix of a service type, treating a missing version as `1`.
fn parse_service_version(version: &str) -> Option<u32> {
    if version.is_empty() {
        return Some(1);
    }
    match version.strip_prefix(':')?.parse().ok()? {
        0 => None,
        version => Some(version),
    }
}

/// The URL of a service's event subscription endpoint.
#[derive(Clone, Debug)]
pub struct EventUrl {
    /// The socket address of the HTTP server hosting the URL.
    pub address: SocketAddr,

    /// The absolute path of the URL.
    pub path: String,

    /// The index of the network interface the gateway was discovered through, if one was
    /// given; connections to the URL are bound to it, see `GatewayAddress::interface_index`.
    pub interface: Option<u32>,
}

/// The endpoint used to manage port mappings on the gateway, discovered through an SSDP
/// search and the device description it points to.
#[derive(Clone, Debug)]
pub struct ControlEndpoint {
    /// The socket address of the HTTP server on the gateway hosting the control URL.
    pub address: SocketAddr,

    /// The absolute path of the control URL on the gateway's HTTP server.
    pub control_path: String,

    /// The WAN connection service used to manage port mappings.
    pub service: WanService,

    /// The URL used to subscribe to the service's state change events.
    /// `None` if the service does not offer eventing.
    pub event_url: Option<EventUrl>,

    /// The index of the network interface the gateway was discovered through, if one was
    /// given; connections to the endpoint are bound to it, see `GatewayAddress::interface_index`.
    pub interface: Option<u32>,
}

/// How long to keep collecting further search responses after the first from the gateway,
/// so that a more preferred device description (e.g. IGD version 2) can win over the first to arrive.
const RESPONSE_GRACE: Duration = Duration::from_millis(50);

/// The maximum number of device descriptions fetched during a single discovery,
/// as protection against misbehaving devices announcing many locations.
const MAX_LOCATION_ATTEMPTS: usize = 10;

/// A candidate device description location parsed from a search response.
struct SearchCandidate {
    /// Whether the response names a version 2 gateway device or service, which is preferred.
    version_2: bool,

    /// The location of the device description.
    location: String,
}

/// Attempts to discover the endpoint for managing port mappings on the gateway.
/// Sends SSDP search requests to the gateway and fetches the device descriptions they announce.
/// # Notes
/// Search requests are sent to both the gateway itself and the local multicast group: unicast
/// search support was only added in version 1.1 of the UPnP Device Architecture, so some older
/// devices respond exclusively to multicast searches. The unicast request is sent first to teach
/// stateful host firewalls to expect a response from the gateway. Only responses which arrive
/// from the gateway address are trusted directly; responses from other addresses are used as a
/// last resort, since gateways may answer from a different address than they are reached by.
/// # Errors
/// Returns a `upnp::Failure` enum which decomposes into different errors depending on the cause.
pub async fn discover_gateway(
    gateway: GatewayAddress,
    timeout_config: Option<TimeoutConfig>,
) -> Result<ControlEndpoint, Failure> {
    let timeout_config = timeout_config.unwrap_or(TIMEOUT_CONFIG_DEFAULT);

    // Create a new UDP socket without connecting it: some device implementations respond to
    // search requests from an ephemeral port or a different address, so responses are judged
    // by their source address instead of relying on the socket to filter them.
    let socket = helpers::bind_socket(gateway).map_err(Failure::Socket)?;
    let destination = helpers::socket_address(gateway, DISCOVERY_PORT);
    let gateway_ip = IpAddr::from(gateway);

    // The multicast group used by SSDP, matching the IP version of the gateway.
    // Reference implementations use this group in the HOST header of every search request,
    // including unicast ones, so deployed devices are only known to accept this form.
    let (multicast_destination, multicast_host) = match gateway {
        GatewayAddress::IpV4(_, _) => (
            SocketAddr::from((std::net::Ipv4Addr::new(239, 255, 255, 250), DISCOVERY_PORT)),
            format!("239.255.255.250:{DISCOVERY_PORT}"),
        ),
        GatewayAddress::IpV6(_, scope_id) => (
            SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xC),
                DISCOVERY_PORT,
                0,
                scope_id.unwrap_or(0),
            )),
            format!("[ff02::c]:{DISCOVERY_PORT}"),
        ),
    };

    // Remember the locations already tried and the reason the most recent one was rejected.
    let mut tried_locations: Vec<String> = Vec::new();
    let mut last_failure = None;

    // Internal helper to try each candidate location, preferring version 2 devices over arrival order.
    async fn try_candidates(
        gateway: GatewayAddress,
        timeout_config: TimeoutConfig,
        candidates: &mut Vec<SearchCandidate>,
        tried_locations: &mut Vec<String>,
        last_failure: &mut Option<Failure>,
    ) -> Option<ControlEndpoint> {
        candidates.sort_by_key(|candidate| !candidate.version_2);
        for candidate in candidates.drain(..) {
            if tried_locations.contains(&candidate.location)
                || tried_locations.len() >= MAX_LOCATION_ATTEMPTS
            {
                continue;
            }
            tried_locations.push(candidate.location.clone());

            // A response may name a device without a usable WAN connection service
            // (e.g., for the generic search targets), so keep trying further candidates on failure.
            match control_endpoint_from_location(gateway, &candidate.location, timeout_config).await
            {
                Ok(endpoint) => return Some(endpoint),
                Err(e) => *last_failure = Some(e),
            }
        }
        None
    }

    // Use the specified initial timeout and double it on each successive failure,
    // limited to the configured maximum, mirroring the behavior of the other protocols.
    let mut wait = timeout_config.initial_timeout;
    let mut retries = 0;
    loop {
        // Send a search request for each target, see section 1.3.2 of the UPnP Device Architecture.
        // Header names are conventionally sent in upper case for compatibility with strict devices.
        for search_target in SEARCH_TARGETS {
            let search = format!(
                "M-SEARCH * HTTP/1.1\r\n\
                 HOST: {multicast_host}\r\n\
                 MAN: \"ssdp:discover\"\r\n\
                 MX: {SEARCH_WINDOW_SECONDS}\r\n\
                 ST: {search_target}\r\n\r\n"
            );
            socket
                .send_to(search.as_bytes(), destination)
                .await
                .map_err(Failure::Socket)?;

            // The multicast request is best-effort; the route to the group may be unavailable.
            let _ = socket
                .send_to(search.as_bytes(), multicast_destination)
                .await;
        }

        // Collect responses until the window closes, or briefly after the first response from
        // the gateway, then follow each candidate location to a usable description.
        let deadline = std::time::Instant::now() + wait;
        let mut commit_at: Option<std::time::Instant> = None;
        let mut from_gateway: Vec<SearchCandidate> = Vec::new();
        let mut from_others: Vec<SearchCandidate> = Vec::new();
        loop {
            let limit = commit_at.map_or(deadline, |commit_at| commit_at.min(deadline));
            let remaining = limit.saturating_duration_since(std::time::Instant::now());

            // Use a byte-buffer to read responses into. Search responses are small header-only HTTP messages.
            let mut recv_buffer = [0; 2048];
            let received = if remaining.is_zero() {
                None
            } else {
                tokio::time::timeout(remaining, socket.recv_from(&mut recv_buffer))
                    .await
                    .ok()
            };

            let Some(received) = received else {
                // The collection window closed; try the candidates the gateway sent.
                if let Some(endpoint) = try_candidates(
                    gateway,
                    timeout_config,
                    &mut from_gateway,
                    &mut tried_locations,
                    &mut last_failure,
                )
                .await
                {
                    return Ok(endpoint);
                }

                // Keep collecting until the full window has closed, then fall back to
                // responses from other addresses.
                if std::time::Instant::now() < deadline {
                    commit_at = None;
                    continue;
                }
                if let Some(endpoint) = try_candidates(
                    gateway,
                    timeout_config,
                    &mut from_others,
                    &mut tried_locations,
                    &mut last_failure,
                )
                .await
                {
                    return Ok(endpoint);
                }
                break;
            };
            let (n, source) = received.map_err(Failure::Socket)?;

            // Ignore unparsable responses; multiple devices may answer the multicast searches.
            let Ok(response) = std::str::from_utf8(&recv_buffer[..n]) else {
                continue;
            };
            let Ok(location) = parse_search_response(response) else {
                continue;
            };
            let candidate = SearchCandidate {
                version_2: response.contains("InternetGatewayDevice:2")
                    || response.contains("WANIPConnection:2"),
                location: location.to_string(),
            };

            if source.ip() == gateway_ip {
                // Give a more preferred response a brief chance to arrive before committing.
                if commit_at.is_none() {
                    commit_at = Some(std::time::Instant::now() + RESPONSE_GRACE);
                }
                from_gateway.push(candidate);
            } else {
                from_others.push(candidate);
            }
        }

        // Retry on timeout up to `max_retries` times.
        if retries >= timeout_config.max_retries {
            return Err(last_failure.unwrap_or(Failure::Timeout));
        }
        retries += 1;

        wait += wait;
        if let Some(max) = timeout_config.max_retry_timeout {
            if wait > max {
                wait = max;
            }
        }

        // Optionally log retry attempts to tracing.
        #[cfg(feature = "tracing")]
        tracing::info!(
            "Starting search retry {retries}/{} with timeout {wait:?}",
            timeout_config.max_retries
        );
    }
}

/// The maximum number of redirects followed when fetching a device description.
const MAX_REDIRECTS: usize = 3;

/// Fetch the device description at the given location and find the endpoint of its
/// preferred WAN connection service.
async fn control_endpoint_from_location(
    gateway: GatewayAddress,
    location: &str,
    timeout_config: TimeoutConfig,
) -> Result<ControlEndpoint, Failure> {
    let timeout = tcp_timeout(timeout_config);

    // Fetch the device description announced by the gateway, following a
    // few redirects, which some gateways use for their description documents.
    let (mut authority, mut path) = {
        let (authority, path) = split_http_url(location)?;
        (authority.to_string(), path.to_string())
    };
    let mut redirects = 0;
    let (description, authority, path) = loop {
        let address = repoint_at_gateway(gateway, &authority)?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
            host = host_header(&address),
        );
        let response = http_request(
            address,
            gateway.interface_index(),
            request.as_bytes(),
            timeout,
        )
        .await?;
        match response.status {
            200 => break (response.body, authority, path),

            // Follow a redirect to an absolute URL or an absolute path.
            301 | 302 | 303 | 307 | 308 if redirects < MAX_REDIRECTS => {
                let target = response
                    .location
                    .ok_or(Failure::HttpStatus(response.status))?;
                if target.starts_with('/') {
                    path = target;
                } else {
                    let (target_authority, target_path) = split_http_url(&target)?;
                    authority = target_authority.to_string();
                    path = target_path.to_string();
                }
                redirects += 1;
            }

            status => return Err(Failure::HttpStatus(status)),
        }
    };

    // Find the WAN connection services offered by the gateway, most preferred first.
    let (services, url_base) = parse_device_description(&description)?;

    // Resolve the possibly relative control URLs against the location of the device description,
    // or the legacy `URLBase` element if one was given.
    let mut endpoints = Vec::new();
    for service in services {
        let (control_authority, control_path) =
            resolve_control_url(&service.control_url, url_base.as_deref(), &authority, &path)?;

        // A malformed event URL only disables eventing rather than failing the discovery.
        let event_url = service.event_url.and_then(|event_url| {
            let (event_authority, event_path) =
                resolve_control_url(&event_url, url_base.as_deref(), &authority, &path).ok()?;
            Some(EventUrl {
                address: repoint_at_gateway(gateway, &event_authority).ok()?,
                path: event_path,
                interface: gateway.interface_index(),
            })
        });

        endpoints.push(ControlEndpoint {
            address: repoint_at_gateway(gateway, &control_authority)?,
            control_path,
            service: service.service,
            event_url,
            interface: gateway.interface_index(),
        });
    }

    // When the gateway offers several services, e.g. both PPP and IP connections, prefer one
    // which reports an established connection. The check is best-effort: gateways which do not
    // implement `GetStatusInfo` still use the most preferred service.
    if endpoints.len() > 1 {
        for endpoint in &endpoints {
            if connection_status(endpoint, timeout).await.unwrap_or(true) {
                return Ok(endpoint.clone());
            }
        }
    }
    endpoints
        .into_iter()
        .next()
        .ok_or_else(|| InvalidResponseKind::NoWanConnectionService.into())
}

/// Best-effort check of whether the WAN connection service reports an established connection.
/// Returns `None` if the gateway does not give a valid response to the `GetStatusInfo` action.
async fn connection_status(endpoint: &ControlEndpoint, timeout: Duration) -> Option<bool> {
    let response = soap_request(endpoint, "GetStatusInfo", "", timeout)
        .await
        .ok()?;
    // Firmware derived from other specification lineages may report `Up` instead of `Connected`.
    let status = find_tag_value(&response, "NewConnectionStatus")?;
    Some(status.eq_ignore_ascii_case("Connected") || status.eq_ignore_ascii_case("Up"))
}

/// Attempts to complete the `GetExternalIPAddress` action against the gateway.
/// Returns the external IP address of the gateway.
/// # Notes
/// A gateway without an established WAN connection may report the unspecified address `0.0.0.0`.
/// # Errors
/// Returns a `upnp::Failure` enum which decomposes into different errors depending on the cause.
pub async fn external_address(
    gateway: GatewayAddress,
    timeout_config: Option<TimeoutConfig>,
) -> Result<IpAddr, Failure> {
    let timeout_config = timeout_config.unwrap_or(TIMEOUT_CONFIG_DEFAULT);
    let endpoint = discover_gateway(gateway, Some(timeout_config)).await?;

    external_address_internal(&endpoint, tcp_timeout(timeout_config)).await
}

/// Attempts to map a port on the gateway using UPnP.
/// Discovers the control endpoint on the gateway before requesting the port mapping.
/// Will try to use the given external port if it is `Some`. Otherwise, gateways supporting
/// `WANIPConnection:2` are asked to choose a port, and older gateways use the internal port.
/// # Notes
/// A lifetime of `0` requests a mapping without an expiration, which some older gateways require.
/// Unlike NAT-PMP and PCP, a lifetime of `0` is not a deletion request, see `upnp::try_drop_mapping`.
/// Some gateways refuse to map external ports below `1024`, so requesting such a port,
/// or an internal port below `1024` without an external port, may fail with an error.
/// # Errors
/// Returns a `upnp::Failure` enum which decomposes into different errors depending on the cause.
pub async fn port_mapping(
    gateway: GatewayAddress,
    client: IpAddr,
    protocol: InternetProtocol,
    internal_port: NonZeroU16,
    mapping_options: PortMappingOptions,
) -> Result<PortMapping, Failure> {
    let endpoint = discover_gateway(gateway, mapping_options.timeout_config).await?;

    port_mapping_with_endpoint(
        gateway,
        &endpoint,
        client,
        protocol,
        internal_port,
        mapping_options,
    )
    .await
}

/// Attempts to map a port on the gateway using an already discovered control endpoint.
/// Used to renew mappings without repeating discovery, see `upnp::port_mapping` for details.
/// # Errors
/// Returns a `upnp::Failure` enum which decomposes into different errors depending on the cause.
pub async fn port_mapping_with_endpoint(
    gateway: GatewayAddress,
    endpoint: &ControlEndpoint,
    client: IpAddr,
    protocol: InternetProtocol,
    internal_port: NonZeroU16,
    mapping_options: PortMappingOptions,
) -> Result<PortMapping, Failure> {
    let PortMappingInternal {
        external_port,
        lifetime_seconds,
        external_ip,
        timeout_config,
    } = port_mapping_internal(endpoint, client, protocol, internal_port, mapping_options).await?;

    // A lifetime of zero means the mapping is permanent, i.e., it effectively never expires.
    let lifetime = if lifetime_seconds == 0 {
        Duration::from_secs(u64::from(u32::MAX))
    } else {
        Duration::from_secs(u64::from(lifetime_seconds))
    };

    Ok(PortMapping {
        gateway,
        protocol,
        internal_port,
        external_port,
        external_ip,
        lifetime_seconds,
        expiration: std::time::Instant::now() + lifetime,
        // UPnP does not share a "seconds since boot" epoch the way NAT-PMP and PCP do.
        gateway_epoch_seconds: 0,
        mapping_type: PortMappingType::Upnp {
            client,
            endpoint: endpoint.clone(),
        },
        timeout_config,
    })
}

/// Attempts to remove a UPnP port mapping on the gateway.
/// The gateway identifies mappings by their external port and protocol alone.
/// # Errors
/// Returns a `upnp::Failure` enum which decomposes into different errors depending on the cause.
pub async fn try_drop_mapping(
    endpoint: &ControlEndpoint,
    protocol: InternetProtocol,
    external_port: NonZeroU16,
    timeout_config: Option<TimeoutConfig>,
) -> Result<(), Failure> {
    let timeout = tcp_timeout(timeout_config.unwrap_or(TIMEOUT_CONFIG_DEFAULT));

    // Request that the gateway delete the mapping for the external port and protocol.
    soap_request(
        endpoint,
        "DeletePortMapping",
        &format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>{protocol}</NewProtocol>"
        ),
        timeout,
    )
    .await?;

    Ok(())
}

/// A successful response to a port mapping request.
struct PortMappingInternal {
    pub external_port: NonZeroU16,
    pub lifetime_seconds: u32,
    pub external_ip: IpAddr,
    pub timeout_config: TimeoutConfig,
}

/// The parameters shared by the mapping actions sent to a control endpoint.
struct MapRequest<'a> {
    endpoint: &'a ControlEndpoint,
    client: IpAddr,
    protocol: InternetProtocol,
    internal_port: NonZeroU16,
    timeout: Duration,
}
impl MapRequest<'_> {
    /// Format the shared arguments of the `AddPortMapping` and `AddAnyPortMapping` actions.
    fn arguments(&self, external_port: NonZeroU16, lifetime_seconds: u32) -> String {
        format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>{protocol}</NewProtocol>\
             <NewInternalPort>{internal_port}</NewInternalPort>\
             <NewInternalClient>{client}</NewInternalClient>\
             <NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>{PORT_MAPPING_DESCRIPTION}</NewPortMappingDescription>\
             <NewLeaseDuration>{lifetime_seconds}</NewLeaseDuration>",
            protocol = self.protocol,
            internal_port = self.internal_port,
            client = self.client,
        )
    }

    /// Whether a mapping request rejection indicates the gateway needs a permanent lifetime.
    /// Gateways which only support permanent mappings answer with `OnlyPermanentLeasesSupported`,
    /// or with `InvalidArgs` or `ActionFailed` on firmware predating that error code.
    fn needs_permanent_lifetime(failure: &Failure) -> bool {
        matches!(
            failure,
            Failure::OnlyPermanentLeasesSupported | Failure::InvalidArgs | Failure::ActionFailed
        )
    }

    /// Attempt the `AddPortMapping` action, retrying with a permanent lifetime if rejected.
    /// Returns the lifetime granted by the gateway.
    async fn add(&self, external_port: NonZeroU16, lifetime_seconds: u32) -> Result<u32, Failure> {
        match soap_request(
            self.endpoint,
            "AddPortMapping",
            &self.arguments(external_port, lifetime_seconds),
            self.timeout,
        )
        .await
        {
            Ok(_) => Ok(lifetime_seconds),

            // Retry with a permanent lifetime if the gateway requires one.
            Err(e) if Self::needs_permanent_lifetime(&e) && lifetime_seconds != 0 => {
                soap_request(
                    self.endpoint,
                    "AddPortMapping",
                    &self.arguments(external_port, 0),
                    self.timeout,
                )
                .await?;
                Ok(0)
            }

            // Any other error is returned immediately.
            Err(e) => Err(e),
        }
    }

    /// Attempt the `AddAnyPortMapping` action, retrying with a permanent lifetime if rejected.
    /// The external port is only a suggestion; returns the reserved port and granted lifetime.
    async fn add_any(
        &self,
        suggested_external_port: NonZeroU16,
        lifetime_seconds: u32,
    ) -> Result<(NonZeroU16, u32), Failure> {
        match soap_request(
            self.endpoint,
            "AddAnyPortMapping",
            &self.arguments(suggested_external_port, lifetime_seconds),
            self.timeout,
        )
        .await
        {
            Ok(response) => Ok((Self::reserved_port(&response)?, lifetime_seconds)),

            // Retry with a permanent lifetime if the gateway requires one.
            Err(e) if Self::needs_permanent_lifetime(&e) && lifetime_seconds != 0 => {
                let response = soap_request(
                    self.endpoint,
                    "AddAnyPortMapping",
                    &self.arguments(suggested_external_port, 0),
                    self.timeout,
                )
                .await?;
                Ok((Self::reserved_port(&response)?, 0))
            }

            // Any other error is returned immediately.
            Err(e) => Err(e),
        }
    }

    /// Read the external port reserved by an `AddAnyPortMapping` response.
    fn reserved_port(response: &str) -> Result<NonZeroU16, Failure> {
        let reserved = find_tag_value(response, "NewReservedPort")
            .ok_or(InvalidResponseKind::MissingTag("NewReservedPort"))?;
        reserved
            .parse()
            .ok()
            .and_then(NonZeroU16::new)
            .ok_or_else(|| {
                InvalidResponseKind::InvalidValue {
                    tag: "NewReservedPort",
                    value: reserved.to_string(),
                }
                .into()
            })
    }
}

/// Helper for attempting a port mapping against a discovered control endpoint.
/// # Errors
/// Returns a `upnp::Failure` enum which decomposes into different errors depending on the cause.
async fn port_mapping_internal(
    endpoint: &ControlEndpoint,
    client: IpAddr,
    protocol: InternetProtocol,
    internal_port: NonZeroU16,
    mapping_options: PortMappingOptions,
) -> Result<PortMappingInternal, Failure> {
    let timeout_config = mapping_options
        .timeout_config
        .unwrap_or(TIMEOUT_CONFIG_DEFAULT);
    let timeout = tcp_timeout(timeout_config);
    let lifetime_seconds = mapping_options
        .lifetime_seconds
        .unwrap_or(RECOMMENDED_MAPPING_LIFETIME_SECONDS);

    // Read the external IP address before creating the mapping: some gateways only support
    // permanent mappings, which would be leaked if a later step of this request failed.
    let external_ip = external_address_internal(endpoint, timeout).await?;

    let request = MapRequest {
        endpoint,
        client,
        protocol,
        internal_port,
        timeout,
    };

    let (external_port, lifetime_seconds) = if endpoint.service == WanService::WanIpConnection2
        && mapping_options.external_port.is_none()
    {
        // Without a requested external port, ask the gateway to choose a free one.
        match request.add_any(internal_port, lifetime_seconds).await {
            Ok(reservation) => reservation,

            // Some gateways advertise `WANIPConnection:2` without implementing `AddAnyPortMapping`;
            // retry with the version 1 action, which requests the internal port as the external port.
            Err(Failure::InvalidAction | Failure::OptionalActionNotImplemented) => {
                let lifetime_seconds = request.add(internal_port, lifetime_seconds).await?;
                (internal_port, lifetime_seconds)
            }

            // Any other error is returned immediately.
            Err(e) => return Err(e),
        }
    } else {
        // A requested external port always uses `AddPortMapping`: `AddAnyPortMapping` treats the
        // port as a suggestion, which would allow renewals to drift to a new external port.
        // Version 1 gateways cannot choose an external port for us, so default to the internal port.
        let external_port = mapping_options.external_port.unwrap_or(internal_port);
        let lifetime_seconds = request.add(external_port, lifetime_seconds).await?;
        (external_port, lifetime_seconds)
    };

    Ok(PortMappingInternal {
        external_port,
        lifetime_seconds,
        external_ip,
        timeout_config,
    })
}

/// Helper to complete the `GetExternalIPAddress` action against a discovered control endpoint.
async fn external_address_internal(
    endpoint: &ControlEndpoint,
    timeout: Duration,
) -> Result<IpAddr, Failure> {
    let response = soap_request(endpoint, "GetExternalIPAddress", "", timeout).await?;

    // Read the external IP address of the gateway from the response.
    // Gateways without an established WAN connection may report an empty address.
    let external_ip = find_tag_value(&response, "NewExternalIPAddress")
        .ok_or(InvalidResponseKind::MissingTag("NewExternalIPAddress"))?;
    if external_ip.is_empty() {
        return Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    external_ip.parse().map_err(|_| {
        InvalidResponseKind::InvalidValue {
            tag: "NewExternalIPAddress",
            value: external_ip.to_string(),
        }
        .into()
    })
}

/// The total timeout to use for a TCP exchange with the gateway.
/// TCP performs its own retransmission, so requests are made once using the time
/// the `TimeoutConfig` would allow a first request and its retries.
pub(crate) fn tcp_timeout(timeout_config: TimeoutConfig) -> Duration {
    timeout_config.initial_timeout.saturating_mul(
        u32::try_from(timeout_config.max_retries)
            .unwrap_or(u32::MAX)
            .saturating_add(1),
    )
}

/// Parse an SSDP search response and return the value of its location header.
/// See section 1.3.3 of the UPnP Device Architecture.
fn parse_search_response(response: &str) -> Result<&str, InvalidResponseKind> {
    let mut lines = response.lines();

    // Search responses use the HTTP success status line.
    let status = lines.next().ok_or(InvalidResponseKind::SearchResponse)?;
    if !status.starts_with("HTTP/") || status.split_ascii_whitespace().nth(1) != Some("200") {
        return Err(InvalidResponseKind::SearchResponse);
    }

    // Find the location header naming the URL of the device description. Header names are case-insensitive.
    lines
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.trim()
                .eq_ignore_ascii_case("location")
                .then(|| value.trim())
        })
        .ok_or(InvalidResponseKind::MissingLocation)
}

/// Strip the scheme from a plain HTTP URL; device descriptions are served over HTTP on the local network.
fn strip_http_scheme(url: &str) -> Option<&str> {
    url.get(.."http://".len())
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .map(|_| &url["http://".len()..])
}

/// Split an HTTP URL into its authority (`host[:port]`) and path.
fn split_http_url(url: &str) -> Result<(&str, &str), InvalidResponseKind> {
    let rest =
        strip_http_scheme(url).ok_or_else(|| InvalidResponseKind::InvalidUrl(url.to_string()))?;

    // Split the remainder into the authority and an absolute path, defaulting to the root.
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(InvalidResponseKind::InvalidUrl(url.to_string()));
    }

    Ok((authority, path))
}

/// The socket address to reach the authority of a URL announced by the gateway.
/// Always addresses the gateway itself: some gateways announce URLs naming one of their other,
/// possibly unreachable, addresses, so only the port of the authority is used.
fn repoint_at_gateway(
    gateway: GatewayAddress,
    authority: &str,
) -> Result<SocketAddr, InvalidResponseKind> {
    Ok(helpers::socket_address(gateway, authority_port(authority)?))
}

/// Extract the port of an HTTP URL authority, defaulting to the standard HTTP port.
fn authority_port(authority: &str) -> Result<u16, InvalidResponseKind> {
    // Bracketed IPv6 hosts carry their port after the closing bracket.
    let port = if let Some(end) = authority.find(']') {
        authority[end + 1..].strip_prefix(':')
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        // A colon in the remaining host means it is a bare IPv6 literal without a port.
        (!host.contains(':')).then_some(port)
    } else {
        None
    };

    port.map_or(Ok(80), |port| {
        port.parse()
            .map_err(|_| InvalidResponseKind::InvalidUrl(authority.to_string()))
    })
}

/// A WAN connection service entry parsed from a device description, with URLs as written.
#[derive(Debug, PartialEq)]
struct DescriptionService {
    service: WanService,
    control_url: String,
    event_url: Option<String>,
}

/// The WAN connection services in a device description and the legacy `URLBase` element if one was given.
type DescriptionServices = (Vec<DescriptionService>, Option<String>);

/// Find the WAN connection services in a device description, most preferred first.
fn parse_device_description(description: &str) -> Result<DescriptionServices, InvalidResponseKind> {
    // `URLBase` was removed in version 1.1 of the UPnP Device Architecture, but older devices may specify it.
    let url_base = find_tag_value(description, "URLBase").map(decode_xml_entities);

    // Scan the `<service>` entries of the nested device lists for WAN connection services.
    let mut services: Vec<DescriptionService> = Vec::new();
    let mut rest = description;
    while let Some(start) = rest.find("<service>") {
        rest = &rest[start + "<service>".len()..];
        let Some(end) = rest.find("</service>") else {
            break;
        };
        let service_block = &rest[..end];
        rest = &rest[end..];

        // Only consider service entries which name a control URL and a WAN connection service type.
        let Some(service) =
            find_tag_value(service_block, "serviceType").and_then(WanService::from_service_type)
        else {
            continue;
        };
        let Some(control_url) = find_tag_value(service_block, "controlURL") else {
            continue;
        };
        services.push(DescriptionService {
            service,
            control_url: decode_xml_entities(control_url),
            event_url: find_tag_value(service_block, "eventSubURL")
                .filter(|url| !url.is_empty())
                .map(decode_xml_entities),
        });
    }

    if services.is_empty() {
        return Err(InvalidResponseKind::NoWanConnectionService);
    }
    services.sort_by_key(|service| std::cmp::Reverse(service.service.preference()));
    Ok((services, url_base))
}

/// Resolve a possibly relative control URL against the URL of the device description,
/// or the legacy `URLBase` element if one was given.
/// Returns the authority and path of the control URL.
fn resolve_control_url(
    control_url: &str,
    url_base: Option<&str>,
    location_authority: &str,
    location_path: &str,
) -> Result<(String, String), InvalidResponseKind> {
    // An absolute URL requires no resolution.
    if strip_http_scheme(control_url).is_some() {
        let (authority, path) = split_http_url(control_url)?;
        return Ok((authority.to_string(), path.to_string()));
    }

    // Resolve against the `URLBase` if given, otherwise the location of the device description.
    let (base_authority, base_path) = match url_base {
        Some(url_base) => split_http_url(url_base)?,
        None => (location_authority, location_path),
    };

    // An absolute path replaces the base path entirely, a relative path replaces its last segment.
    // Base paths always begin with a `/` by construction in `split_http_url`.
    let path = if control_url.starts_with('/') {
        control_url.to_string()
    } else {
        let directory = &base_path[..=base_path.rfind('/').unwrap_or(0)];
        format!("{directory}{control_url}")
    };

    Ok((base_authority.to_string(), path))
}

/// The parts of an HTTP response used by this module.
#[derive(Debug)]
struct HttpResponse {
    /// The status code of the response.
    status: u16,

    /// The value of the location header, used to follow description redirects.
    location: Option<String>,

    /// The value of the SID header, identifying an event subscription.
    sid: Option<String>,

    /// The value of the timeout header, e.g. `Second-1800`, used by event subscriptions.
    timeout: Option<String>,

    /// The response body.
    body: String,
}

/// Format the host header value for the given socket address.
fn host_header(address: &SocketAddr) -> String {
    match address {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

/// Perform a single HTTP request against the given address and return the parsed response.
/// The connection is bound to the given interface, when one is known toward the address.
/// # Errors
/// Will return a `Socket(..)` error if the TCP connection fails, a `Timeout` error if the exchange
/// does not complete within the timeout, or an `InvalidResponse(..)` error for unparsable responses.
async fn http_request(
    address: SocketAddr,
    interface: Option<u32>,
    request: &[u8],
    timeout: Duration,
) -> Result<HttpResponse, Failure> {
    let exchange = async {
        // Open a new TCP connection to the gateway and send the request.
        let mut stream = helpers::connect_tcp(address, interface)
            .await
            .map_err(Failure::Socket)?;
        stream.write_all(request).await.map_err(Failure::Socket)?;

        // Read until the response is complete. We always request `Connection: close`,
        // but not all gateways honor it, so parse incrementally instead of expecting an EOF.
        let mut response = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            let n = stream.read(&mut chunk).await.map_err(Failure::Socket)?;
            let eof = n == 0;
            response.extend_from_slice(&chunk[..n]);

            if response.len() > MAX_HTTP_RESPONSE_SIZE {
                return Err(InvalidResponseKind::ResponseTooLarge.into());
            }
            if let Some(complete) = parse_http_response(&response, eof)? {
                return Ok(complete);
            }
        }
    };

    // Limit the total time of the exchange, since TCP will otherwise retransmit indefinitely.
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| Failure::Timeout)?
}

/// Try to parse an HTTP response, returning `Ok(None)` if it is incomplete and more data should be read.
/// `eof` indicates that no more data will arrive, making an incomplete response an error.
/// Handles the `Content-Length` and chunked framing used by gateway HTTP servers.
fn parse_http_response(raw: &[u8], eof: bool) -> Result<Option<HttpResponse>, InvalidResponseKind> {
    /// Helper to signal an incomplete response, which is only an error once `eof` is reached.
    fn incomplete<T>(eof: bool) -> Result<Option<T>, InvalidResponseKind> {
        if eof {
            Err(InvalidResponseKind::HttpResponse)
        } else {
            Ok(None)
        }
    }

    // Wait for the header separator before parsing. Some simple device implementations
    // terminate lines with a bare line feed rather than the specified `\r\n`.
    let crlf_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4));
    let lf_end = raw.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2));
    let Some((head_end, separator_len)) = crlf_end
        .into_iter()
        .chain(lf_end)
        .min_by_key(|(position, _)| *position)
    else {
        return incomplete(eof);
    };
    let head =
        std::str::from_utf8(&raw[..head_end]).map_err(|_| InvalidResponseKind::HttpResponse)?;
    let body = &raw[head_end + separator_len..];

    // Parse the status code from the status line, e.g. `HTTP/1.1 200 OK`.
    let mut lines = head.lines();
    let status = lines
        .next()
        .filter(|line| line.starts_with("HTTP/"))
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(InvalidResponseKind::HttpResponse)?;

    // Skip interim responses, which some devices send unrequested, and parse the response that follows.
    if (100..200).contains(&status) {
        return parse_http_response(body, eof);
    }

    // Determine how the response body is framed. Header names are case-insensitive.
    let mut content_length = None;
    let mut chunked = false;
    let mut location = None;
    let mut sid = None;
    let mut timeout = None;
    for (name, value) in lines.filter_map(|line| line.split_once(':')) {
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| InvalidResponseKind::HttpResponse)?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.eq_ignore_ascii_case("chunked");
        } else if name.eq_ignore_ascii_case("location") {
            location = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("sid") {
            sid = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("timeout") {
            timeout = Some(value.to_string());
        }
    }

    // Extract the response body, or wait for the framing to indicate a complete response.
    let body = if chunked {
        match decode_chunked(body)? {
            Some(body) => body,
            None => return incomplete(eof),
        }
    } else if let Some(content_length) = content_length {
        match body.get(..content_length) {
            Some(body) => body.to_vec(),
            // Devices sometimes overstate the length of the entity they send;
            // accept what was received once the connection has closed.
            None if eof => body.to_vec(),
            None => return Ok(None),
        }
    } else if eof {
        // Without explicit framing the body is terminated by the connection closing.
        body.to_vec()
    } else {
        return Ok(None);
    };

    Ok(Some(HttpResponse {
        status,
        location,
        sid,
        timeout,
        body: String::from_utf8_lossy(&body).into_owned(),
    }))
}

/// Decode an HTTP chunked response body, returning `Ok(None)` if it is incomplete.
fn decode_chunked(mut raw: &[u8]) -> Result<Option<Vec<u8>>, InvalidResponseKind> {
    let mut body = Vec::new();
    loop {
        // Each chunk begins with its size in hexadecimal, optionally followed by extensions we ignore.
        let Some(line_end) = raw.windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let size = std::str::from_utf8(&raw[..line_end])
            .ok()
            .and_then(|line| {
                let size = line.split(';').next().unwrap_or_default().trim();
                usize::from_str_radix(size, 16).ok()
            })
            .ok_or(InvalidResponseKind::HttpResponse)?;

        // A chunk of size zero terminates the body. Any trailers which follow are ignored.
        if size == 0 {
            return Ok(Some(body));
        }

        // Read the chunk data and its trailing separator, waiting for more data if incomplete.
        let data_start = line_end + 2;
        let Some(data) = raw.get(data_start..data_start + size) else {
            return Ok(None);
        };
        body.extend_from_slice(data);
        match raw.get(data_start + size..data_start + size + 2) {
            Some(b"\r\n") => raw = &raw[data_start + size + 2..],
            Some(_) => return Err(InvalidResponseKind::HttpResponse),
            None => return Ok(None),
        }
    }
}

/// Perform a SOAP action against the control endpoint and return the response body.
/// # Errors
/// UPnP error responses are returned as the `Failure` matching their error code,
/// see <https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v1.1.pdf> section 3.
async fn soap_request(
    endpoint: &ControlEndpoint,
    action: &str,
    arguments: &str,
    timeout: Duration,
) -> Result<String, Failure> {
    let service_type = endpoint.service.service_type();

    // Format the SOAP envelope for the requested action.
    let body = format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{service_type}\">{arguments}</u:{action}></s:Body>\
         </s:Envelope>"
    );

    // Format the HTTP request wrapping the SOAP envelope.
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\n\
         Content-Length: {length}\r\n\
         SOAPAction: \"{service_type}#{action}\"\r\n\
         Connection: close\r\n\r\n\
         {body}",
        path = endpoint.control_path,
        host = host_header(&endpoint.address),
        length = body.len(),
    );

    let response = http_request(
        endpoint.address,
        endpoint.interface,
        request.as_bytes(),
        timeout,
    )
    .await?;

    // Some gateways return error responses with a success or unrelated status code,
    // so an error code in the body takes precedence over the status line.
    if let Some(failure) = response_error(&response.body) {
        return Err(failure);
    }
    match response.status {
        200 => Ok(response.body),

        // UPnP errors are specified to use an internal server error status; reaching
        // this without an error code in the body means the response is invalid.
        500 => Err(InvalidResponseKind::ErrorResponse.into()),

        // Any other status code is unexpected for a SOAP exchange.
        status => Err(Failure::HttpStatus(status)),
    }
}

/// Extract the UPnP error from a response body, if it contains one.
fn response_error(response: &str) -> Option<Failure> {
    let error_code = find_tag_value(response, "errorCode")?;
    Some(error_code.parse().map_or_else(
        |_| InvalidResponseKind::ErrorResponse.into(),
        code_to_failure,
    ))
}

/// Find the trimmed text content of the first occurrence of an XML tag.
/// The narrow XML used by UPnP device descriptions and SOAP responses places values
/// in unprefixed tags without attributes, which avoids needing a full XML parser.
fn find_tag_value<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");

    let start = xml.find(&open)? + open.len();
    let length = xml[start..].find(&close)?;
    Some(xml[start..start + length].trim())
}

/// Decode the predefined XML entities in a value extracted from a description.
/// `&amp;` is decoded last so that double-escaped values are not decoded twice.
fn decode_xml_entities(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The subscription duration requested for event subscriptions, matching the common gateway default.
const EVENT_TIMEOUT_SECONDS: u32 = 1800;

/// An active event subscription on a gateway service.
/// See section 4 of the UPnP Device Architecture for the eventing protocol.
#[derive(Debug)]
pub(crate) struct EventSubscription {
    /// The URL the subscription was made at.
    pub url: EventUrl,

    /// The subscription identifier assigned by the gateway.
    pub sid: String,

    /// The number of seconds until the subscription expires unless renewed.
    pub timeout_seconds: u32,
}

/// Subscribe to state change events of the service at the given event URL.
/// The gateway will deliver events by connecting to an HTTP server at the callback address.
pub(crate) async fn subscribe(
    event_url: &EventUrl,
    callback: SocketAddr,
    timeout: Duration,
) -> Result<EventSubscription, Failure> {
    let request = format!(
        "SUBSCRIBE {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         CALLBACK: <http://{callback}/>\r\n\
         NT: upnp:event\r\n\
         TIMEOUT: Second-{EVENT_TIMEOUT_SECONDS}\r\n\
         Connection: close\r\n\r\n",
        path = event_url.path,
        host = host_header(&event_url.address),
        callback = host_header(&callback),
    );
    let response = http_request(
        event_url.address,
        event_url.interface,
        request.as_bytes(),
        timeout,
    )
    .await?;
    if response.status != 200 {
        return Err(Failure::HttpStatus(response.status));
    }

    Ok(EventSubscription {
        url: event_url.clone(),
        sid: response
            .sid
            .ok_or(InvalidResponseKind::MissingSubscriptionId)?,
        timeout_seconds: parse_subscription_timeout(response.timeout.as_deref()),
    })
}

/// Renew an event subscription before it expires.
/// Returns the number of seconds until the renewed subscription expires.
pub(crate) async fn renew_subscription(
    subscription: &EventSubscription,
    timeout: Duration,
) -> Result<u32, Failure> {
    let request = format!(
        "SUBSCRIBE {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         SID: {sid}\r\n\
         TIMEOUT: Second-{EVENT_TIMEOUT_SECONDS}\r\n\
         Connection: close\r\n\r\n",
        path = subscription.url.path,
        host = host_header(&subscription.url.address),
        sid = subscription.sid,
    );
    let response = http_request(
        subscription.url.address,
        subscription.url.interface,
        request.as_bytes(),
        timeout,
    )
    .await?;
    if response.status != 200 {
        return Err(Failure::HttpStatus(response.status));
    }

    Ok(parse_subscription_timeout(response.timeout.as_deref()))
}

/// Cancel an event subscription, which would otherwise remain active until its timeout expires.
pub(crate) async fn unsubscribe(
    subscription: &EventSubscription,
    timeout: Duration,
) -> Result<(), Failure> {
    let request = format!(
        "UNSUBSCRIBE {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         SID: {sid}\r\n\
         Connection: close\r\n\r\n",
        path = subscription.url.path,
        host = host_header(&subscription.url.address),
        sid = subscription.sid,
    );
    let response = http_request(
        subscription.url.address,
        subscription.url.interface,
        request.as_bytes(),
        timeout,
    )
    .await?;
    if response.status != 200 {
        return Err(Failure::HttpStatus(response.status));
    }

    Ok(())
}

/// Parse the number of seconds in a subscription timeout header, e.g. `Second-1800`.
/// Falls back to the requested duration when the header is missing or unparsable.
fn parse_subscription_timeout(value: Option<&str>) -> u32 {
    value
        .and_then(|value| {
            value
                .get(.."Second-".len())
                .filter(|prefix| prefix.eq_ignore_ascii_case("Second-"))
                .and_then(|_| value["Second-".len()..].parse().ok())
        })
        .unwrap_or(EVENT_TIMEOUT_SECONDS)
}

/// An event notification request received on the callback listener.
struct EventNotification {
    /// The request method, expected to be `NOTIFY`.
    method: String,

    /// The subscription identifier the event belongs to.
    sid: Option<String>,

    /// The event sequence number: `0` for the initial event, counting upward for later
    /// events and wrapping back to `1`. A gap means events were lost.
    seq: Option<u32>,

    /// The property set carried by the event.
    body: String,
}

/// Try to parse an event notification request, returning `Ok(None)` if it is incomplete.
/// `eof` indicates that no more data will arrive, making an incomplete request an error.
fn parse_notify_request(
    raw: &[u8],
    eof: bool,
) -> Result<Option<EventNotification>, InvalidResponseKind> {
    // Wait for the header separator before parsing, accepting bare line feeds as in responses.
    let crlf_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4));
    let lf_end = raw.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2));
    let Some((head_end, separator_len)) = crlf_end
        .into_iter()
        .chain(lf_end)
        .min_by_key(|(position, _)| *position)
    else {
        return if eof {
            Err(InvalidResponseKind::HttpResponse)
        } else {
            Ok(None)
        };
    };
    let head =
        std::str::from_utf8(&raw[..head_end]).map_err(|_| InvalidResponseKind::HttpResponse)?;
    let body = &raw[head_end + separator_len..];

    // Parse the method from the request line, e.g. `NOTIFY / HTTP/1.1`.
    let mut lines = head.lines();
    let method = lines
        .next()
        .and_then(|line| line.split_ascii_whitespace().next())
        .ok_or(InvalidResponseKind::HttpResponse)?
        .to_string();

    // Read the headers relevant to event delivery. Header names are case-insensitive.
    let mut content_length = None;
    let mut chunked = false;
    let mut sid = None;
    let mut seq = None;
    for (name, value) in lines.filter_map(|line| line.split_once(':')) {
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| InvalidResponseKind::HttpResponse)?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.eq_ignore_ascii_case("chunked");
        } else if name.eq_ignore_ascii_case("sid") {
            sid = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("seq") {
            seq = value.parse().ok();
        }
    }

    // Wait for the full property set, accepting a shorter body once the connection has closed.
    // Unlike responses, a request without explicit framing has an empty body.
    let body = if chunked {
        match decode_chunked(body)? {
            Some(body) => body,
            None if eof => return Err(InvalidResponseKind::HttpResponse),
            None => return Ok(None),
        }
    } else {
        match body.get(..content_length.unwrap_or(0)) {
            Some(body) => body.to_vec(),
            None if eof => body.to_vec(),
            None => return Ok(None),
        }
    };

    Ok(Some(EventNotification {
        method,
        sid,
        seq,
        body: String::from_utf8_lossy(&body).into_owned(),
    }))
}

/// An event notification read from the callback listener.
pub(crate) enum Notification {
    /// The connection did not carry an event for our subscription.
    NotOurs,

    /// An event for our subscription, with the values it carried.
    Event {
        /// The external IP address of the gateway, if the event carried one.
        external_ip: Option<IpAddr>,

        /// The event sequence number, if the event carried one.
        seq: Option<u32>,
    },
}

/// Read an event notification from an accepted callback connection and acknowledge it.
pub(crate) async fn read_notification(
    mut stream: tokio::net::TcpStream,
    expected_sid: &str,
    timeout: Duration,
) -> Result<Notification, Failure> {
    let exchange = async {
        // Read until the notification request is complete, mirroring `http_request`.
        let mut request = Vec::new();
        let mut chunk = [0; 4096];
        let notification = loop {
            let n = stream.read(&mut chunk).await.map_err(Failure::Socket)?;
            let eof = n == 0;
            request.extend_from_slice(&chunk[..n]);

            if request.len() > MAX_HTTP_RESPONSE_SIZE {
                return Err(InvalidResponseKind::ResponseTooLarge.into());
            }
            if let Some(notification) = parse_notify_request(&request, eof)? {
                break notification;
            }
        };

        // Acknowledge events for our subscription; reject others as the architecture specifies.
        let ours = notification.method.eq_ignore_ascii_case("NOTIFY")
            && notification.sid.as_deref() == Some(expected_sid);
        let status = if ours {
            "200 OK"
        } else {
            "412 Precondition Failed"
        };
        let response =
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = stream.write_all(response.as_bytes()).await;
        if !ours {
            return Ok(Notification::NotOurs);
        }

        // The initial event carries all evented variables, later events only the changed ones.
        // Gateways without an established WAN connection may report an empty address.
        let external_ip =
            find_tag_value(&notification.body, "ExternalIPAddress").and_then(|value| {
                if value.is_empty() {
                    Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                } else {
                    value.parse().ok()
                }
            });
        Ok(Notification::Event {
            external_ip,
            seq: notification.seq,
        })
    };

    // Limit the total time of the exchange, since TCP will otherwise retransmit indefinitely.
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| Failure::Timeout)?
}

#[cfg(test)]
mod tests;
