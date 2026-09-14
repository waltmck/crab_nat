//! # 🦀 NAT

//! A library providing a pure Rust implementation of a client for the NAT Port Mapping Protocol (NAT-PMP, [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886)), the Port Control Protocol (PCP, [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887)), and the UPnP Internet Gateway Device protocol ([IGD](https://openconnectivity.org/developer/specifications/upnp-resources/upnp/internet-gateway-device-igd-v-2-0/)).

//! This library is intended to feel like high level, idiomatic Rust, while still maintaining a strong focus on performance. It is asynchronous and uses the [tokio](https://tokio.rs) runtime to avoid blocking operations and to succinctly handle timeouts on UDP sockets.

//! ## Usage
//! ```rust,no_run
//! async {
//!     use std::{net::{IpAddr, Ipv4Addr}, num::NonZeroU16};
//!     use crab_nat::{InternetProtocol, PortMapping, PortMappingOptions};
//!     // Attempt a port mapping request through PCP first, falling back to NAT-PMP and then UPnP.
//!     let mapping = match PortMapping::new(
//!         Ipv4Addr::new(192, 168, 1, 1).into(), /* Address of the PCP server, often a gateway or firewall */
//!         Ipv4Addr::new(192, 168, 1, 167).into(), /* Address of our client, as seen by the gateway. Only strictly necessary for PCP and UPnP */
//!         InternetProtocol::Tcp, /* Protocol to map */
//!         NonZeroU16::new(8080).unwrap(), /* Internal port, cannot be zero */
//!         PortMappingOptions::default(), /* Optional configuration values, including suggested external port and lifetimes */
//!     )
//!     .await
//!     {
//!         Ok(m) => m,
//!         Err(e) => return eprintln!("Failed to map port: {e:?}"),
//!     };
//!
//!     // ...
//!
//!     // Try to safely drop the mapping.
//!     if let Err((e, m)) = mapping.try_drop().await {
//!         eprintln!("Failed to drop mapping {:?}:{}->{}: {e:?}", m.gateway(), m.external_port(), m.internal_port());
//!     } else {
//!         println!("Successfully deleted the mapping...");
//!     }
//! };
//! ```

use std::{net::IpAddr, num::NonZeroU16, time::Duration};

use num_enum::TryFromPrimitive;

pub mod natpmp;
pub mod pcp;
pub mod upnp;

// The RFC for NAT-PMP states that connections SHOULD make up to 9 attempts, <https://www.rfc-editor.org/rfc/rfc6886#section-3.1> page 6.
// The RFC for PCP states that connections SHOULD make attempts without a limit, <https://www.rfc-editor.org/rfc/rfc6887#section-8.1.1> page 22.
// However, that would be largely impractical so we set a sane default of 3 retries after the first attempt fails.
const SANE_MAX_REQUEST_RETRIES: usize = 3;

/// The required port for NAT-PMP and its successor, PCP.
pub const GATEWAY_PORT: u16 = 5351;

/// The port NAT-PMP and PCP clients listen on for multicast announcements from the gateway.
/// See <https://www.rfc-editor.org/rfc/rfc6886#section-3.2.1> and <https://www.rfc-editor.org/rfc/rfc6887#section-8.1>.
pub const ANNOUNCEMENT_PORT: u16 = 5350;

/// The RFC recommended lifetime for a port mapping, <https://www.rfc-editor.org/rfc/rfc6886#section-3.3> page 12.
pub const RECOMMENDED_MAPPING_LIFETIME_SECONDS: u32 = 7200;

/// The firewall mark applied to sockets created by this library, where `0` means no mark is set.
static FWMARK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Sets the firewall mark (`SO_MARK`) applied to all sockets this library creates from now on.
/// Marks let routing and firewall rules classify this library's traffic, e.g. to route
/// requests toward the gateway around a VPN which would otherwise capture them.
/// A mark of `0`, the initial value, leaves sockets unmarked.
/// # Notes
/// Marks only exist on Linux and Android; the value is ignored elsewhere. Setting a mark
/// requires the `CAP_NET_ADMIN` capability, without which socket creation will fail rather
/// than send traffic without its mark.
pub fn set_fwmark(fwmark: u32) {
    FWMARK.store(fwmark, std::sync::atomic::Ordering::Relaxed);
}

/// The firewall mark currently applied to sockets this library creates, where `0` means none.
#[must_use]
pub fn fwmark() -> u32 {
    FWMARK.load(std::sync::atomic::Ordering::Relaxed)
}

/// The `TimeoutConfig` used for the PCP attempt of the protocol fallback chain when none is given.
/// Uses a shorter initial timeout than the RFC-flavored `pcp::TIMEOUT_CONFIG_DEFAULT`, since
/// gateways on the local network respond within milliseconds and the chain has fallback
/// protocols left to attempt. Calls to `pcp::port_mapping(..)` directly keep the RFC timing.
const CHAIN_PCP_TIMEOUT_CONFIG: TimeoutConfig = TimeoutConfig {
    initial_timeout: Duration::from_millis(500),
    max_retries: SANE_MAX_REQUEST_RETRIES,
    max_retry_timeout: None,
};

/// 8-bit version field in the NAT-PMP and PCP headers.
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum VersionCode {
    /// NAT-PMP identifies its version with a `0` byte.
    NatPmp,

    /// PCP identifies its version with a `2` byte.
    /// The RFC explicitly states that PCP must use version `2` because non-compliant
    /// devices were created that used `1` before the creation of PCP.
    Pcp = 2,
}
impl std::fmt::Display for VersionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionCode::NatPmp => write!(f, "NAT-PMP"),
            VersionCode::Pcp => write!(f, "PCP"),
        }
    }
}

/// Specifies the protocol to map a port for.
/// Values are defined to match the opcodes in the NAT-PMP RFC, here <https://www.rfc-editor.org/rfc/rfc6886#section-3.3>.
#[repr(u8)]
#[derive(Clone, Copy, Debug, displaydoc::Display)]
pub enum InternetProtocol {
    /// UDP
    Udp = 1,

    /// TCP
    Tcp,
}

/// Specifies a port mapping protocol, as well as any protocol specific parameters.
#[derive(Clone, Debug, displaydoc::Display)]
pub enum PortMappingType {
    /// NAT-PMP
    NatPmp,

    /// PCP
    Pcp {
        /// Our address as seen by the PCP server.
        client: IpAddr,

        /// The nonce used to identify this session with the PCP server.
        /// A unique nonce may be used for each mapping, see <https://www.rfc-editor.org/rfc/rfc6887#page-44>.
        nonce: pcp::Nonce,
    },

    /// UPnP
    Upnp {
        /// Our address as seen by the gateway. Used as the internal client address of the mapping.
        client: IpAddr,

        /// The endpoint discovered on the gateway which is used to manage the mapping.
        endpoint: upnp::ControlEndpoint,
    },
}

/// Specifies the address of the gateway, either IPv4 or IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GatewayAddress {
    /// IPv4 address of the gateway.
    IpV4(std::net::Ipv4Addr),

    /// IPv6 address of the gateway, with an optional scope (zone) id for link-local addresses.
    IpV6(std::net::Ipv6Addr, Option<u32>),
}
impl From<GatewayAddress> for IpAddr {
    fn from(gateway: GatewayAddress) -> Self {
        match gateway {
            GatewayAddress::IpV4(v4) => IpAddr::V4(v4),
            GatewayAddress::IpV6(v6, _) => IpAddr::V6(v6),
        }
    }
}
impl From<IpAddr> for GatewayAddress {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => GatewayAddress::IpV4(v4),
            IpAddr::V6(v6) => GatewayAddress::IpV6(v6, None),
        }
    }
}
impl From<std::net::Ipv4Addr> for GatewayAddress {
    fn from(ip: std::net::Ipv4Addr) -> Self {
        GatewayAddress::IpV4(ip)
    }
}
impl From<std::net::Ipv6Addr> for GatewayAddress {
    fn from(ip: std::net::Ipv6Addr) -> Self {
        GatewayAddress::IpV6(ip, None)
    }
}

/// Configuration of the timing of UDP requests to the gateway.
#[derive(Clone, Copy, Debug)]
pub struct TimeoutConfig {
    /// The initial timeout for the first request. In general, the timeout will be doubled on each successive retry.
    pub initial_timeout: std::time::Duration,

    /// The maximum number of retries to attempt before giving up.
    /// Note that the first request is not considered a retry.
    pub max_retries: usize,

    /// The maximum timeout to use for a retry.
    pub max_retry_timeout: Option<std::time::Duration>,
}

/// Optional configuration values for a port mapping request.
#[derive(Clone, Copy, Debug, Default)]
pub struct PortMappingOptions {
    /// The external port to try to map. The server is not guaranteed to use this port.
    pub external_port: Option<NonZeroU16>,

    /// The lifetime of the port mapping in seconds. The server is not guaranteed to use this lifetime.
    pub lifetime_seconds: Option<u32>,

    /// The configuration of the timing of UDP requests made to the gateway.
    pub timeout_config: Option<TimeoutConfig>,
}

/// A port mapping on the gateway. Should be renewed with `.renew()` and deleted from the gateway with `.try_drop()`.
#[derive(Clone, Debug)]
pub struct PortMapping {
    /// The address of the gateway the mapping is registered with.
    gateway: GatewayAddress,

    /// The protocol the mapping is for.
    protocol: InternetProtocol,

    /// The internal/local port of the port mapping.
    internal_port: NonZeroU16,

    /// The external port of the port mapping.
    external_port: NonZeroU16,

    /// The external IP address of the port mapping.
    external_ip: IpAddr,

    /// The lifetime of the port mapping in seconds.
    lifetime_seconds: u32,

    /// The datetime the port mapping is set to expire at, using this machine's clock.
    expiration: std::time::Instant,

    /// The gateway epoch time when the port mapping was created.
    /// The RFC recommends checking if this value ever decreases and assuming the gateway has rebooted if it does by a certain margin (<https://www.rfc-editor.org/info/rfc6886/#section-3.6>, <https://www.rfc-editor.org/info/rfc6887/#section-8.5>).
    /// If the gateway has rebooted, all mappings on the gateway are lost and should be renewed.
    gateway_epoch_seconds: u32,

    /// The type of mapping protocol used, as well as any protocol specific parameters.
    mapping_type: PortMappingType,

    /// The configuration of the timing of UDP requests made to the gateway.
    pub timeout_config: TimeoutConfig,
}
impl PortMapping {
    /// Attempts to map a port on the gateway using PCP first, falling back to NAT-PMP and then UPnP.
    /// Will request to use the given external port if specified, otherwise it will let the gateway choose.
    /// If no lifetime is specified, the NAT-PMP recommended lifetime of two hours will be used.
    /// # Notes
    /// NAT-PMP is attempted when the PCP server recommends it with an unsupported version response,
    /// as well as when the PCP exchange suggests the responder may only speak NAT-PMP correctly:
    /// an invalid response, or a rejection of the request as malformed, unauthorized, or mismatched.
    /// When PCP goes unanswered entirely, NAT-PMP is attempted only if a stateless probe made
    /// concurrently with the PCP request demonstrated a NAT-PMP responder on the gateway.
    /// UPnP is attempted when the earlier protocols are ruled out as above, or when an attempted
    /// NAT-PMP fallback fails with an error specific to that protocol.
    /// Failures describing a state shared by all mapping protocols, such as the gateway lacking resources
    /// or a network failure, are returned without attempting further protocols.
    ///
    /// UPnP discovery is started concurrently with the earlier protocols to reduce the latency of
    /// falling back to it. Discovery creates no state on the gateway and is abandoned when unused.
    /// Without an explicit `timeout_config`, the PCP attempt uses a shorter initial timeout than
    /// `pcp::TIMEOUT_CONFIG_DEFAULT`, since gateways respond within milliseconds and the chain
    /// has fallback protocols left to attempt.
    /// # Errors
    /// Returns a `FallbackFailure` containing the `MappingFailure` of the last protocol attempted, which
    /// decomposes into a `NatPmp(natpmp::Failure)`, `Pcp(pcp::Failure)`, or `Upnp(upnp::Failure)`,
    /// as well as the time the PCP server estimated its error will persist, if it gave one.
    /// If you want control over exactly which protocols are attempted, you can call
    /// `pcp::port_mapping(..)`, `natpmp::port_mapping(..)`, or `upnp::port_mapping(..)` directly.
    pub async fn new(
        gateway: GatewayAddress,
        client: IpAddr,
        protocol: InternetProtocol,
        internal_port: NonZeroU16,
        mapping_options: PortMappingOptions,
    ) -> Result<Self, FallbackFailure> {
        /// The result of attempting the PCP, and possibly NAT-PMP, steps of the fallback chain.
        enum ChainAttempt {
            Mapped(Box<PortMapping>),
            Failed(FallbackFailure),
            TryUpnp { retry_after_seconds: Option<u32> },
        }

        // Attempt the protocols sharing the gateway port in their fallback order.
        let chain = async {
            // Probe for a NAT-PMP responder concurrently with the PCP attempt, using a stateless
            // external address request. The probe decides whether NAT-PMP is worth attempting when
            // PCP goes unanswered: relying on the unsupported version reply required by
            // <https://www.rfc-editor.org/rfc/rfc6886#section-3.5> would let one lost datagram,
            // or firmware which silently drops unknown versions, rule out a working NAT-PMP server.
            let probe = natpmp::external_address(gateway, mapping_options.timeout_config);

            // Try to use PCP first, as recommended by the RFC in the last paragraph of section 1.1 <https://www.rfc-editor.org/rfc/rfc6886#page-5>.
            let attempt = pcp::port_mapping(
                pcp::BaseMapRequest::new(gateway, client, protocol, internal_port),
                None,
                None,
                PortMappingOptions {
                    timeout_config: Some(
                        mapping_options
                            .timeout_config
                            .unwrap_or(CHAIN_PCP_TIMEOUT_CONFIG),
                    ),
                    ..mapping_options
                },
            );

            // Drive the probe alongside the PCP attempt; its result is read only when needed.
            let mut probe = std::pin::pin!(probe);
            let mut attempt = std::pin::pin!(attempt);
            let mut probed = None;
            let e = loop {
                let result = if probed.is_none() {
                    tokio::select! {
                        result = &mut attempt => result,
                        probed_ip = &mut probe => {
                            probed = Some(probed_ip);
                            continue;
                        }
                    }
                } else {
                    attempt.as_mut().await
                };
                match result {
                    Ok(m) => return ChainAttempt::Mapped(Box::new(m)),
                    Err(e) => break e,
                }
            };

            // Internal helper to wait for the probe if it has not resolved yet.
            let probed = async move {
                match probed {
                    Some(probed_ip) => probed_ip,
                    None => probe.await,
                }
            };

            // Keep the "retry after" estimate reported by the PCP server, if any, for the returned failure.
            let retry_after_seconds = e.retry_after_seconds();
            let natpmp_attempt = match pcp_failure_fallback(&e) {
                // Return errors describing a state shared by all mapping protocols.
                PcpFallback::None => {
                    return ChainAttempt::Failed(FallbackFailure {
                        failure: e.into(),
                        retry_after_seconds,
                    })
                }

                // The gateway asks for, or may only speak, NAT-PMP; always attempt it.
                PcpFallback::NatPmp => Some(probed.await),

                // The gateway did not answer PCP usefully; only attempt NAT-PMP if the
                // concurrent probe demonstrated a responder.
                PcpFallback::Upnp => match probed.await {
                    Ok(external_ip) => Some(Ok(external_ip)),
                    Err(_) => None,
                },
            };

            // Fall back to the older, possibly more widely supported, NAT-PMP.
            // The probe's result stands in for the external address request that
            // `natpmp::port_mapping` would otherwise repeat, in success and in failure.
            if let Some(probed_ip) = natpmp_attempt {
                let result = match probed_ip {
                    Ok(external_ip) => {
                        natpmp::port_mapping_with_external_address(
                            gateway,
                            external_ip,
                            protocol,
                            internal_port,
                            mapping_options,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                };
                match result {
                    Ok(m) => return ChainAttempt::Mapped(Box::new(m)),

                    // Fall through to UPnP for failures specific to the NAT-PMP protocol.
                    Err(e) if natpmp_failure_is_protocol_specific(&e) => {}

                    // Otherwise, return the error.
                    Err(e) => {
                        return ChainAttempt::Failed(FallbackFailure {
                            failure: e.into(),
                            retry_after_seconds,
                        })
                    }
                }
            }

            ChainAttempt::TryUpnp {
                retry_after_seconds,
            }
        };

        // Begin UPnP discovery concurrently so that falling back to it does not have to wait for
        // the exchanges above. Discovery creates no state on the gateway if it goes unused.
        let discovery = upnp::discover_gateway(gateway, mapping_options.timeout_config);

        let mut chain = std::pin::pin!(chain);
        let mut discovery = std::pin::pin!(discovery);
        let mut discovered = None;
        let attempt = loop {
            if discovered.is_none() {
                tokio::select! {
                    attempt = &mut chain => break attempt,
                    result = &mut discovery => discovered = Some(result),
                }
            } else {
                break chain.as_mut().await;
            }
        };

        let retry_after_seconds = match attempt {
            ChainAttempt::Mapped(m) => return Ok(*m),
            ChainAttempt::Failed(f) => return Err(f),
            ChainAttempt::TryUpnp {
                retry_after_seconds,
            } => retry_after_seconds,
        };

        // Fall back to UPnP, which is often available on gateways that have PCP and NAT-PMP disabled.
        // UPnP servers do not give "retry after" estimates; keep any reported by the earlier protocols.
        let endpoint = match discovered {
            Some(result) => result,
            None => discovery.await,
        };
        match endpoint {
            Ok(endpoint) => {
                upnp::port_mapping_with_endpoint(
                    gateway,
                    &endpoint,
                    client,
                    protocol,
                    internal_port,
                    mapping_options,
                )
                .await
            }
            Err(e) => Err(e),
        }
        .map_err(|e| FallbackFailure {
            failure: e.into(),
            retry_after_seconds,
        })
    }

    /// Attempts to renew this port mapping on the gateway, otherwise returns an error.
    /// # Notes
    /// Renewal also refreshes the address reported by `external_ip()`, so a stale external
    /// address is corrected even without an `AddressChangeListener`.
    /// # Errors
    /// Returns a `MappingFailure` enum which decomposes into a `NatPmp(natpmp::Failure)`,
    /// `Pcp(pcp::Failure)`, or `Upnp(upnp::Failure)` depending on which protocol was used to create the mapping.
    pub async fn renew(&mut self) -> Result<(), MappingFailure> {
        // The optional configuration values for the port mapping request.
        let options = PortMappingOptions {
            external_port: Some(self.external_port),
            lifetime_seconds: Some(self.lifetime()),
            timeout_config: Some(self.timeout_config),
        };

        // Attempt to renew the existing port mapping on the gateway.
        let renewed = match self.mapping_type.clone() {
            PortMappingType::NatPmp => {
                natpmp::port_mapping(self.gateway, self.protocol, self.internal_port, options)
                    .await
                    .map_err(MappingFailure::from)?
            }
            PortMappingType::Pcp { client, nonce } => pcp::port_mapping(
                pcp::BaseMapRequest::new(self.gateway, client, self.protocol, self.internal_port),
                Some(nonce),
                Some(self.external_ip),
                options,
            )
            .await
            .map_err(MappingFailure::from)?,
            PortMappingType::Upnp { client, endpoint } => {
                match upnp::port_mapping_with_endpoint(
                    self.gateway,
                    &endpoint,
                    client,
                    self.protocol,
                    self.internal_port,
                    options,
                )
                .await
                {
                    Ok(m) => m,

                    // The stored endpoint may be stale: some gateways host their control URL
                    // on a new port after each reboot. Retry once with a fresh discovery.
                    Err(
                        upnp::Failure::Socket(_)
                        | upnp::Failure::Timeout
                        | upnp::Failure::HttpStatus(404),
                    ) => upnp::port_mapping(
                        self.gateway,
                        client,
                        self.protocol,
                        self.internal_port,
                        options,
                    )
                    .await
                    .map_err(MappingFailure::from)?,

                    Err(e) => return Err(e.into()),
                }
            }
        };

        // A decreased gateway epoch suggests the gateway rebooted and lost its mappings.
        // This renewal recreated its own mapping, but others made earlier should also be renewed.
        // See <https://www.rfc-editor.org/rfc/rfc6887#section-8.5>.
        #[cfg(feature = "tracing")]
        if renewed.gateway_epoch_seconds < self.gateway_epoch_seconds {
            tracing::warn!(
                "Gateway epoch decreased from {} to {}; the gateway may have rebooted and dropped its other mappings",
                self.gateway_epoch_seconds,
                renewed.gateway_epoch_seconds
            );
        }

        *self = renewed;
        Ok(())
    }

    /// Attempts to safely delete this port mapping on the gateway, otherwise returns an error and the `PortMapping` back.
    /// # Errors
    /// Returns a `MappingFailure` enum which decomposes into `NatPmp(natpmp::Failure)`, `Pcp(pcp::Failure)`,
    /// and `Upnp(upnp::Failure)` depending on which protocol was used to create the mapping.
    pub async fn try_drop(self) -> Result<(), (MappingFailure, Self)> {
        let gateway = self.gateway();
        let protocol = self.protocol();
        let internal_port = self.internal_port();
        let mapping_type = self.mapping_type();

        // Attempt to delete the port mapping on the gateway.
        match mapping_type {
            PortMappingType::NatPmp => natpmp::try_drop_mapping(
                self.gateway(),
                self.protocol(),
                Some(internal_port),
                Some(self.timeout_config),
            )
            .await
            .map_err(|e| (MappingFailure::from(e), self)),

            PortMappingType::Pcp { client, nonce } => pcp::try_drop_mapping(
                gateway,
                client,
                nonce,
                pcp::DropMappingRange::Single {
                    internal_port,
                    protocol,
                },
                Some(self.timeout_config),
            )
            .await
            .map_err(|e| (MappingFailure::from(e), self)),

            PortMappingType::Upnp { endpoint, .. } => upnp::try_drop_mapping(
                &endpoint,
                protocol,
                self.external_port(),
                Some(self.timeout_config),
            )
            .await
            .map_err(|e| (MappingFailure::from(e), self)),
        }
    }

    /// The address of the gateway the mapping is registered with, along with an optional IPv6 scope (zone) id.
    #[must_use]
    pub fn gateway(&self) -> GatewayAddress {
        self.gateway
    }
    /// The IPv6 scope (zone) id toward the gateway, if the gateway is link-local.
    /// Only returns `Some(scope_id)` if the gateway address is IPv6 and a scope ID was provided, otherwise `None`.
    #[must_use]
    pub fn gateway_scope_id(&self) -> Option<u32> {
        if let GatewayAddress::IpV6(_, scope_id) = self.gateway {
            scope_id
        } else {
            None
        }
    }
    /// The protocol the mapping is for.
    #[must_use]
    pub fn protocol(&self) -> InternetProtocol {
        self.protocol
    }
    /// The internal/local port of the port mapping.
    #[must_use]
    pub fn internal_port(&self) -> NonZeroU16 {
        self.internal_port
    }
    /// The external port of the port mapping.
    #[must_use]
    pub fn external_port(&self) -> NonZeroU16 {
        self.external_port
    }
    /// The external IP address of the port mapping.
    /// NAT-PMP responses do not include this address, so it is requested separately when
    /// the mapping is created or renewed. A gateway without an established WAN connection
    /// may report an unspecified address.
    #[must_use]
    pub fn external_ip(&self) -> IpAddr {
        self.external_ip
    }
    /// The lifetime of the port mapping in seconds.
    /// A lifetime of `0` indicates a permanent mapping, which only UPnP gateways may create.
    #[must_use]
    pub fn lifetime(&self) -> u32 {
        self.lifetime_seconds
    }
    /// The datetime the port mapping is set to expire at, using this machine's clock.
    #[must_use]
    pub fn expiration(&self) -> std::time::Instant {
        self.expiration
    }
    /// The gateway epoch time when the port mapping was created.
    /// UPnP does not share an epoch, so this is always `0` for UPnP mappings.
    #[must_use]
    pub fn gateway_epoch(&self) -> u32 {
        self.gateway_epoch_seconds
    }
    /// The type of mapping protocol used, as well as any protocol specific parameters.
    #[must_use]
    pub fn mapping_type(&self) -> PortMappingType {
        self.mapping_type.clone()
    }

    /// The datetime after which the port mapping should be renewed, using this machine's clock.
    /// Renewal halfway through the lifetime is recommended by the RFC, see <https://www.rfc-editor.org/rfc/rfc6886#page-13>.
    #[must_use]
    pub fn renew_after(&self) -> std::time::Instant {
        self.expiration - Duration::from_secs(u64::from(self.lifetime_seconds) / 2)
    }
}

/// A change to the gateway state observed by an `AddressChangeListener`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressChange {
    /// The gateway announced a new external IP address.
    /// An unspecified address means the gateway lost its external connectivity.
    NewAddress(IpAddr),

    /// The gateway epoch was inconsistent with the passage of time, meaning the gateway
    /// likely rebooted and lost its state. Existing mappings should be renewed, which also
    /// refreshes their external addresses.
    GatewayReset {
        /// The gateway epoch time of the announcement.
        epoch_seconds: u32,
    },
}

/// Errors that occur while listening for gateway address changes.
#[derive(Debug, thiserror::Error)]
pub enum ListenerFailure {
    /// Failed to bind, read, or write on a socket.
    #[error("Socket error: {0}")]
    Socket(std::io::Error),

    /// UPnP eventing could not be established or maintained.
    #[error("UPnP({0})")]
    Upnp(#[from] upnp::Failure),

    /// The gateway accepted the event subscription, but its initial event never arrived.
    /// Inbound TCP connections from the gateway to the callback port are likely blocked.
    #[error("The gateway accepted the event subscription, but its initial event never arrived")]
    CallbackUnreachable,

    /// The gateway's WAN connection service does not offer event subscriptions.
    #[error("The service does not offer event subscriptions")]
    EventingUnsupported,
}

/// State of a UPnP event subscription held by an `AddressChangeListener`.
#[derive(Debug)]
struct UpnpEvents {
    /// Accepts event notification connections from the gateway.
    callback: tokio::net::TcpListener,

    /// The active subscription on the gateway's WAN connection service.
    subscription: upnp::EventSubscription,

    /// When to renew the subscription, halfway through its timeout.
    renew_at: tokio::time::Instant,

    /// The total timeout for TCP exchanges with the gateway.
    timeout: Duration,

    /// The sequence number the next event is expected to carry, used to detect lost events.
    next_seq: Option<u32>,
}

/// Listens for external address changes announced by the gateway.
/// NAT-PMP and PCP servers announce changes over multicast, which `bind` listens for.
/// UPnP gateways deliver state change events to subscribers, which `bind_with_upnp` adds.
/// # Notes
/// The announcements arrive as unsolicited inbound traffic, so host firewalls must permit
/// them; see the README for the exact rules required.
///
/// Even without a listener, a stale external address is corrected whenever a mapping
/// is renewed, see `PortMapping::renew`.
#[derive(Debug)]
pub struct AddressChangeListener {
    /// The gateway being listened to. Messages from other sources are ignored.
    gateway: GatewayAddress,

    /// The socket receiving multicast announcements from NAT-PMP and PCP servers.
    announcements: tokio::net::UdpSocket,

    /// The UPnP event subscription, if one was made.
    upnp_events: Option<UpnpEvents>,

    /// The most recently observed external address, used to suppress repeated announcements.
    last_address: Option<IpAddr>,

    /// The most recent gateway epoch observation, used to detect state resets.
    last_epoch: Option<(std::time::Instant, u32)>,

    /// Changes waiting to be returned by `recv`; a single message can produce more than one.
    pending: std::collections::VecDeque<AddressChange>,
}
impl AddressChangeListener {
    /// Listens for the multicast address change announcements of NAT-PMP and PCP servers.
    /// # Errors
    /// Returns a `ListenerFailure::Socket` if the announcement port could not be bound.
    pub async fn bind(gateway: GatewayAddress) -> Result<Self, ListenerFailure> {
        let announcements =
            helpers::bind_announcement_socket(gateway).map_err(ListenerFailure::Socket)?;

        Ok(Self {
            gateway,
            announcements,
            upnp_events: None,
            last_address: None,
            last_epoch: None,
            pending: std::collections::VecDeque::new(),
        })
    }

    /// Listens for the address changes relevant to an existing port mapping.
    /// Mappings made over UPnP subscribe to the state change events of their control endpoint,
    /// since UPnP gateways do not send the multicast announcements of the other protocols;
    /// see `bind_with_upnp` for the callback this requires. `callback_port` is unused for
    /// NAT-PMP and PCP mappings.
    /// # Errors
    /// Returns a `ListenerFailure` which decomposes into different errors depending on the cause.
    pub async fn bind_for_mapping(
        mapping: &PortMapping,
        callback_port: Option<NonZeroU16>,
    ) -> Result<Self, ListenerFailure> {
        match mapping.mapping_type() {
            // UPnP mappings already know the control endpoint to subscribe to.
            PortMappingType::Upnp { client, endpoint } => {
                let mut listener = Self::bind_with_endpoint(
                    mapping.gateway(),
                    &endpoint,
                    client,
                    callback_port,
                    Some(mapping.timeout_config),
                )
                .await?;

                // The initial event carried the current address; differing from the one the
                // mapping knows means it changed before the listener was bound. Report it,
                // as the gateway will not send another event for it.
                match listener.last_address {
                    Some(current) if current != mapping.external_ip() => {
                        listener
                            .pending
                            .push_back(AddressChange::NewAddress(current));
                    }
                    Some(_) => {}
                    None => listener.last_address = Some(mapping.external_ip()),
                }
                Ok(listener)
            }

            PortMappingType::NatPmp | PortMappingType::Pcp { .. } => {
                let mut listener = Self::bind(mapping.gateway()).await?;

                // Seed the epoch check with the mapping's observation so that a reset
                // since the mapping was created is still detected.
                let created_at =
                    mapping.expiration() - Duration::from_secs(u64::from(mapping.lifetime()));
                listener.last_epoch = Some((created_at, mapping.gateway_epoch()));

                // Announcements of the address the mapping already knows are not changes.
                listener.last_address = Some(mapping.external_ip());

                // One stateless request reports changes from before the listener was bound,
                // which announcements only cover for a couple of minutes. The epoch detects
                // resets even when the gateway re-acquired the same address. The IPv4 address
                // is only meaningful for mappings with an IPv4 external address.
                if let Ok((external_ip, epoch_seconds)) = natpmp::external_address_with_epoch(
                    mapping.gateway(),
                    Some(mapping.timeout_config),
                )
                .await
                {
                    listener.observe_epoch(epoch_seconds);
                    if mapping.external_ip().is_ipv4() {
                        listener.observe_address(IpAddr::V4(external_ip));
                    }
                }
                Ok(listener)
            }
        }
    }

    /// Listens for multicast announcements and additionally subscribes to the state change
    /// events of a UPnP gateway. The gateway delivers events by connecting to a callback
    /// server hosted on `client`, our address as seen by the gateway. A fixed `callback_port`
    /// may be given so that a host firewall rule can allow the gateway's connections,
    /// otherwise one is chosen.
    /// # Notes
    /// Hosting the callback on an IPv6 link-local `client` address is not supported,
    /// as no scope can be given for it.
    /// # Errors
    /// Returns a `ListenerFailure` which decomposes into socket errors, UPnP failures, and
    /// `CallbackUnreachable` when the gateway could not deliver its initial event, which
    /// usually means a host firewall blocks inbound connections to the callback port.
    pub async fn bind_with_upnp(
        gateway: GatewayAddress,
        client: IpAddr,
        callback_port: Option<NonZeroU16>,
        timeout_config: Option<TimeoutConfig>,
    ) -> Result<Self, ListenerFailure> {
        // Discover the gateway's WAN connection service to subscribe to.
        let timeout_config = timeout_config.unwrap_or(upnp::TIMEOUT_CONFIG_DEFAULT);
        let endpoint = upnp::discover_gateway(gateway, Some(timeout_config)).await?;

        Self::bind_with_endpoint(
            gateway,
            &endpoint,
            client,
            callback_port,
            Some(timeout_config),
        )
        .await
    }

    /// Subscribes to the state change events of an already discovered UPnP control endpoint,
    /// see `bind_with_upnp` for details.
    /// # Errors
    /// Returns a `ListenerFailure` which decomposes into socket errors, UPnP failures, and
    /// `CallbackUnreachable` when the gateway could not deliver its initial event.
    pub async fn bind_with_endpoint(
        gateway: GatewayAddress,
        endpoint: &upnp::ControlEndpoint,
        client: IpAddr,
        callback_port: Option<NonZeroU16>,
        timeout_config: Option<TimeoutConfig>,
    ) -> Result<Self, ListenerFailure> {
        let Some(event_url) = &endpoint.event_url else {
            return Err(ListenerFailure::EventingUnsupported);
        };
        let mut listener = Self::bind(gateway).await?;
        let timeout_config = timeout_config.unwrap_or(upnp::TIMEOUT_CONFIG_DEFAULT);
        let timeout = upnp::tcp_timeout(timeout_config);

        // Subscribe to the state change events of the gateway's WAN connection service.
        let callback = helpers::bind_tcp_listener(std::net::SocketAddr::new(
            client,
            callback_port.map_or(0, NonZeroU16::get),
        ))
        .map_err(ListenerFailure::Socket)?;
        let callback_address = callback.local_addr().map_err(ListenerFailure::Socket)?;
        let subscription = upnp::subscribe(event_url, callback_address, timeout).await?;

        // The architecture requires the gateway to immediately deliver an initial event with the
        // current variable states. Waiting for it both proves that the gateway can reach the
        // callback and provides the current external address to compare later events against.
        let deadline = tokio::time::Instant::now() + timeout;
        let (external_ip, seq) = loop {
            let accepted = match tokio::time::timeout_at(deadline, callback.accept()).await {
                // Without the initial event, later events would silently never arrive.
                Err(_) => {
                    let _ = upnp::unsubscribe(&subscription, timeout).await;
                    return Err(ListenerFailure::CallbackUnreachable);
                }
                Ok(result) => result,
            };
            let (stream, source) = match accepted {
                Ok(accepted) => accepted,
                // The callback listener itself failing is fatal; release the subscription.
                Err(e) => {
                    let _ = upnp::unsubscribe(&subscription, timeout).await;
                    return Err(ListenerFailure::Socket(e));
                }
            };
            // Events may also be delivered from the address hosting the event URL.
            if source.ip() != IpAddr::from(gateway) && source.ip() != event_url.address.ip() {
                continue;
            }

            // Other connections, e.g. the events of a previous subscription to the same
            // callback port, do not prove that this subscription's events can arrive.
            // The read shares the deadline so a stalled connection cannot extend the wait.
            match tokio::time::timeout_at(
                deadline,
                upnp::read_notification(stream, &subscription.sid, timeout),
            )
            .await
            {
                Ok(Ok(upnp::Notification::Event { external_ip, seq })) => break (external_ip, seq),
                Ok(Ok(upnp::Notification::NotOurs)) | Ok(Err(_)) => {}
                Err(_) => {
                    let _ = upnp::unsubscribe(&subscription, timeout).await;
                    return Err(ListenerFailure::CallbackUnreachable);
                }
            }
        };
        if let Some(address) = external_ip {
            listener.last_address = Some(address);
        }

        listener.upnp_events = Some(UpnpEvents {
            callback,
            renew_at: tokio::time::Instant::now()
                + Duration::from_secs(u64::from(subscription.timeout_seconds / 2).max(1)),
            subscription,
            timeout,
            next_seq: seq.map(following_seq),
        });
        Ok(listener)
    }

    /// Await the next address change announced by the gateway.
    /// # Notes
    /// UPnP event subscriptions are also renewed within calls to this method, so it should be
    /// kept pending, e.g. in a `tokio::select!` loop, rather than called sporadically.
    ///
    /// Cancelling this method never loses a queued change, but may lose an event notification
    /// that was being read when cancelled; the gap is noticed through the event sequence
    /// numbers, and the subscription is refreshed to resynchronize.
    /// # Errors
    /// Returns a `ListenerFailure` when a socket fails or a lapsed subscription cannot be
    /// re-established. The listener should be bound again after an error.
    pub async fn recv(&mut self) -> Result<AddressChange, ListenerFailure> {
        /// The messages `recv` can be woken by.
        enum Wake {
            Announcement(usize, std::net::SocketAddr),
            Event(tokio::net::TcpStream, std::net::SocketAddr),
            Renew,
        }

        loop {
            if let Some(change) = self.pending.pop_front() {
                return Ok(change);
            }

            // Wait for an announcement datagram, an event connection, or the renewal time.
            let mut buffer = [0; pcp::MAX_DATAGRAM_SIZE];
            let wake = if let Some(events) = &self.upnp_events {
                tokio::select! {
                    result = self.announcements.recv_from(&mut buffer) => {
                        let (n, source) = result.map_err(ListenerFailure::Socket)?;
                        Wake::Announcement(n, source)
                    }
                    result = events.callback.accept() => {
                        let (stream, source) = result.map_err(ListenerFailure::Socket)?;
                        Wake::Event(stream, source)
                    }
                    () = tokio::time::sleep_until(events.renew_at) => Wake::Renew,
                }
            } else {
                let (n, source) = self
                    .announcements
                    .recv_from(&mut buffer)
                    .await
                    .map_err(ListenerFailure::Socket)?;
                Wake::Announcement(n, source)
            };

            match wake {
                // Ignore messages that did not come from the gateway, regardless of their source port.
                Wake::Announcement(_, source) if source.ip() != IpAddr::from(self.gateway) => {}

                // Events may also be delivered from the address hosting the event URL.
                Wake::Event(_, source)
                    if source.ip() != IpAddr::from(self.gateway)
                        && self.upnp_events.as_ref().is_none_or(|events| {
                            source.ip() != events.subscription.url.address.ip()
                        }) => {}

                Wake::Announcement(n, _) => {
                    let datagram = &buffer[..n];
                    if let Some((address, epoch_seconds)) =
                        natpmp::parse_address_announcement(datagram)
                    {
                        self.observe_epoch(epoch_seconds);
                        self.observe_address(IpAddr::V4(address));
                    } else if let Some(epoch_seconds) = pcp::parse_announce(datagram) {
                        self.observe_epoch(epoch_seconds);
                    }
                }

                Wake::Event(stream, _) => {
                    // The borrow of the subscription must end before observing the address.
                    let (sid, timeout) = {
                        let events = self.upnp_events.as_ref().expect("woken by a subscription");
                        (events.subscription.sid.clone(), events.timeout)
                    };

                    // A connection which could not be read is not fatal: announcements and
                    // later events still arrive, and lost events are noticed by their sequence.
                    match upnp::read_notification(stream, &sid, timeout).await {
                        Ok(upnp::Notification::Event { external_ip, seq }) => {
                            // A sequence gap means events were lost; re-establish the
                            // subscription, whose initial event resynchronizes the state.
                            let events =
                                self.upnp_events.as_mut().expect("woken by a subscription");
                            if seq.is_some_and(|seq| {
                                events.next_seq.is_some_and(|expected| seq != expected)
                            }) {
                                Self::resubscribe(events).await?;
                                continue;
                            }

                            if let Some(seq) = seq {
                                events.next_seq = Some(following_seq(seq));
                            }
                            if let Some(address) = external_ip {
                                self.observe_address(address);
                            }
                        }
                        Ok(upnp::Notification::NotOurs) | Err(_) => {}
                    }
                }

                Wake::Renew => {
                    let events = self.upnp_events.as_mut().expect("woken by a subscription");
                    match upnp::renew_subscription(&events.subscription, events.timeout).await {
                        Ok(timeout_seconds) => {
                            events.subscription.timeout_seconds = timeout_seconds;
                            events.renew_at = tokio::time::Instant::now()
                                + Duration::from_secs(u64::from(timeout_seconds / 2).max(1));
                        }

                        // The subscription may have lapsed, e.g. across a gateway reboot;
                        // establish a fresh one as the architecture prescribes.
                        Err(_) => {
                            if let Err(e) = Self::resubscribe(events).await {
                                // Delay the next attempt so ignored errors cannot tight-loop.
                                events.renew_at =
                                    tokio::time::Instant::now() + Duration::from_secs(60);
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Replace a lapsed or desynchronized subscription with a fresh one.
    /// The new subscription's initial event arrives through the normal callback path.
    async fn resubscribe(events: &mut UpnpEvents) -> Result<(), ListenerFailure> {
        // Release the replaced subscription; it may still be active, e.g. after a sequence gap.
        let _ = upnp::unsubscribe(&events.subscription, events.timeout).await;

        let callback_address = events
            .callback
            .local_addr()
            .map_err(ListenerFailure::Socket)?;
        let subscription =
            upnp::subscribe(&events.subscription.url, callback_address, events.timeout).await?;

        events.renew_at = tokio::time::Instant::now()
            + Duration::from_secs(u64::from(subscription.timeout_seconds / 2).max(1));
        events.next_seq = None;
        events.subscription = subscription;
        Ok(())
    }

    /// Stops listening, cancelling the UPnP event subscription if one was made.
    /// The subscription would otherwise remain active on the gateway until its timeout expires.
    /// # Errors
    /// Returns a `ListenerFailure` if the gateway could not process the cancellation.
    pub async fn shutdown(self) -> Result<(), ListenerFailure> {
        if let Some(events) = self.upnp_events {
            upnp::unsubscribe(&events.subscription, events.timeout).await?;
        }
        Ok(())
    }

    /// Queue a new address observation, suppressing announcements of an unchanged address.
    fn observe_address(&mut self, address: IpAddr) {
        if self.last_address != Some(address) {
            self.last_address = Some(address);
            self.pending.push_back(AddressChange::NewAddress(address));
        }
    }

    /// Queue a gateway reset if an observed epoch is inconsistent with the previous observation.
    /// Consistent observations, e.g. the repeated announcements gateways send, are absorbed.
    fn observe_epoch(&mut self, epoch_seconds: u32) {
        let now = std::time::Instant::now();
        if let Some((observed_at, previous_epoch_seconds)) = self.last_epoch {
            let elapsed_seconds = now.duration_since(observed_at).as_secs();
            if !pcp::epoch_is_consistent(elapsed_seconds, previous_epoch_seconds, epoch_seconds) {
                self.pending
                    .push_back(AddressChange::GatewayReset { epoch_seconds });
            }
        }
        self.last_epoch = Some((now, epoch_seconds));
    }
}

/// The sequence number expected after the given one; event sequences wrap to `1`, not `0`.
fn following_seq(seq: u32) -> u32 {
    if seq == u32::MAX {
        1
    } else {
        seq + 1
    }
}

/// Private module for shared helper functions within the library.
mod helpers {
    use crate::{GatewayAddress, TimeoutConfig};
    use std::time::Duration;
    use tokio::net::UdpSocket;

    /// The socket address of the gateway at the given port, including any IPv6 scope ID.
    #[must_use]
    pub fn socket_address(gateway: GatewayAddress, port: u16) -> std::net::SocketAddr {
        use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

        match gateway {
            GatewayAddress::IpV4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
            GatewayAddress::IpV6(v6, scope_id) => {
                SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope_id.unwrap_or(0)))
            }
        }
    }

    /// Apply the configured firewall mark, if any, to a socket before it is used.
    /// See `crate::set_fwmark`; marks only exist on some platforms.
    fn apply_fwmark(socket: &socket2::Socket) -> Result<(), std::io::Error> {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            let fwmark = crate::fwmark();
            if fwmark != 0 {
                socket.set_mark(fwmark)?;
            }
        }
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        let _ = socket;

        Ok(())
    }

    /// Create a new UDP socket with an IP protocol matching that of the gateway address.
    /// # Errors
    /// Will return an error if we fail to bind to a local UDP socket or to apply a firewall mark.
    pub fn bind_socket(gateway: GatewayAddress) -> Result<tokio::net::UdpSocket, std::io::Error> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

        let (domain, bind_address) = match &gateway {
            GatewayAddress::IpV4(_) => (
                Domain::IPV4,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            ),
            GatewayAddress::IpV6(_, _) => (
                Domain::IPV6,
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
            ),
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        apply_fwmark(&socket)?;
        socket.set_nonblocking(true)?;
        socket.bind(&bind_address.into())?;

        tokio::net::UdpSocket::from_std(socket.into())
    }

    /// Create a new UDP socket and "connect" it to the given port on the gateway.
    /// # Errors
    /// Will return an error if we fail to bind to a local UDP socket or connect to the gateway address.
    pub async fn new_socket(
        gateway: GatewayAddress,
        port: u16,
    ) -> Result<tokio::net::UdpSocket, std::io::Error> {
        let socket = bind_socket(gateway)?;
        socket.connect(socket_address(gateway, port)).await?;

        Ok(socket)
    }

    /// Open a TCP connection to the given address, applying the configured firewall mark.
    /// # Errors
    /// Will return an error if we fail to create the socket or connect to the address.
    pub async fn connect_tcp(
        address: std::net::SocketAddr,
    ) -> Result<tokio::net::TcpStream, std::io::Error> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        apply_fwmark(&socket)?;
        socket.set_nonblocking(true)?;

        tokio::net::TcpSocket::from_std_stream(socket.into())
            .connect(address)
            .await
    }

    /// Create a TCP listener bound to the given address, applying the configured firewall mark.
    /// Connections accepted from the listener inherit the mark for their responses.
    /// # Errors
    /// Will return an error if we fail to bind or listen on the address.
    pub fn bind_tcp_listener(
        address: std::net::SocketAddr,
    ) -> Result<tokio::net::TcpListener, std::io::Error> {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        apply_fwmark(&socket)?;
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        socket.listen(1024)?;

        tokio::net::TcpListener::from_std(socket.into())
    }

    /// Create a UDP socket listening for multicast gateway announcements on the announcement port.
    /// The RFC instructs clients to allow address reuse, so that other listening programs can
    /// coexist, and to bind the multicast group address itself rather than the unspecified
    /// address, see <https://www.rfc-editor.org/rfc/rfc6886#section-3.2.1>.
    /// # Errors
    /// Will return an error if we fail to bind to the announcement port.
    pub fn bind_announcement_socket(gateway: GatewayAddress) -> Result<UdpSocket, std::io::Error> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

        let (domain, bind_address) = match &gateway {
            GatewayAddress::IpV4(_) => (
                Domain::IPV4,
                // Binding the group address also filters unrelated unicast traffic,
                // but is not supported on all platforms.
                if cfg!(windows) {
                    SocketAddr::from((Ipv4Addr::UNSPECIFIED, crate::ANNOUNCEMENT_PORT))
                } else {
                    SocketAddr::from((Ipv4Addr::new(224, 0, 0, 1), crate::ANNOUNCEMENT_PORT))
                },
            ),
            GatewayAddress::IpV6(_, _) => (
                Domain::IPV6,
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    crate::ANNOUNCEMENT_PORT,
                    0,
                    0,
                )),
            ),
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        apply_fwmark(&socket)?;
        socket.set_reuse_address(true)?;
        #[cfg(all(
            unix,
            not(any(
                target_os = "solaris",
                target_os = "illumos",
                target_os = "cygwin",
                target_os = "nuttx"
            ))
        ))]
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&bind_address.into())?;
        let socket = UdpSocket::from_std(socket.into())?;

        // Announcements are addressed to the all-hosts and all-nodes multicast groups, which
        // hosts are implicitly members of; join explicitly where supported and continue otherwise.
        match gateway {
            GatewayAddress::IpV4(_) => {
                let _ =
                    socket.join_multicast_v4(Ipv4Addr::new(224, 0, 0, 1), Ipv4Addr::UNSPECIFIED);
            }
            GatewayAddress::IpV6(_, scope_id) => {
                let _ = socket.join_multicast_v6(
                    &Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 1),
                    scope_id.unwrap_or(0),
                );
            }
        }

        Ok(socket)
    }

    pub enum RequestSendError {
        Socket(std::io::Error),
        Timeout,
    }

    /// Send a request and wait for a response, retrying on timeout up to `max_retries` times.
    /// Allow for a custom fuzzing function to be applied to the timeout after each retry. This is to
    /// avoid synchronization issues, but `std::convert::identity` can be used as a no-op.
    /// `fuzz_timeout` is given the timeout to be used for the next request, and can be modified in
    /// place if necessary.
    /// # Returns
    /// On success, will return the number of bytes read from the response into `recv_buf`.
    /// # Errors
    /// Will return a `Socket(..)` error if we:
    /// * Failed to send data on the socket
    /// * Failed to receive data on the socket
    ///
    /// Otherwise, will return a `Timeout` error if the gateway could not be reached after all retries.
    pub async fn try_send_until_response<B, F>(
        timeout_config: TimeoutConfig,
        socket: &UdpSocket,
        send_bytes: &[u8],
        recv_buf: &mut B,
        fuzz_timeout: F,
    ) -> Result<usize, RequestSendError>
    where
        B: bytes::BufMut,
        F: Fn(Duration) -> Duration,
    {
        // Internal helper to try sending and receiving packets; will springboard errors back to the caller.
        async fn send_and_recv<B: bytes::BufMut>(
            socket: &UdpSocket,
            send_bytes: &[u8],
            recv_buf: &mut B,
            timeout: Duration,
        ) -> Result<usize, RequestSendError> {
            socket
                .send(send_bytes)
                .await
                .map_err(RequestSendError::Socket)?;

            tokio::time::timeout(timeout, socket.recv_buf(recv_buf))
                .await
                .map_err(|_| RequestSendError::Timeout)?
                .map_err(RequestSendError::Socket)
        }

        // Use the specified initial timeout and double it on each successive failure, with optional fuzzing.
        // NOTE: Technically, `fuzz_timeout` fuzzes [0.95-1.05] of the initial timeout in PCP, whereas the RFC recommends [0.9-1.1].
        //       However, the approach used allows the types to stay as positive `Duration`s while meeting the max-timeout requirements.
        let mut wait = fuzz_timeout(timeout_config.initial_timeout);
        let mut retries = 0;
        let max_retries = timeout_config.max_retries;
        loop {
            match send_and_recv(socket, send_bytes, recv_buf, wait).await {
                // Return the number of bytes read from the response.
                Ok(n) => return Ok(n),

                // Retry on timeout up to `max_retries` times.
                Err(RequestSendError::Timeout) => {
                    if retries >= max_retries {
                        return Err(RequestSendError::Timeout);
                    }
                    retries += 1;

                    // Both NAT-PMP and PCP have a base scaling of doubling the timeout each retry.
                    wait += wait;

                    // Limit the timeout to the configured maximum.
                    // This was added with the PCP RFC, but is supported here for both protocols.
                    if let Some(max) = timeout_config.max_retry_timeout {
                        if wait > max {
                            wait = max;
                        }
                    }

                    // PCP specifies that fuzzing be done after applying the maximum timeout, to avoid synchronization issues.
                    wait = fuzz_timeout(wait);

                    // Optionally log retry attempts to tracing.
                    #[cfg(feature = "tracing")]
                    tracing::info!("Starting retry {retries}/{max_retries} with timeout {wait:?}");
                }

                // Any other error is returned immediately.
                Err(e) => return Err(e),
            }
        }
    }
}

/// Errors that occur during the respective port mapping protocols.
#[derive(Debug, thiserror::Error)]
pub enum MappingFailure {
    #[error("NAT-PMP({0})")]
    NatPmp(#[from] natpmp::Failure),

    #[error("PCP({0})")]
    Pcp(#[from] pcp::Failure),

    #[error("UPnP({0})")]
    Upnp(#[from] upnp::Failure),
}

/// The failure returned when `PortMapping::new` has exhausted its protocol fallback chain.
#[derive(Debug, thiserror::Error)]
#[error("{failure}{}", .retry_after_seconds.map_or_else(String::new, |s| format!(" (PCP server estimates the error will persist for {s} seconds)")))]
pub struct FallbackFailure {
    /// The failure returned by the last protocol attempted.
    #[source]
    pub failure: MappingFailure,

    /// The number of seconds the PCP server estimated its error will persist, when it reported one.
    /// NAT-PMP and UPnP servers do not give such estimates, see `pcp::Failure::retry_after_seconds`.
    pub retry_after_seconds: Option<u32>,
}

/// Whether a socket error indicates that nothing is listening on the port we sent a datagram to.
/// The ICMP rejection is reported as `ConnectionRefused` on most platforms, but as
/// `ConnectionReset` on Windows.
fn is_port_closed_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
    )
}

/// The protocol `PortMapping::new` should attempt next after a PCP failure.
enum PcpFallback {
    /// The failure describes a state shared by all mapping protocols; no fallback will help.
    None,

    /// The gateway recommended NAT-PMP, or the responder may only speak NAT-PMP correctly.
    NatPmp,

    /// NAT-PMP was ruled out along with PCP, but UPnP may still be available.
    Upnp,
}

/// Categorize which fallback protocol, if any, may still succeed after the given PCP failure.
/// Errors describing a state shared by all mapping protocols, e.g. the gateway lacking resources
/// for a new mapping or experiencing a network failure, do not benefit from a fallback.
fn pcp_failure_fallback(failure: &pcp::Failure) -> PcpFallback {
    match failure {
        // The gateway explicitly recommends a version downgrade, gave a response we could not
        // understand, or rejected the request itself. The responder may only speak NAT-PMP correctly.
        pcp::Failure::UnsupportedVersion(_)
        | pcp::Failure::InvalidResponse(_)
        | pcp::Failure::Nonce
        | pcp::Failure::MalformedRequest
        | pcp::Failure::NotAuthorized(_) => PcpFallback::NatPmp,

        // The client address we sent does not match the address the server saw, so no plain PCP
        // request can succeed. NAT-PMP requests carry no client address and always map the
        // address the gateway sees, so it cannot fail the same way.
        pcp::Failure::AddressMismatch => PcpFallback::NatPmp,

        // Nothing responded in time. NAT-PMP servers are required to answer requests with an
        // unknown version using an "unsupported version" error (<https://www.rfc-editor.org/rfc/rfc6886#section-3.5>),
        // and PCP relies on that reply for downgrades (<https://www.rfc-editor.org/rfc/rfc6887#section-9>),
        // so a silent gateway is assumed not to speak NAT-PMP either.
        pcp::Failure::Timeout => PcpFallback::Upnp,

        // The gateway speaks well-formed PCP but cannot serve this request; it would have
        // recommended NAT-PMP with an unsupported version response if it preferred it.
        pcp::Failure::UnsupportedOpcode
        | pcp::Failure::UnsupportedOption
        | pcp::Failure::MalformedOption
        | pcp::Failure::UnsupportedProtocol => PcpFallback::Upnp,

        // A rejection indicates that the gateway does not listen on the port NAT-PMP and PCP
        // share. Other socket errors are local or environmental and would affect any protocol.
        pcp::Failure::Socket(e) => {
            if is_port_closed_error(e) {
                PcpFallback::Upnp
            } else {
                PcpFallback::None
            }
        }

        // The gateway state or the request itself would cause any mapping protocol to fail.
        pcp::Failure::NetworkFailure(_)
        | pcp::Failure::NoResources(_)
        | pcp::Failure::UserExceededQuota(_)
        | pcp::Failure::CannotProvideExternal(_)
        | pcp::Failure::ExcessiveRemotePeers => PcpFallback::None,
    }
}

/// Whether a NAT-PMP failure is specific to the NAT-PMP protocol, meaning a fallback protocol may still succeed.
/// See `pcp_failure_fallback` for the reasoning behind the categorization.
fn natpmp_failure_is_protocol_specific(failure: &natpmp::Failure) -> bool {
    match failure {
        // Nothing intelligible is answering NAT-PMP requests, or the server refused to process ours.
        natpmp::Failure::Timeout
        | natpmp::Failure::InvalidResponse(_)
        | natpmp::Failure::UnsupportedVersion(_)
        | natpmp::Failure::NotAuthorized
        | natpmp::Failure::UnsupportedOpcode => true,

        // A rejection indicates that the gateway does not listen on the NAT-PMP port at all.
        // Other socket errors are local or environmental and would affect any protocol.
        natpmp::Failure::Socket(e) => is_port_closed_error(e),

        // The gateway state would cause any mapping protocol to fail.
        natpmp::Failure::NetworkFailure | natpmp::Failure::OutOfResources => false,
    }
}
