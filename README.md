# 🦀 NAT

A library providing a pure Rust implementation of a client for the NAT Port Mapping Protocol (NAT-PMP, [RFC 6886](https://www.rfc-editor.org/rfc/rfc6886)), the Port Control Protocol (PCP, [RFC 6887](https://www.rfc-editor.org/rfc/rfc6887)), and the UPnP Internet Gateway Device protocol ([IGD](https://openconnectivity.org/developer/specifications/upnp-resources/upnp/internet-gateway-device-igd-v-2-0/)).

This library is intended to feel like high level, idiomatic Rust, while still maintaining a strong focus on performance. It is asynchronous and uses the [tokio](https://tokio.rs) runtime to avoid blocking operations and to succinctly handle timeouts on UDP sockets.

## Usage
If there isn't a preference on which port mapping protocol is used or what the external port should be, etc., then usage looks as follows:
```rust
// Attempt a port mapping request through PCP first, falling back to NAT-PMP and then UPnP.
let mapping = match crab_nat::PortMapping::new(
    gateway, /* Address of the PCP server, often a gateway or firewall */
    local_address, /* Address of our client, as seen by the gateway. Only used by PCP and UPnP */
    crab_nat::InternetProtocol::Tcp, /* Protocol to map */
    std::num::NonZeroU16::new(8080).unwrap(), /* Internal port, cannot be zero */
    crab_nat::PortMappingOptions::default(), /* Optional configuration values, including suggested external port and lifetimes */
)
.await
{
    Ok(m) => m,
    Err(e) => return eprintln!("Failed to map port: {e:?}"),
};

// ...

// Try to safely drop the mapping.
if let Err((e, m)) = mapping.try_drop().await {
    eprintln!("Failed to drop mapping {}:{}->{}: {e:?}", m.gateway(), m.external_port(), m.internal_port());
} else {
    println!("Successfully deleted the mapping...");
}
```

If there is a preference on which protocol to use then you can access the `natpmp`, `pcp`, and `upnp` modules directly.

Crab NAT does not determine the gateway address or the local client address. This is to reduce unnecessary assumptions about how this library will be used. For an easy API to determine these values reliably, I recommend using [netdev](https://crates.io/crates/netdev); see the example [client](examples/client.rs) for basic usage.

### Address change notifications
`AddressChangeListener` reports when the gateway's external address changes. `AddressChangeListener::bind_for_mapping` listens with the mechanism matching an existing mapping's protocol: NAT-PMP and PCP servers announce changes over multicast, while UPnP gateways deliver state change events to subscribers (also available directly with `bind` and `bind_with_upnp`). These notifications arrive as unsolicited inbound traffic, so host firewalls must permit:

* **UDP datagrams to port `5350`**, addressed to the multicast group `224.0.0.1` (IPv4) or `ff02::1` (IPv6) and sent by the gateway: NAT-PMP address change announcements and PCP `ANNOUNCE` messages.
* **TCP connections from the gateway to the event callback port** given to `bind_with_upnp`, which is ephemeral when unspecified: UPnP event notifications. Passing a fixed port keeps the firewall rule predictable. `bind_with_upnp` verifies delivery using the initial event gateways are required to send, and fails with `CallbackUnreachable` when it does not arrive.

The outbound requests this library makes (UDP to gateway port `5351`, SSDP searches to port `1900`, and HTTP connections for UPnP control) receive their responses through connection tracking and normally require no rules on stateful host firewalls. One caveat: some devices answer SSDP searches from a different port or address than they were reached at, and responses to the multicast search never match the request; strict firewalls drop such responses, so if UPnP discovery only fails while the firewall is enabled, allow inbound UDP from the gateway.

The announcement listener follows the RFC's guidance of sharing its port, so multiple listeners — including other programs' — can coexist on one host.

Even without a listener, a stale external address is corrected whenever a mapping is renewed: `PortMapping::renew` refreshes the address reported by `PortMapping::external_ip`.

### Crate Features
* `tracing`: Enables logging of UDP packet retry attempts using the [tracing](https://github.com/tokio-rs/tracing) crate. This currently only shows UDP retry attempts at an `INFO` verbosity level.

### Missing Implementation Details
* NAT-PMP:
  * External address change announcements (<https://www.rfc-editor.org/rfc/rfc6886#section-3.2.1>) are surfaced by `AddressChangeListener`, but no attempt is made to renew existing mappings automatically in response.
* PCP:
  * PCP supports more protocols than just UDP and TCP which are not yet added. I'm open to supporting more protocols if they are requested.
  * PCP defines a number of operation `Options` which are not implemented. I'm open to supporting some options if they are requested.
  * PCP `Announce` requests are not implemented; the unsolicited announcements servers multicast after state changes are surfaced by `AddressChangeListener`.
* UPnP:
  * Discovery uses unicast SSDP search requests to the given gateway rather than multicast, since this library takes an explicit gateway address. Multicast discovery of arbitrary devices is out of scope.
  * Gateways implementing only version 1 of the IGD specifications cannot be asked to choose a free external port, so the internal port is requested when no external port is specified. If the port is taken by another client, the gateway returns a `ConflictInMappingEntry` error rather than this library hunting for a free port.
  * Some firmware incorrectly answers a refresh of a client's own mapping with `ConflictInMappingEntry`. Renewals surface this error rather than deleting and recreating the mapping, which would briefly leave the port closed; callers who accept that window can drop and recreate the mapping themselves.
  * The `GENA` eventing and `GetGenericPortMappingEntry`/`GetListOfPortMappings` actions for enumerating existing mappings are not implemented.