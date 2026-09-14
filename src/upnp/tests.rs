use super::*;

/// A search response in the style of common gateway implementations should yield its location.
#[test]
fn test_parse_search_response_valid() {
    let response = "HTTP/1.1 200 OK\r\n\
                    CACHE-CONTROL: max-age=120\r\n\
                    ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                    USN: uuid::00000000-0000-0000-0000-000000000000\r\n\
                    EXT:\r\n\
                    SERVER: TestOS/1.0 UPnP/1.1 TestServer/1.0\r\n\
                    LOCATION: http://192.168.1.1:1900/rootDesc.xml\r\n\r\n";
    assert_eq!(
        parse_search_response(response).unwrap(),
        "http://192.168.1.1:1900/rootDesc.xml"
    );
}

/// Header names are case-insensitive.
#[test]
fn test_parse_search_response_mixed_case_location() {
    let response = "HTTP/1.1 200 OK\r\nLocation: http://192.168.1.1/desc.xml\r\n\r\n";
    assert_eq!(
        parse_search_response(response).unwrap(),
        "http://192.168.1.1/desc.xml"
    );
}

/// A search response without a location header cannot be used.
#[test]
fn test_parse_search_response_missing_location() {
    let response = "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n";
    assert!(matches!(
        parse_search_response(response).unwrap_err(),
        InvalidResponseKind::MissingLocation
    ));
}

/// Search responses always use the HTTP success status line.
#[test]
fn test_parse_search_response_bad_status() {
    let response = "HTTP/1.1 404 Not Found\r\nLOCATION: http://192.168.1.1/desc.xml\r\n\r\n";
    assert!(matches!(
        parse_search_response(response).unwrap_err(),
        InvalidResponseKind::SearchResponse
    ));
}

/// HTTP URLs decompose into their authority and path.
#[test]
fn test_split_http_url() {
    assert_eq!(
        split_http_url("http://192.168.1.1:1900/rootDesc.xml").unwrap(),
        ("192.168.1.1:1900", "/rootDesc.xml")
    );

    // The path defaults to the root when missing.
    assert_eq!(
        split_http_url("http://192.168.1.1:1900").unwrap(),
        ("192.168.1.1:1900", "/")
    );

    // The port may be omitted, and IPv6 hosts are given in brackets.
    assert_eq!(
        split_http_url("http://[fd00::1]/desc.xml").unwrap(),
        ("[fd00::1]", "/desc.xml")
    );
}

/// Only plain HTTP URLs are supported.
#[test]
fn test_split_http_url_invalid() {
    assert!(matches!(
        split_http_url("https://192.168.1.1/desc.xml").unwrap_err(),
        InvalidResponseKind::InvalidUrl(_)
    ));
    assert!(matches!(
        split_http_url("http://").unwrap_err(),
        InvalidResponseKind::InvalidUrl(_)
    ));
}

/// Authorities yield their port, defaulting to the standard HTTP port.
#[test]
fn test_authority_port() {
    assert_eq!(authority_port("192.168.1.1:49000").unwrap(), 49000);
    assert_eq!(authority_port("192.168.1.1").unwrap(), 80);
    assert_eq!(authority_port("[fd00::1]:8080").unwrap(), 8080);
    assert_eq!(authority_port("[fd00::1]").unwrap(), 80);

    // A bare IPv6 literal contains colons but no port.
    assert_eq!(authority_port("fd00::1").unwrap(), 80);

    // Host names may carry a port like any other authority.
    assert_eq!(authority_port("gateway.local:5000").unwrap(), 5000);
    assert!(matches!(
        authority_port("192.168.1.1:notaport").unwrap_err(),
        InvalidResponseKind::InvalidUrl(_)
    ));
}

/// Service type strings map to the matching WAN connection service.
#[test]
fn test_wan_service_from_service_type() {
    assert_eq!(
        WanService::from_service_type("urn:schemas-upnp-org:service:WANIPConnection:1"),
        Some(WanService::WanIpConnection1)
    );
    assert_eq!(
        WanService::from_service_type("urn:schemas-upnp-org:service:WANIPConnection:2"),
        Some(WanService::WanIpConnection2)
    );
    assert_eq!(
        WanService::from_service_type("urn:schemas-upnp-org:service:WANPPPConnection:1"),
        Some(WanService::WanPppConnection1)
    );

    // Higher service versions are treated as the latest supported version.
    assert_eq!(
        WanService::from_service_type("urn:schemas-upnp-org:service:WANIPConnection:3"),
        Some(WanService::WanIpConnection2)
    );

    // A missing version, used by some devices predating the standardized descriptions, is treated as `1`.
    assert_eq!(
        WanService::from_service_type("urn:schemas-upnp-org:service:WANIPConnection"),
        Some(WanService::WanIpConnection1)
    );

    // Unrelated services and invalid versions do not match.
    assert_eq!(
        WanService::from_service_type("urn:schemas-upnp-org:service:Layer3Forwarding:1"),
        None
    );
    assert_eq!(
        WanService::from_service_type("urn:schemas-upnp-org:service:WANIPConnection:0"),
        None
    );
}

/// Helper to format a device description containing the given service entries.
fn make_description(services: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\
         <root xmlns=\"urn:schemas-upnp-org:device-1-0\">\
         <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\
         <serviceList>{services}</serviceList></device></root>"
    )
}

/// WAN connection services should be found and ordered with the most capable first.
#[test]
fn test_parse_device_description_prefers_latest_service() {
    let description = make_description(
        "<service>\
         <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>\
         <controlURL>/ctl/PPP</controlURL>\
         </service>\
         <service>\
         <serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>\
         <controlURL>/ctl/IPConn2</controlURL>\
         </service>\
         <service>\
         <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
         <controlURL>/ctl/IPConn1</controlURL>\
         </service>",
    );
    let (services, url_base) = parse_device_description(&description).unwrap();
    assert_eq!(
        services,
        vec![
            (WanService::WanIpConnection2, "/ctl/IPConn2".to_string()),
            (WanService::WanIpConnection1, "/ctl/IPConn1".to_string()),
            (WanService::WanPppConnection1, "/ctl/PPP".to_string()),
        ]
    );
    assert_eq!(url_base, None);
}

/// Service entries without a control URL cannot be used and should be skipped.
#[test]
fn test_parse_device_description_skips_missing_control_url() {
    let description = make_description(
        "<service>\
         <serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>\
         </service>\
         <service>\
         <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
         <controlURL>/ctl/IPConn1</controlURL>\
         </service>",
    );
    let (services, _) = parse_device_description(&description).unwrap();
    assert_eq!(
        services,
        vec![(WanService::WanIpConnection1, "/ctl/IPConn1".to_string())]
    );
}

/// A description without a WAN connection service is an error.
#[test]
fn test_parse_device_description_no_service() {
    let description = make_description(
        "<service>\
         <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>\
         <controlURL>/ctl/L3F</controlURL>\
         </service>",
    );
    assert!(matches!(
        parse_device_description(&description).unwrap_err(),
        InvalidResponseKind::NoWanConnectionService
    ));
}

/// The legacy `URLBase` element should be extracted, and XML entities in URLs decoded.
#[test]
fn test_parse_device_description_url_base_and_entities() {
    let description = format!(
        "<root><URLBase>http://192.168.1.1:5000</URLBase>{}</root>",
        make_description(
            "<service>\
             <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
             <controlURL>/ctl?a=1&amp;b=2</controlURL>\
             </service>"
        )
    );
    let (services, url_base) = parse_device_description(&description).unwrap();
    assert_eq!(url_base.as_deref(), Some("http://192.168.1.1:5000"));
    assert_eq!(services[0].1, "/ctl?a=1&b=2");
}

/// Control URLs resolve against the description location, the `URLBase`, or stand alone.
#[test]
fn test_resolve_control_url() {
    // An absolute URL requires no resolution.
    assert_eq!(
        resolve_control_url(
            "http://192.168.1.1:49000/ctl",
            None,
            "192.168.1.1:1900",
            "/rootDesc.xml"
        )
        .unwrap(),
        ("192.168.1.1:49000".to_string(), "/ctl".to_string())
    );

    // An absolute path keeps the authority of the description.
    assert_eq!(
        resolve_control_url("/ctl/IPConn", None, "192.168.1.1:1900", "/rootDesc.xml").unwrap(),
        ("192.168.1.1:1900".to_string(), "/ctl/IPConn".to_string())
    );

    // A relative path replaces the last segment of the description path.
    assert_eq!(
        resolve_control_url("ctl", None, "192.168.1.1:1900", "/upnp/rootDesc.xml").unwrap(),
        ("192.168.1.1:1900".to_string(), "/upnp/ctl".to_string())
    );

    // The `URLBase` takes precedence over the description location.
    assert_eq!(
        resolve_control_url(
            "ctl",
            Some("http://192.168.1.1:5000/base/"),
            "192.168.1.1:1900",
            "/rootDesc.xml"
        )
        .unwrap(),
        ("192.168.1.1:5000".to_string(), "/base/ctl".to_string())
    );
}

/// A response with a content length is complete once the full body has arrived.
#[test]
fn test_parse_http_response_content_length() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

    // The response is incomplete until the full body has been read.
    assert!(parse_http_response(&response[..response.len() - 1], false)
        .unwrap()
        .is_none());

    let response = parse_http_response(response, false).unwrap().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "hello");
    assert_eq!(response.location, None);
}

/// A chunked response is complete once the terminating zero-size chunk has arrived.
#[test]
fn test_parse_http_response_chunked() {
    let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n8;ext=1\r\n, chunks\r\n0\r\n\r\n";

    // The response is incomplete until the terminating chunk has been read.
    assert!(parse_http_response(&response[..response.len() - 5], false)
        .unwrap()
        .is_none());

    let response = parse_http_response(response, false).unwrap().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "hello, chunks");
}

/// Without explicit framing, the body is terminated by the connection closing.
#[test]
fn test_parse_http_response_read_to_end() {
    let response = b"HTTP/1.1 500 Internal Server Error\r\nServer: Test\r\n\r\nsome fault";
    assert!(parse_http_response(response, false).unwrap().is_none());

    let response = parse_http_response(response, true).unwrap().unwrap();
    assert_eq!(response.status, 500);
    assert_eq!(response.body, "some fault");
}

/// Devices which overstate their content length are accepted once the connection closes.
#[test]
fn test_parse_http_response_overstated_content_length() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\nshort body";
    assert!(parse_http_response(response, false).unwrap().is_none());

    let response = parse_http_response(response, true).unwrap().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "short body");
}

/// Redirect responses should expose the target of their location header.
#[test]
fn test_parse_http_response_redirect_location() {
    let response =
        b"HTTP/1.1 302 Found\r\nLocation: http://192.168.1.1:5000/desc.xml\r\nContent-Length: 0\r\n\r\n";
    let response = parse_http_response(response, false).unwrap().unwrap();
    assert_eq!(response.status, 302);
    assert_eq!(
        response.location.as_deref(),
        Some("http://192.168.1.1:5000/desc.xml")
    );
}

/// A response cut short by the connection closing before its head completes is invalid.
#[test]
fn test_parse_http_response_truncated_head() {
    let partial_head = b"HTTP/1.1 200 OK\r\nContent-Le";
    assert!(parse_http_response(partial_head, false).unwrap().is_none());
    assert!(matches!(
        parse_http_response(partial_head, true).unwrap_err(),
        InvalidResponseKind::HttpResponse
    ));
}

/// Simple devices may terminate header lines with a bare line feed.
#[test]
fn test_parse_http_response_bare_line_feeds() {
    let response = b"HTTP/1.1 200 OK\nContent-Length: 5\n\nhello";
    let response = parse_http_response(response, false).unwrap().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "hello");
}

/// Unrequested interim responses should be skipped in favor of the response that follows.
#[test]
fn test_parse_http_response_interim_continue() {
    let response = b"HTTP/1.1 100 Continue\r\n\r\n\
                     HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let response = parse_http_response(response, false).unwrap().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "hello");
}

/// Responses without a valid HTTP status line are invalid.
#[test]
fn test_parse_http_response_invalid_status() {
    let response = b"SIP/2.0 200 OK\r\n\r\n";
    assert!(matches!(
        parse_http_response(response, true).unwrap_err(),
        InvalidResponseKind::HttpResponse
    ));
}

/// UPnP error responses should map to the failure matching their error code.
#[test]
fn test_response_error() {
    /// Helper to format a SOAP fault with the given UPnP error code.
    fn make_fault(error_code: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?>\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault>\
             <faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>\
             <detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
             <errorCode>{error_code}</errorCode><errorDescription>Test</errorDescription>\
             </UPnPError></detail></s:Fault></s:Body></s:Envelope>"
        )
    }

    assert!(matches!(
        response_error(&make_fault("718")),
        Some(Failure::ConflictInMappingEntry)
    ));
    assert!(matches!(
        response_error(&make_fault("725")),
        Some(Failure::OnlyPermanentLeasesSupported)
    ));
    assert!(matches!(
        response_error(&make_fault("606")),
        Some(Failure::ActionNotAuthorized)
    ));

    // Unrecognized error codes are reported with their raw value.
    assert!(matches!(
        response_error(&make_fault("799")),
        Some(Failure::UnknownErrorCode(799))
    ));

    // An unparsable error code is an invalid response.
    assert!(matches!(
        response_error(&make_fault("oops")),
        Some(Failure::InvalidResponse(InvalidResponseKind::ErrorResponse))
    ));

    // A response without an error code is not an error; the status code decides.
    assert!(response_error("<html>internal error</html>").is_none());
}

/// All recognized error codes should map to the correct `Failure` variant.
#[test]
fn test_code_to_failure() {
    assert!(matches!(code_to_failure(401), Failure::InvalidAction));
    assert!(matches!(code_to_failure(402), Failure::InvalidArgs));
    assert!(matches!(code_to_failure(501), Failure::ActionFailed));
    assert!(matches!(
        code_to_failure(602),
        Failure::OptionalActionNotImplemented
    ));
    assert!(matches!(code_to_failure(606), Failure::ActionNotAuthorized));
    assert!(matches!(code_to_failure(714), Failure::NoSuchEntryInArray));
    assert!(matches!(
        code_to_failure(716),
        Failure::WildCardNotPermittedInExtPort
    ));
    assert!(matches!(
        code_to_failure(718),
        Failure::ConflictInMappingEntry
    ));
    assert!(matches!(
        code_to_failure(725),
        Failure::OnlyPermanentLeasesSupported
    ));
    assert!(matches!(code_to_failure(728), Failure::NoPortMapsAvailable));
    assert!(matches!(
        code_to_failure(729),
        Failure::ConflictWithOtherMechanisms
    ));
    assert!(matches!(code_to_failure(0), Failure::UnknownErrorCode(0)));
}

/// Tag values are extracted from the narrow XML used by UPnP and trimmed of whitespace.
#[test]
fn test_find_tag_value() {
    let xml = "<a><b> value </b><c>other</c></a>";
    assert_eq!(find_tag_value(xml, "b"), Some("value"));
    assert_eq!(find_tag_value(xml, "c"), Some("other"));
    assert_eq!(find_tag_value(xml, "d"), None);

    // Unterminated tags yield nothing.
    assert_eq!(find_tag_value("<a>unterminated", "a"), None);
}

/// The predefined XML entities should decode, including double-escaped values.
#[test]
fn test_decode_xml_entities() {
    assert_eq!(decode_xml_entities("/ctl?a=1&amp;b=2"), "/ctl?a=1&b=2");
    assert_eq!(decode_xml_entities("&lt;&gt;&quot;&apos;&amp;"), "<>\"'&");

    // A double-escaped ampersand decodes exactly one level.
    assert_eq!(decode_xml_entities("&amp;lt;"), "&lt;");
}
