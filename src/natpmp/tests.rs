use super::*;

/// Proper codes with R bit set should convert to the correct `OperationCode`.
#[test]
fn test_response_to_opcode_valid() {
    assert_eq!(
        response_to_opcode(0x80).unwrap(),
        OperationCode::ExternalAddress
    );
    assert_eq!(response_to_opcode(0x81).unwrap(), OperationCode::MapUdp);
    assert_eq!(response_to_opcode(0x82).unwrap(), OperationCode::MapTcp);
}

/// Codes without the R bit set should be rejected.
#[test]
fn test_response_to_opcode_r_bit_unset() {
    let err = response_to_opcode(0x01).unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidResponse(InvalidResponseKind::ResponseBitNotSet(0x01))
    ));
}

/// R bit set but opcode 0x7F is not a valid OperationCode
#[test]
fn test_response_to_opcode_invalid_opcode() {
    let err = response_to_opcode(0xFF).unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidResponse(InvalidResponseKind::InvalidOperationCode(0x7F))
    ));
}

/// The success code always maps to `Ok(())`.
#[test]
fn test_code_to_result_success() {
    assert!(code_to_result(ResultCode::Success, VersionCode::NatPmp).is_ok());
}

/// The unsupported version code should map to the correct `Failure` variant with the version included.
#[test]
fn test_code_to_result_unsupported_version() {
    let err = code_to_result(ResultCode::UnsupportedVersion, VersionCode::NatPmp).unwrap_err();
    assert!(matches!(
        err,
        Failure::UnsupportedVersion(VersionCode::NatPmp)
    ));
    let err = code_to_result(ResultCode::UnsupportedVersion, VersionCode::Pcp).unwrap_err();
    assert!(matches!(err, Failure::UnsupportedVersion(VersionCode::Pcp)));
}

/// All error codes should map to the correct `Failure` variant.
#[test]
fn test_code_to_result_all_errors() {
    assert!(matches!(
        code_to_result(ResultCode::NotAuthorized, VersionCode::NatPmp).unwrap_err(),
        Failure::NotAuthorized
    ));
    assert!(matches!(
        code_to_result(ResultCode::NetworkFailure, VersionCode::NatPmp).unwrap_err(),
        Failure::NetworkFailure
    ));
    assert!(matches!(
        code_to_result(ResultCode::OutOfResources, VersionCode::NatPmp).unwrap_err(),
        Failure::OutOfResources
    ));
    assert!(matches!(
        code_to_result(ResultCode::UnsupportedOpcode, VersionCode::NatPmp).unwrap_err(),
        Failure::UnsupportedOpcode
    ));
}

/// External address change announcements share the format of an `ExternalAddress` response.
#[test]
fn test_parse_address_announcement() {
    let mut announcement = [0u8; 12];
    announcement[1] = 0x80; // `ExternalAddress` response opcode.
    announcement[4..8].copy_from_slice(&2000u32.to_be_bytes()); // Gateway epoch.
    announcement[8..12].copy_from_slice(&[80, 100, 100, 1]); // External address.
    assert_eq!(
        parse_address_announcement(&announcement),
        Some((Ipv4Addr::new(80, 100, 100, 1), 2000))
    );

    // Failed responses and other messages are not announcements.
    let mut failed = announcement;
    failed[3] = ResultCode::NetworkFailure as u8;
    assert_eq!(parse_address_announcement(&failed), None);
    assert_eq!(parse_address_announcement(&announcement[..8]), None);
}
