//! Per-type payload limits and MAX_CONTENT (spec §4.3).

use ruxmsg_core::data::DataSender;
use ruxmsg_core::protocol::{DirectionId, MessageType, SessionId, MAX_CONTENT};
use ruxmsg_core::wire::Frame;
use ruxmsg_core::Error;

#[test]
fn control_frames_are_limited_by_type() {
    for (kind, limit) in [
        (MessageType::Handshake, 1_024),
        (MessageType::Rekey, 1_024),
        (MessageType::SessionConfirm, 128),
        (MessageType::Close, 256),
    ] {
        assert!(Frame::new(kind, vec![0; limit]).is_ok());
        assert!(Frame::new(kind, vec![0; limit + 1]).is_err());
    }

    assert!(Frame::new(MessageType::Data, vec![0; 1_048_576]).is_ok());
}

#[test]
fn headers_are_checked_before_any_payload_is_needed() {
    assert_eq!(
        Frame::parse_header(&[1, 1, 0, 0, 4, 1]).err(),
        Some(Error::InvalidFrameLength(1_025))
    );
    assert_eq!(
        Frame::parse_header(&[1, 9, 0, 0, 0, 1]).err(),
        Some(Error::UnknownMessageType(0x09))
    );
    assert_eq!(
        Frame::parse_header(&[9, 1, 0, 0, 0, 1]).err(),
        Some(Error::UnsupportedVersion(9))
    );
    assert!(Frame::parse_header(&[1, 3, 0, 0x10, 0, 0]).is_ok());
    assert!(Frame::parse_header(&[1, 3, 0, 0x10, 0, 1]).is_err());
}

#[test]
fn sender_enforces_max_content() {
    let mut sender = DataSender::new(
        SessionId::from_bytes([1; 16]),
        DirectionId::InitiatorToResponder,
        [2; 32],
    );

    assert!(sender.encrypt(&vec![0; MAX_CONTENT]).is_ok());
    assert_eq!(
        sender.encrypt(&vec![0; MAX_CONTENT + 1]).err(),
        Some(Error::DataTooLarge)
    );
}
