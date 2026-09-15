#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxmsg::handshake::{HandshakePayload, HelloPayload, SessionConfirmPayload};
use ruxmsg::protocol::MessageType;
use ruxmsg::wire::Frame;

fuzz_target!(|data: (u8, Vec<u8>)| {
    let (type_byte, payload) = data;
    let message_type = match type_byte % 5 {
        0 => MessageType::Handshake,
        1 => MessageType::SessionConfirm,
        2 => MessageType::Data,
        3 => MessageType::Rekey,
        _ => MessageType::Close,
    };
    if let Ok(frame) = Frame::new(message_type, payload) {
        let _ = HelloPayload::decode(&frame);
        let _ = HandshakePayload::decode(&frame);
        let _ = SessionConfirmPayload::decode(&frame);
    }
});
