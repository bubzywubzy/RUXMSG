#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxmsg::data::DataReceiver;
use ruxmsg::protocol::{DirectionId, MessageType, SessionId};
use ruxmsg::wire::Frame;

// Fuzzes the AEAD/replay/padding decode path directly, without needing a real
// handshake, by handing arbitrary bytes to a receiver with a fixed key.
fuzz_target!(|input: &[u8]| {
    if let Ok(frame) = Frame::new(MessageType::Data, input.to_vec()) {
        let mut receiver = DataReceiver::new(
            SessionId::from_bytes([0; 16]),
            DirectionId::InitiatorToResponder,
            [7; 32],
        );
        let _ = receiver.decrypt(&frame);
    }
});
