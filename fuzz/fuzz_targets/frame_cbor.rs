#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxmsg::protocol::MessageType;
use ruxmsg::wire::Frame;

fuzz_target!(|input: &[u8]| {
    if let Ok(frame) = Frame::new(MessageType::Data, input.to_vec()) {
        let _ = frame.validate_cbor_map();
    }
});
