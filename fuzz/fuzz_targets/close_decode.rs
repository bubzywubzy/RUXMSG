#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxmsg::close::ClosePayload;
use ruxmsg::protocol::MessageType;
use ruxmsg::wire::Frame;

fuzz_target!(|input: &[u8]| {
    if let Ok(frame) = Frame::new(MessageType::Close, input.to_vec()) {
        let _ = ClosePayload::decode(&frame);
    }
});
