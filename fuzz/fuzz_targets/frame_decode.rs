#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxmsg::wire::Frame;

fuzz_target!(|input: &[u8]| {
    let _ = Frame::decode(input);
});
