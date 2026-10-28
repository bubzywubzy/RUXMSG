#![no_main]

use libfuzzer_sys::fuzz_target;
use ruxmsg_cli::config::parse;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // Must never panic, overflow the stack, or loop.
        let _ = parse(text);
    }
});
