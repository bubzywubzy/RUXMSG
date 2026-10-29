#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ruxmsg_net::FrameDecoder;

#[derive(Arbitrary, Debug)]
struct StreamInput {
    chunks: Vec<Vec<u8>>,
}

fuzz_target!(|input: StreamInput| {
    let mut decoder = FrameDecoder::new();

    for chunk in input.chunks.into_iter().take(256) {
        decoder.push(&chunk);

        loop {
            match decoder.next_frame() {
                Ok(Some(_frame)) => {}
                Ok(None) | Err(_) => break,
            }
        }
    }
});
