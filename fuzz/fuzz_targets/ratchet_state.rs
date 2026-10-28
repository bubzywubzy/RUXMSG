#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ruxmsg::protocol::DirectionId;
use ruxmsg::ratchet::{ReceivingChain, ReplayWindow, ReplayStatus};

#[derive(Arbitrary, Debug)]
enum RatchetOp {
    Classify(u64),
    Accept(u64),
    PrepareKey(u64),
    CommitKey(u64),
}

fuzz_target!(|ops: Vec<RatchetOp>| {
    let mut window = ReplayWindow::new();
    let mut chain = ReceivingChain::new([0xAA; 32], DirectionId::InitiatorToResponder);

    for op in ops.into_iter().take(256) {
        match op {
            RatchetOp::Classify(counter) => {
                let _ = window.classify(counter);
            }
            RatchetOp::Accept(counter) => {
                let _ = window.accept(counter);
            }
            RatchetOp::PrepareKey(counter) => {
                let _ = chain.prepare_message_key(counter);
                // Ensure skipped keys never exceed the MAX_SKIPPED_KEYS bound + 1 (the target)
                assert!(chain.skipped_len() <= 65);
            }
            RatchetOp::CommitKey(counter) => {
                let _ = chain.commit_message_key(counter);
            }
        }
    }
});