#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ruxmsg::protocol::{DirectionId, MAX_PREPARED_KEYS};
use ruxmsg::ratchet::{ReceivingChain, ReplayWindow};

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
                assert!(chain.skipped_len() <= MAX_PREPARED_KEYS);
            }
            RatchetOp::CommitKey(counter) => {
                let _ = chain.commit_message_key(counter);
            }
        }
    }
});
