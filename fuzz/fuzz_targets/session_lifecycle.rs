#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ruxmsg::protocol::SessionId;
use ruxmsg::session::{SessionLifecycle, SessionState};
use std::time::{Duration, Instant};

#[derive(Arbitrary, Debug)]
enum Op {
    Activate,
    BeginRekey,
    BeginDraining,
    Close,
    RecordSentData,
    AdvanceTime(u8),
}

// State-machine fuzzing: arbitrary call sequences must never let a DRAINING
// or CLOSED session originate DATA, regardless of order.
fuzz_target!(|ops: Vec<Op>| {
    let mut lifecycle = SessionLifecycle::new(SessionId::from_bytes([0; 16]));
    let mut now = Instant::now();
    for op in ops.into_iter().take(64) {
        match op {
            Op::Activate => {
                let _ = lifecycle.activate(now);
            }
            Op::BeginRekey => {
                let _ = lifecycle.begin_rekey();
            }
            Op::BeginDraining => {
                let _ = lifecycle.begin_draining(now);
            }
            Op::Close => lifecycle.close(),
            Op::RecordSentData => {
                let _ = lifecycle.record_sent_data();
            }
            Op::AdvanceTime(secs) => now += Duration::from_secs(u64::from(secs)),
        }
        let state = lifecycle.state();
        if matches!(state, SessionState::Draining | SessionState::Closed) {
            assert!(!lifecycle.can_originate_data());
        }
    }
});
