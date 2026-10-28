#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ruxmsg::close::CloseReason;
use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::handshake::HelloRole;
use ruxmsg::machine::{DeadlineId, Effect, Engine, Entropy, Input};
use ruxmsg::protocol::MessageType;
use ruxmsg::wire::Frame;
use zeroize::Zeroizing;

struct Counter(u8);

impl Entropy for Counter {
    fn fill(&mut self, dest: &mut [u8]) {
        for byte in dest {
            self.0 = self.0.wrapping_mul(31).wrapping_add(7);
            *byte = self.0;
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Step {
    Start,
    Frame(u8, Vec<u8>),
    Sas(bool),
    Send(Vec<u8>),
    Close,
    Rekey,
    Timeout(u8),
    Eof,
}

fuzz_target!(|data: (bool, Vec<Step>)| {
    let (initiator, steps) = data;
    let role = if initiator { HelloRole::Initiator } else { HelloRole::Responder };
    let mut engine = Engine::new(role, IdentityKeypair::from_bytes(&[4; 32]), Box::new(Counter(1)));
    let mut armed: Vec<DeadlineId> = Vec::new();

    for step in steps.into_iter().take(64) {
        let input = match step {
            Step::Start => Input::Start,
            Step::Frame(kind, payload) => {
                let kind = match kind % 5 {
                    0 => MessageType::Handshake,
                    1 => MessageType::SessionConfirm,
                    2 => MessageType::Data,
                    3 => MessageType::Rekey,
                    _ => MessageType::Close,
                };
                match Frame::new(kind, payload) {
                    Ok(frame) => Input::FrameReceived(frame),
                    Err(_) => continue,
                }
            }
            Step::Sas(approved) => Input::SasDecision(approved),
            Step::Send(content) => Input::LocalSend(Zeroizing::new(content)),
            Step::Close => Input::LocalClose(CloseReason::Normal),
            Step::Rekey => Input::RequestRekey,
            Step::Timeout(index) => match armed.get(usize::from(index) % armed.len().max(1)) {
                Some(id) => Input::Timeout(*id),
                None => continue,
            },
            Step::Eof => Input::TransportClosed,
        };

        let effects = engine.handle(input);

        // Work per input is bounded regardless of what the peer sends.
        assert!(effects.len() <= 16);

        for effect in effects {
            match effect {
                Effect::SetDeadline { id, .. } => armed.push(id),
                Effect::CancelDeadline(id) => armed.retain(|existing| *existing != id),
                _ => {}
            }
        }

        assert!(engine.armed_deadlines() <= 6);
    }
});
