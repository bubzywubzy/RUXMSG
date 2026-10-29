//! Sans-IO engine behaviour, driven by a deterministic simulator with a virtual clock.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use zeroize::Zeroizing;

use ruxmsg_core::close::{ClosePayload, CloseReason};
use ruxmsg_core::crypto::{IdentityKeypair, commit_hash};
use ruxmsg_core::handshake::{CommitPayload, HandshakePurpose, HelloPayload, HelloRole};
use ruxmsg_core::machine::{
    CloseCause, DeadlineId, DeadlineKind, Effect, Engine, EngineState, Entropy, Event, Input,
    RekeyFailure, SendRejection,
};
use ruxmsg_core::protocol::{MessageType, REKEY_INTERVAL_SECS, SessionId};
use ruxmsg_core::wire::Frame;

struct Seeded(u64);

impl Entropy for Seeded {
    fn fill(&mut self, dest: &mut [u8]) {
        for byte in dest {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *byte = (self.0 >> 24) as u8;
        }
    }
}

enum Wire {
    Frame(Frame),
    Eof,
}

struct Node {
    engine: Engine,
    deadlines: HashMap<DeadlineId, (Duration, DeadlineKind)>,
    delivered: Vec<Vec<u8>>,
    events: Vec<Event>,
    sas_words: Option<[&'static str; 3]>,
    auto_sas: Option<bool>,
    sent: Vec<Frame>,
    transport_closed: bool,
    blackhole: bool,
}

impl Node {
    fn new(role: HelloRole, seed: u8, rng: u64) -> Self {
        Self {
            engine: Engine::new(
                role,
                IdentityKeypair::from_bytes(&[seed; 32]),
                Box::new(Seeded(rng)),
            ),
            deadlines: HashMap::new(),
            delivered: Vec::new(),
            events: Vec::new(),
            sas_words: None,
            auto_sas: Some(true),
            sent: Vec::new(),
            transport_closed: false,
            blackhole: false,
        }
    }
}

struct Sim {
    nodes: [Node; 2],
    queues: [VecDeque<Wire>; 2],
    now: Duration,
}

impl Sim {
    fn new() -> Self {
        Self {
            nodes: [
                Node::new(HelloRole::Initiator, 1, 0x1234_5678_9abc_def1),
                Node::new(HelloRole::Responder, 2, 0x0fed_cba9_8765_4321),
            ],
            queues: [VecDeque::new(), VecDeque::new()],
            now: Duration::ZERO,
        }
    }

    /// Feeds an input to node `side` and applies the resulting effects.
    fn input(&mut self, side: usize, input: Input) {
        let effects = self.nodes[side].engine.handle(input);

        assert!(
            effects.len() <= 12,
            "one input produced {} effects",
            effects.len()
        );

        self.apply(side, effects);
    }

    fn apply(&mut self, side: usize, effects: Vec<Effect>) {
        let mut pending_sas = None;

        for effect in effects {
            match effect {
                Effect::Send(frame) => {
                    assert!(
                        !self.nodes[side].transport_closed,
                        "frame sent after CloseTransport"
                    );
                    self.nodes[side].sent.push(frame.clone());
                    if !self.nodes[side].blackhole {
                        self.queues[1 - side].push_back(Wire::Frame(frame));
                    }
                }
                Effect::SetDeadline { id, kind, after } => {
                    self.nodes[side]
                        .deadlines
                        .insert(id, (self.now + after, kind));
                }
                Effect::CancelDeadline(id) => {
                    self.nodes[side].deadlines.remove(&id);
                }
                Effect::RequestSas { words, .. } => {
                    self.nodes[side].sas_words = Some(words);
                    pending_sas = self.nodes[side].auto_sas;
                }
                Effect::Deliver(bytes) => self.nodes[side].delivered.push(bytes.to_vec()),
                Effect::Notify(event) => self.nodes[side].events.push(event),
                Effect::CloseTransport => {
                    self.nodes[side].transport_closed = true;
                    if !self.nodes[side].blackhole {
                        self.queues[1 - side].push_back(Wire::Eof);
                    }
                }
            }
        }

        if let Some(decision) = pending_sas {
            self.input(side, Input::SasDecision(decision));
        }
    }

    /// Delivers queued wire traffic until both directions are quiet.
    fn pump(&mut self) {
        loop {
            let mut progressed = false;

            for side in 0..2 {
                while let Some(item) = self.queues[side].pop_front() {
                    progressed = true;

                    let input = match item {
                        Wire::Frame(frame) => Input::FrameReceived(frame),
                        Wire::Eof => Input::TransportClosed,
                    };

                    self.input(side, input);
                }
            }

            if !progressed {
                break;
            }
        }
    }

    fn start(&mut self) {
        self.input(0, Input::Start);
        self.input(1, Input::Start);
        self.pump();
    }

    fn established() -> Self {
        let mut sim = Self::new();
        sim.start();
        assert_eq!(sim.nodes[0].engine.state(), EngineState::Active);
        assert_eq!(sim.nodes[1].engine.state(), EngineState::Active);
        sim
    }

    /// Advances virtual time, firing deadlines in order.
    fn advance(&mut self, by: Duration) {
        let target = self.now + by;

        loop {
            let next = (0..2)
                .flat_map(|side| {
                    self.nodes[side]
                        .deadlines
                        .iter()
                        .map(move |(id, (due, _))| (*due, side, *id))
                })
                .filter(|(due, _, _)| *due <= target)
                .min();

            let Some((due, side, id)) = next else {
                break;
            };

            self.now = due;
            self.nodes[side].deadlines.remove(&id);
            self.input(side, Input::Timeout(id));
            self.pump();
        }

        self.now = target;
    }

    fn send(&mut self, side: usize, text: &[u8]) {
        self.input(side, Input::LocalSend(Zeroizing::new(text.to_vec())));
        self.pump();
    }

    fn closed(&self, side: usize) -> Option<CloseCause> {
        self.nodes[side]
            .events
            .iter()
            .find_map(|event| match event {
                Event::Closed(cause) => Some(*cause),
                _ => None,
            })
    }

    fn count(&self, side: usize, wanted: Event) -> usize {
        self.nodes[side]
            .events
            .iter()
            .filter(|event| **event == wanted)
            .count()
    }
}

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

// ------------------------------------------------------------- handshake

#[test]
fn initial_handshake_completes_and_peers_exchange_data() {
    let mut sim = Sim::established();

    assert_eq!(sim.nodes[0].sas_words, sim.nodes[1].sas_words);
    assert!(sim.nodes[0].sas_words.is_some());

    sim.send(0, b"hello");
    sim.send(1, b"world");

    assert_eq!(sim.nodes[1].delivered, vec![b"hello".to_vec()]);
    assert_eq!(sim.nodes[0].delivered, vec![b"world".to_vec()]);
}

#[test]
fn handshake_deadlines_are_all_cancelled_once_established() {
    let sim = Sim::established();

    // Only the 24 h rekey trigger remains armed.
    assert_eq!(sim.nodes[0].engine.armed_deadlines(), 1);
    assert_eq!(sim.nodes[1].engine.armed_deadlines(), 1);
    assert!(
        sim.nodes[0]
            .deadlines
            .values()
            .all(|(_, kind)| *kind == DeadlineKind::RekeyDue)
    );
}

#[test]
fn the_24_hour_deadline_starts_and_completes_a_rekey() {
    let mut sim = Sim::established();

    sim.advance(secs(REKEY_INTERVAL_SECS));

    assert_eq!(sim.nodes[0].engine.state(), EngineState::Active);
    assert_eq!(sim.nodes[1].engine.state(), EngineState::Active);
    assert_eq!(sim.count(0, Event::RekeyCompleted), 1);
    assert_eq!(sim.count(1, Event::RekeyCompleted), 1);
    for node in &sim.nodes {
        assert!(
            node.deadlines
                .values()
                .any(|(_, kind)| *kind == DeadlineKind::RekeyDue)
        );
        assert_eq!(node.engine.armed_deadlines(), node.deadlines.len());
    }
    assert!(sim.nodes.iter().all(|node| {
        node.events
            .iter()
            .all(|event| !matches!(event, Event::Closed(_)))
    }));
}

#[test]
fn only_the_initiator_sends_before_it_hears_from_the_responder() {
    let mut sim = Sim::new();
    sim.nodes[1].blackhole = true;

    sim.input(0, Input::Start);
    sim.input(1, Input::Start);

    assert_eq!(sim.nodes[0].sent.len(), 1, "COMMIT only");
    assert!(CommitPayload::decode(&sim.nodes[0].sent[0]).is_ok());
    assert!(sim.nodes[1].sent.is_empty(), "responder waits for COMMIT");
}

#[test]
fn sas_rejection_closes_without_any_signature() {
    let mut sim = Sim::new();
    sim.nodes[0].auto_sas = Some(false);
    sim.nodes[1].auto_sas = None;

    sim.start();

    assert_eq!(sim.closed(0), Some(CloseCause::SasRejected));

    // Initiator sent COMMIT, HELLO and a CLOSE, but never AUTH.
    let types: Vec<_> = sim.nodes[0].sent.iter().map(|f| f.message_type).collect();
    assert_eq!(
        types,
        vec![
            MessageType::Handshake,
            MessageType::Handshake,
            MessageType::Close
        ]
    );
    assert_eq!(sim.nodes[0].sent.len(), 3);
}

#[test]
fn responder_that_approves_first_still_accepts_the_early_auth() {
    // Initiator approves immediately; responder's human is slower.
    let mut sim = Sim::new();
    sim.nodes[1].auto_sas = None;
    sim.start();

    assert!(sim.nodes[1].sas_words.is_some());
    assert_eq!(sim.nodes[1].engine.state(), EngineState::Handshaking);

    sim.input(1, Input::SasDecision(true));
    sim.pump();

    assert_eq!(sim.nodes[0].engine.state(), EngineState::Active);
    assert_eq!(sim.nodes[1].engine.state(), EngineState::Active);
}

// ------------------------------------------------------------- ordering

fn hello_from(identity: &IdentityKeypair, role: HelloRole) -> HelloPayload {
    HelloPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Initial,
        role,
        identity_public_key: identity.identity(),
        ephemeral_public_key: [9; 32],
        nonce: [7; 16],
        previous_session_id: None,
    }
}

#[test]
fn responder_closes_on_a_first_frame_that_is_not_a_commit() {
    for first in [
        hello_from(&IdentityKeypair::from_bytes(&[1; 32]), HelloRole::Initiator)
            .encode()
            .unwrap(),
        Frame::new(MessageType::Data, vec![0xa0]).unwrap(),
        Frame::new(MessageType::SessionConfirm, vec![0xa0]).unwrap(),
    ] {
        let mut engine = Engine::new(
            HelloRole::Responder,
            IdentityKeypair::from_bytes(&[2; 32]),
            Box::new(Seeded(1)),
        );
        engine.handle(Input::Start);

        let effects = engine.handle(Input::FrameReceived(first));

        assert_eq!(engine.state(), EngineState::Closed);
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, Effect::CloseTransport))
        );
        assert!(
            !effects.iter().any(|effect| matches!(
                effect,
                Effect::Send(frame) if frame.message_type == MessageType::Handshake
            )),
            "no HELLO may be sent for a bad first frame"
        );
    }
}

#[test]
fn responder_rejects_a_reveal_that_does_not_match_the_commitment() {
    let initiator = IdentityKeypair::from_bytes(&[1; 32]);

    let committed = hello_from(&initiator, HelloRole::Initiator);
    let commit = CommitPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Initial,
        commitment: commit_hash(&committed.encode().unwrap().payload),
        previous_session_id: None,
    }
    .encode()
    .unwrap();

    let mut other = committed;
    other.ephemeral_public_key = [10; 32];

    let mut engine = Engine::new(
        HelloRole::Responder,
        IdentityKeypair::from_bytes(&[2; 32]),
        Box::new(Seeded(1)),
    );
    engine.handle(Input::Start);

    let reply = engine.handle(Input::FrameReceived(commit));
    assert!(
        reply.iter().any(|e| matches!(e, Effect::Send(_))),
        "HELLO sent"
    );

    let effects = engine.handle(Input::FrameReceived(other.encode().unwrap()));

    assert_eq!(engine.state(), EngineState::Closed);
    assert!(
        !effects
            .iter()
            .any(|e| matches!(e, Effect::RequestSas { .. }))
    );
}

#[test]
fn replayed_auth_from_a_prior_session_is_rejected() {
    // Capture a complete handshake, then replay its initiator AUTH into a new one.
    let mut first = Sim::established();
    let old_auth = first.nodes[0]
        .sent
        .iter()
        .find(|frame| {
            frame.message_type == MessageType::Handshake
                && ruxmsg_core::handshake::HandshakePayload::decode(frame).is_ok()
        })
        .cloned()
        .unwrap();
    first.send(0, b"x");

    let mut engine = Engine::new(
        HelloRole::Responder,
        IdentityKeypair::from_bytes(&[2; 32]),
        Box::new(Seeded(99)),
    );
    let mut initiator = Engine::new(
        HelloRole::Initiator,
        IdentityKeypair::from_bytes(&[1; 32]),
        Box::new(Seeded(77)),
    );

    engine.handle(Input::Start);
    let mut to_responder: VecDeque<Frame> = VecDeque::new();
    for effect in initiator.handle(Input::Start) {
        if let Effect::Send(frame) = effect {
            to_responder.push_back(frame);
        }
    }

    // COMMIT -> HELLO(R) -> HELLO(I) -> SAS request.
    let mut to_initiator = Vec::new();
    for effect in engine.handle(Input::FrameReceived(to_responder.pop_front().unwrap())) {
        if let Effect::Send(frame) = effect {
            to_initiator.push(frame);
        }
    }
    for effect in initiator.handle(Input::FrameReceived(to_initiator.remove(0))) {
        if let Effect::Send(frame) = effect {
            to_responder.push_back(frame);
        }
    }
    engine.handle(Input::FrameReceived(to_responder.pop_front().unwrap()));
    engine.handle(Input::SasDecision(true));

    let effects = engine.handle(Input::FrameReceived(old_auth));

    assert_eq!(engine.state(), EngineState::Closed);
    assert!(
        !effects.iter().any(|e| matches!(
            e,
            Effect::Send(frame) if frame.message_type == MessageType::Handshake
        )),
        "Sig_R must not be sent for a replayed AUTH"
    );
}

fn fresh_engine(role: HelloRole, seed: u8) -> Engine {
    Engine::new(
        role,
        IdentityKeypair::from_bytes(&[seed; 32]),
        Box::new(Seeded(u64::from(seed) + 100)),
    )
}

fn commit_for(hello: &HelloPayload) -> Frame {
    CommitPayload {
        cipher_suite: 1,
        purpose: hello.purpose,
        commitment: commit_hash(&hello.encode().unwrap().payload),
        previous_session_id: hello.previous_session_id,
    }
    .encode()
    .unwrap()
}

fn sent_handshake_frames(effects: &[Effect]) -> usize {
    effects
        .iter()
        .filter(|effect| {
            matches!(effect, Effect::Send(frame) if frame.message_type == MessageType::Handshake)
        })
        .count()
}

#[test]
fn responder_closes_on_reveals_that_break_the_hello_rules() {
    let initiator = IdentityKeypair::from_bytes(&[1; 32]);
    let responder = IdentityKeypair::from_bytes(&[2; 32]);

    let wrong_role = hello_from(&initiator, HelloRole::Responder);
    // Same bytes as the commitment, but it carries the responder's own key.
    let reflected = hello_from(&responder, HelloRole::Initiator);

    for reveal in [wrong_role, reflected] {
        let mut engine = fresh_engine(HelloRole::Responder, 2);
        engine.handle(Input::Start);
        engine.handle(Input::FrameReceived(commit_for(&reveal)));

        let effects = engine.handle(Input::FrameReceived(reveal.encode().unwrap()));

        assert_eq!(engine.state(), EngineState::Closed);
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::RequestSas { .. }))
        );
    }
}

#[test]
fn responder_closes_on_a_commit_with_the_wrong_purpose() {
    let mut rekey_hello = hello_from(&IdentityKeypair::from_bytes(&[1; 32]), HelloRole::Initiator);
    rekey_hello.purpose = HandshakePurpose::Rekey;
    rekey_hello.previous_session_id = Some(SessionId::from_bytes([9; 16]));

    let mut engine = fresh_engine(HelloRole::Responder, 2);
    engine.handle(Input::Start);
    let effects = engine.handle(Input::FrameReceived(commit_for(&rekey_hello)));

    assert_eq!(engine.state(), EngineState::Closed);
    assert_eq!(
        sent_handshake_frames(&effects),
        0,
        "no HELLO for a bad COMMIT"
    );
}

#[test]
fn initiator_never_reveals_to_an_invalid_responder_hello() {
    let responder = IdentityKeypair::from_bytes(&[2; 32]);

    let wrong_role = hello_from(&responder, HelloRole::Initiator);

    let mut wrong_purpose = hello_from(&responder, HelloRole::Responder);
    wrong_purpose.purpose = HandshakePurpose::Rekey;
    wrong_purpose.previous_session_id = Some(SessionId::from_bytes([1; 16]));

    // Reflects the initiator's own identity back at it.
    let own_identity = hello_from(&IdentityKeypair::from_bytes(&[1; 32]), HelloRole::Responder);

    let replayed_commit = commit_for(&hello_from(&responder, HelloRole::Responder));

    for reply in [
        wrong_role.encode().unwrap(),
        wrong_purpose.encode().unwrap(),
        own_identity.encode().unwrap(),
        replayed_commit,
    ] {
        let mut engine = fresh_engine(HelloRole::Initiator, 1);
        let start = engine.handle(Input::Start);
        assert_eq!(sent_handshake_frames(&start), 1, "COMMIT only");

        let effects = engine.handle(Input::FrameReceived(reply));

        assert_eq!(engine.state(), EngineState::Closed);
        assert_eq!(
            sent_handshake_frames(&effects),
            0,
            "HELLO must stay unrevealed"
        );
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::RequestSas { .. }))
        );
    }
}

#[test]
fn rekey_commit_uses_the_rekey_frame_type_and_skips_sas() {
    let mut sim = Sim::established();
    sim.nodes[0].auto_sas = None;
    sim.nodes[0].sas_words = None;

    sim.input(0, Input::RequestRekey);

    let commit = sim.nodes[0].sent.last().unwrap();
    assert_eq!(commit.message_type, MessageType::Rekey);
    assert!(CommitPayload::decode(commit).is_ok());

    sim.pump();
    assert_eq!(sim.nodes[0].sas_words, None, "rekeys never ask for SAS");
}

// ------------------------------------------------------------- timeouts

#[test]
fn responder_closes_if_no_commit_arrives_within_the_frame_timeout() {
    let mut sim = Sim::new();
    sim.input(1, Input::Start);

    sim.advance(secs(14));
    assert_eq!(sim.nodes[1].engine.state(), EngineState::Handshaking);

    sim.advance(secs(1));
    assert_eq!(sim.closed(1), Some(CloseCause::Timeout));
}

#[test]
fn sas_decision_times_out_after_120_seconds() {
    let mut sim = Sim::new();
    sim.nodes[0].auto_sas = None;
    sim.nodes[1].auto_sas = None;
    sim.start();

    // The 15 s frame deadline must not fire while a human is deciding.
    sim.advance(secs(119));
    assert_eq!(sim.nodes[0].engine.state(), EngineState::Handshaking);

    sim.advance(secs(1));
    assert_eq!(sim.closed(0), Some(CloseCause::Timeout));
}

#[test]
fn total_handshake_deadline_is_180_seconds() {
    let mut sim = Sim::new();
    sim.nodes[0].auto_sas = Some(true);
    sim.nodes[1].auto_sas = None;
    // Nothing the responder sends from now on reaches the initiator, not even its CLOSE.
    sim.start();
    sim.nodes[1].blackhole = true;

    // Initiator waits for AUTH with only the total deadline armed: the 15 s
    // frame deadline must not fire while the peer may be deciding.
    sim.advance(secs(179));
    assert_eq!(sim.nodes[0].engine.state(), EngineState::Handshaking);
    assert_eq!(
        sim.closed(1),
        Some(CloseCause::Timeout),
        "responder SAS expired"
    );

    sim.advance(secs(1));
    assert_eq!(sim.closed(0), Some(CloseCause::Timeout));
}

#[test]
fn a_stale_timeout_for_a_cancelled_deadline_is_ignored() {
    let mut engine = Engine::new(
        HelloRole::Responder,
        IdentityKeypair::from_bytes(&[5; 32]),
        Box::new(Seeded(5)),
    );

    let frame_deadline = engine
        .handle(Input::Start)
        .into_iter()
        .find_map(|effect| match effect {
            Effect::SetDeadline {
                id,
                kind: DeadlineKind::HandshakeFrame,
                ..
            } => Some(id),
            _ => None,
        })
        .unwrap();

    // A valid COMMIT re-arms the frame deadline, cancelling the first one.
    let commit = CommitPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Initial,
        commitment: [0; 32],
        previous_session_id: None,
    }
    .encode()
    .unwrap();
    engine.handle(Input::FrameReceived(commit));

    assert!(engine.handle(Input::Timeout(frame_deadline)).is_empty());
    assert_eq!(engine.state(), EngineState::Handshaking);
}

// ---------------------------------------------------------------- rekey

fn rekey(sim: &mut Sim) {
    sim.input(0, Input::RequestRekey);
    sim.pump();
}

#[test]
fn rekey_replaces_the_session_without_sas_and_drains_the_old_one() {
    let mut sim = Sim::established();
    let old = sim.nodes[0].engine.active_session_id().unwrap();
    sim.nodes[0].sas_words = None;
    sim.nodes[0].auto_sas = None;

    rekey(&mut sim);

    assert_eq!(sim.nodes[0].sas_words, None, "rekeys do not use SAS");
    assert_ne!(sim.nodes[0].engine.active_session_id(), Some(old));
    assert_eq!(sim.nodes[0].engine.draining_session_id(), Some(old));
    assert_eq!(
        sim.nodes[0].engine.active_session_id(),
        sim.nodes[1].engine.active_session_id()
    );
    assert_eq!(sim.count(0, Event::RekeyCompleted), 1);
    assert_eq!(sim.count(1, Event::RekeyCompleted), 1);

    sim.send(0, b"after");
    assert_eq!(sim.nodes[1].delivered, vec![b"after".to_vec()]);

    sim.advance(secs(15));
    assert_eq!(sim.nodes[0].engine.draining_session_id(), None);
    assert_eq!(sim.nodes[1].engine.draining_session_id(), None);
}

#[test]
fn data_in_flight_under_the_old_session_is_delivered_during_the_drain() {
    let mut sim = Sim::established();

    // B encrypts under the old session but the frame is delivered after rekey.
    sim.nodes[0].blackhole = false;
    sim.input(1, Input::LocalSend(Zeroizing::new(b"late".to_vec())));
    let late = sim.queues[0].pop_front();

    rekey(&mut sim);

    if let Some(Wire::Frame(frame)) = late {
        sim.input(0, Input::FrameReceived(frame));
    }

    assert_eq!(sim.nodes[0].delivered, vec![b"late".to_vec()]);
}

#[test]
fn data_for_a_drained_session_is_rejected_without_ending_the_session() {
    let mut sim = Sim::established();

    sim.input(1, Input::LocalSend(Zeroizing::new(b"late".to_vec())));
    let late = sim.queues[0].pop_front();

    rekey(&mut sim);
    sim.advance(secs(15));

    if let Some(Wire::Frame(frame)) = late {
        sim.input(0, Input::FrameReceived(frame));
    }

    assert!(sim.nodes[0].delivered.is_empty());
    assert_eq!(sim.count(0, Event::DataRejected), 1);
    assert_eq!(sim.nodes[0].engine.state(), EngineState::Active);
}

#[test]
fn simultaneous_rekeys_resolve_to_exactly_one_candidate() {
    let mut sim = Sim::established();

    // Both sides commit before either sees the other's COMMIT.
    sim.input(0, Input::RequestRekey);
    sim.input(1, Input::RequestRekey);
    sim.pump();

    assert_eq!(sim.nodes[0].engine.state(), EngineState::Active);
    assert_eq!(sim.nodes[1].engine.state(), EngineState::Active);
    assert_eq!(
        sim.nodes[0].engine.active_session_id(),
        sim.nodes[1].engine.active_session_id()
    );
    assert_eq!(sim.count(0, Event::RekeyCompleted), 1);
    assert_eq!(sim.count(1, Event::RekeyCompleted), 1);
    assert_eq!(sim.count(0, Event::RekeyFailed(RekeyFailure::Invalid)), 0);

    sim.send(1, b"ok");
    assert_eq!(sim.nodes[0].delivered, vec![b"ok".to_vec()]);
}

#[test]
fn greater_identity_key_stays_initiator_in_glare() {
    let mut sim = Sim::established();
    let a = IdentityKeypair::from_bytes(&[1; 32]).identity();
    let b = IdentityKeypair::from_bytes(&[2; 32]).identity();
    let winner = if a.as_bytes() > b.as_bytes() { 0 } else { 1 };

    sim.input(0, Input::RequestRekey);
    sim.input(1, Input::RequestRekey);

    // The loser's COMMIT is ignored by the winner: no HELLO comes from the winner
    // in answer to it, but the loser answers the winner's COMMIT.
    sim.pump();

    let winner_hellos = sim.nodes[winner]
        .sent
        .iter()
        .filter(|frame| {
            frame.message_type == MessageType::Rekey && HelloPayload::decode(frame).is_ok()
        })
        .count();
    let loser_hellos = sim.nodes[1 - winner]
        .sent
        .iter()
        .filter(|frame| {
            frame.message_type == MessageType::Rekey
                && HelloPayload::decode(frame).is_ok_and(|hello| hello.role == HelloRole::Responder)
        })
        .count();

    // Winner sends only its initiator HELLO (reveal); loser sends the responder HELLO.
    assert_eq!(winner_hellos, 1);
    assert_eq!(loser_hellos, 1);
}

#[test]
fn rekey_with_the_wrong_previous_session_is_discarded_and_the_session_survives() {
    let mut sim = Sim::established();

    let stale = CommitPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Rekey,
        commitment: [0; 32],
        previous_session_id: Some(SessionId::from_bytes([0xee; 16])),
    }
    .encode()
    .unwrap();

    for _ in 0..6 {
        sim.input(1, Input::FrameReceived(stale.clone()));
    }

    assert_eq!(sim.count(1, Event::RekeyFailed(RekeyFailure::Repeated)), 1);
    assert_eq!(sim.nodes[1].engine.state(), EngineState::Active);
    assert!(
        sim.nodes[1]
            .sent
            .iter()
            .all(|f| f.message_type != MessageType::Rekey)
    );

    sim.send(0, b"still works");
    assert_eq!(sim.nodes[1].delivered, vec![b"still works".to_vec()]);
}

#[test]
fn malformed_rekey_commit_does_not_close_the_active_session() {
    let mut sim = Sim::established();
    let malformed = Frame::new(MessageType::Rekey, vec![0xa0]).unwrap();

    sim.input(1, Input::FrameReceived(malformed));

    assert_eq!(sim.nodes[1].engine.state(), EngineState::Active);
    assert_eq!(sim.closed(1), None);
    assert_eq!(sim.count(1, Event::RekeyFailed(RekeyFailure::Repeated)), 0);
}

#[test]
fn rekey_from_a_changed_identity_is_discarded_and_the_session_survives() {
    let mut sim = Sim::established();
    let active = sim.nodes[1].engine.active_session_id().unwrap();

    // A third party commits for the real previous session ID, then reveals its own HELLO.
    let intruder = IdentityKeypair::from_bytes(&[3; 32]);
    let hello = HelloPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Rekey,
        role: HelloRole::Initiator,
        identity_public_key: intruder.identity(),
        ephemeral_public_key: [9; 32],
        nonce: [7; 16],
        previous_session_id: Some(active),
    };
    let hello_frame = hello.encode().unwrap();
    let commit = CommitPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Rekey,
        commitment: commit_hash(&hello_frame.payload),
        previous_session_id: Some(active),
    }
    .encode()
    .unwrap();

    sim.input(1, Input::FrameReceived(commit));
    sim.input(1, Input::FrameReceived(hello_frame));

    assert_eq!(
        sim.count(1, Event::RekeyFailed(RekeyFailure::IdentityMismatch)),
        1
    );
    assert_eq!(sim.nodes[1].engine.state(), EngineState::Active);
    assert!(sim.nodes[1].engine.draining_session_id().is_none());

    sim.send(0, b"unaffected");
    assert_eq!(sim.nodes[1].delivered, vec![b"unaffected".to_vec()]);
}

#[test]
fn a_timed_out_rekey_aborts_only_the_candidate_and_retries_later() {
    let mut sim = Sim::established();

    sim.nodes[1].blackhole = true;
    sim.input(0, Input::RequestRekey);
    // B receives COMMIT but its HELLO never reaches A.
    sim.pump();

    assert_eq!(sim.nodes[0].engine.state(), EngineState::Rekeying);

    // Data keeps flowing in both directions while the candidate is pending.
    sim.send(0, b"during");
    assert_eq!(sim.nodes[1].delivered, vec![b"during".to_vec()]);

    sim.advance(secs(15));

    assert_eq!(sim.count(0, Event::RekeyFailed(RekeyFailure::Timeout)), 1);
    assert_eq!(sim.nodes[0].engine.state(), EngineState::Active);
    assert_eq!(
        sim.closed(0),
        None,
        "a rekey timeout must not close the session"
    );

    let late_hello = sim.nodes[1]
        .sent
        .iter()
        .find(|frame| {
            frame.message_type == MessageType::Rekey
                && HelloPayload::decode(frame).is_ok_and(|hello| hello.role == HelloRole::Responder)
        })
        .expect("responder HELLO was sent")
        .clone();
    sim.input(0, Input::FrameReceived(late_hello));
    assert_eq!(sim.nodes[0].engine.state(), EngineState::Active);
    assert_eq!(sim.closed(0), None);

    // Retry only after the back-off (30 s), via the rekey timer.
    let commits_before = count_commits(&sim.nodes[0]);
    sim.nodes[1].blackhole = false;
    sim.advance(secs(29));
    assert_eq!(count_commits(&sim.nodes[0]), commits_before);

    sim.advance(secs(2));
    assert!(count_commits(&sim.nodes[0]) > commits_before);
}

fn count_commits(node: &Node) -> usize {
    node.sent
        .iter()
        .filter(|f| f.message_type == MessageType::Rekey && CommitPayload::decode(f).is_ok())
        .count()
}

#[test]
fn stray_session_confirm_outside_a_rekey_ends_the_session() {
    let mut sim = Sim::established();

    sim.input(
        1,
        Input::FrameReceived(Frame::new(MessageType::SessionConfirm, vec![0xa0]).unwrap()),
    );

    assert_eq!(sim.closed(1), Some(CloseCause::ProtocolError));
}

// ----------------------------------------------------------------- CLOSE

#[test]
fn close_for_an_unknown_session_is_ignored() {
    let mut sim = Sim::established();

    let forged = ClosePayload {
        session_id: Some(SessionId::from_bytes([0x55; 16])),
        reason: CloseReason::Normal,
        detail: None,
    }
    .encode()
    .unwrap();

    sim.input(1, Input::FrameReceived(forged));

    assert_eq!(sim.nodes[1].engine.state(), EngineState::Active);
    assert_eq!(sim.closed(1), None);
}

#[test]
fn close_for_the_active_session_ends_it_and_is_marked_unauthenticated() {
    let mut sim = Sim::established();
    let id = sim.nodes[1].engine.active_session_id().unwrap();

    let close = ClosePayload {
        session_id: Some(id),
        reason: CloseReason::Normal,
        detail: None,
    }
    .encode()
    .unwrap();

    sim.input(1, Input::FrameReceived(close));

    assert_eq!(
        sim.closed(1),
        Some(CloseCause::PeerUnauthenticated(CloseReason::Normal))
    );
    assert!(
        !sim.nodes[1]
            .sent
            .iter()
            .any(|f| f.message_type == MessageType::Close)
    );
}

#[test]
fn close_naming_the_draining_session_closes_only_that_session() {
    let mut sim = Sim::established();
    let old = sim.nodes[1].engine.active_session_id().unwrap();

    rekey(&mut sim);

    let close = ClosePayload {
        session_id: Some(old),
        reason: CloseReason::Normal,
        detail: None,
    }
    .encode()
    .unwrap();

    sim.input(1, Input::FrameReceived(close));

    assert_eq!(sim.nodes[1].engine.state(), EngineState::Active);
    assert_eq!(sim.nodes[1].engine.draining_session_id(), None);
}

#[test]
fn local_close_sends_close_then_closes_the_transport_in_order() {
    let mut sim = Sim::established();
    let effects = sim.nodes[0]
        .engine
        .handle(Input::LocalClose(CloseReason::Normal));

    let order: Vec<&str> = effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Send(_) => Some("send"),
            Effect::Notify(Event::Closed(_)) => Some("closed"),
            Effect::CloseTransport => Some("close"),
            _ => None,
        })
        .collect();

    assert_eq!(order, vec!["send", "closed", "close"]);
    assert_eq!(sim.nodes[0].engine.state(), EngineState::Closed);
    assert!(sim.nodes[0].engine.handle(Input::RequestRekey).is_empty());
}

#[test]
fn transport_loss_destroys_the_session() {
    let mut sim = Sim::established();

    sim.input(0, Input::TransportClosed);

    assert_eq!(sim.closed(0), Some(CloseCause::TransportLost));
    assert_eq!(sim.nodes[0].engine.active_session_id(), None);
}

// ------------------------------------------------------------------ DATA

#[test]
fn oversized_content_is_rejected_without_touching_the_session() {
    let mut sim = Sim::established();

    sim.send(0, &vec![0; 65_537]);

    assert!(
        sim.nodes[0]
            .events
            .contains(&Event::SendRejected(SendRejection::TooLarge))
    );

    sim.send(0, b"fine");
    assert_eq!(sim.nodes[1].delivered, vec![b"fine".to_vec()]);
}

#[test]
fn sending_before_the_session_is_active_is_rejected() {
    let mut sim = Sim::new();
    sim.input(0, Input::Start);
    sim.input(0, Input::LocalSend(Zeroizing::new(b"early".to_vec())));

    assert!(
        sim.nodes[0]
            .events
            .contains(&Event::SendRejected(SendRejection::NotActive))
    );
}

#[test]
fn data_before_active_ends_the_handshake() {
    let mut sim = Sim::new();
    sim.input(1, Input::Start);
    sim.input(
        1,
        Input::FrameReceived(Frame::new(MessageType::Data, vec![0xa0]).unwrap()),
    );

    assert_eq!(sim.closed(1), Some(CloseCause::ProtocolError));
}

#[test]
fn replayed_data_is_rejected_without_ending_the_session() {
    let mut sim = Sim::established();

    sim.input(0, Input::LocalSend(Zeroizing::new(b"once".to_vec())));
    let Some(Wire::Frame(frame)) = sim.queues[1].pop_front() else {
        panic!("expected a DATA frame");
    };

    sim.input(1, Input::FrameReceived(frame.clone()));
    sim.input(1, Input::FrameReceived(frame));

    assert_eq!(sim.nodes[1].delivered, vec![b"once".to_vec()]);
    assert_eq!(sim.count(1, Event::DataRejected), 1);
    assert_eq!(sim.nodes[1].engine.state(), EngineState::Active);
}

// -------------------------------------------------------------- hygiene

#[test]
fn debug_output_never_contains_message_content() {
    let secret = b"canary-plaintext-7f3a".to_vec();

    let input = format!("{:?}", Input::LocalSend(Zeroizing::new(secret.clone())));
    let effect = format!("{:?}", Effect::Deliver(Zeroizing::new(secret)));

    assert!(!input.contains("canary"));
    assert!(!effect.contains("canary"));
}

#[test]
fn the_engine_module_has_no_clock_socket_thread_or_runtime() {
    let source = include_str!("../src/machine.rs");

    for forbidden in [
        "Instant",
        "SystemTime",
        "std::net",
        "std::thread",
        "std::sync::Mutex",
        "std::sync::RwLock",
        "std::sync::Condvar",
        "tokio",
        "TcpStream",
        "println!",
        "eprintln!",
        "dbg!",
    ] {
        assert!(
            !source.contains(forbidden),
            "engine source mentions {forbidden}"
        );
    }
}

#[test]
fn the_message_count_trigger_starts_a_rekey() {
    let mut sim = Sim::established();
    sim.nodes[0].engine.set_rekey_message_limit(5);
    sim.nodes[1].engine.set_rekey_message_limit(5);
    let before = sim.nodes[0].engine.active_session_id();

    for _ in 0..5 {
        sim.send(0, b"x");
    }

    assert_ne!(sim.nodes[0].engine.active_session_id(), before);
    assert_eq!(
        sim.nodes[0].engine.active_session_id(),
        sim.nodes[1].engine.active_session_id()
    );
    assert_eq!(sim.count(0, Event::RekeyCompleted), 1);

    // The counter restarts with the new session.
    sim.send(0, b"y");
    assert_eq!(sim.count(0, Event::RekeyCompleted), 1);
}

// ------------------------------------------------------------- robustness

#[test]
fn random_inputs_never_panic_and_stay_bounded() {
    let mut rng = Seeded(0xdead_beef_cafe_f00d);

    for round in 0..200u32 {
        let role = if round % 2 == 0 {
            HelloRole::Initiator
        } else {
            HelloRole::Responder
        };
        let mut engine = Engine::new(
            role,
            IdentityKeypair::from_bytes(&[4; 32]),
            Box::new(Seeded(u64::from(round) + 1)),
        );
        let mut armed: Vec<DeadlineId> = Vec::new();
        engine.handle(Input::Start);

        for _ in 0..40 {
            let mut pick = [0u8; 3];
            rng.fill(&mut pick);

            let input = match pick[0] % 7 {
                0 => {
                    let mut payload = vec![0u8; usize::from(pick[2] % 64)];
                    rng.fill(&mut payload);
                    let kind = match pick[1] % 5 {
                        0 => MessageType::Handshake,
                        1 => MessageType::SessionConfirm,
                        2 => MessageType::Data,
                        3 => MessageType::Rekey,
                        _ => MessageType::Close,
                    };
                    Input::FrameReceived(Frame::new(kind, payload).unwrap())
                }
                1 => Input::SasDecision(pick[1] % 2 == 0),
                2 => Input::LocalSend(Zeroizing::new(vec![pick[1]; 8])),
                3 => Input::RequestRekey,
                4 if !armed.is_empty() => Input::Timeout(armed[usize::from(pick[1]) % armed.len()]),
                5 => Input::LocalClose(CloseReason::Normal),
                _ => Input::Start,
            };

            let effects = engine.handle(input);
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
    }
}

#[test]
fn the_core_crate_depends_on_no_runtime_terminal_or_os_store() {
    let manifest = include_str!("../Cargo.toml");

    for forbidden in [
        "tokio",
        "keyring",
        "ratatui",
        "crossterm",
        "clap",
        "futures",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "core manifest mentions {forbidden}"
        );
    }
}
