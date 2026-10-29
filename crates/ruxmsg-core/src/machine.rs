//! Sans-IO protocol engine.
//!
//! The engine is a deterministic state machine: [`Engine::handle`] consumes one
//! [`Input`] and returns the [`Effect`]s the driver must perform, in order.
//! It owns no clock, socket, thread, runtime handle or UI callback.
//!
//! - Time enters only as [`Input::Timeout`]. The engine asks for a deadline with
//!   [`Effect::SetDeadline`] and withdraws it with [`Effect::CancelDeadline`].
//! - Human decisions enter as [`Input::SasDecision`]; the question leaves as
//!   [`Effect::RequestSas`].
//! - Randomness comes from the injected [`Entropy`] source.
//!
//! Effects from one input must be applied in the order returned. Any `Send`
//! that precedes `CloseTransport` must be written before closing. A driver that
//! cannot finish writing a frame must treat the connection as lost and feed
//! [`Input::TransportClosed`].

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::close::{ClosePayload, CloseReason};
use crate::crypto::{
    EphemeralKeypair, IdentityKeypair, SessionKeys, commit_hash, confirmation_mac, sas_words,
    transcript_hash,
};
use crate::data::{DataReceiver, DataSender};
use crate::encoding::Transcript;
use crate::error::{Error, Result};
use crate::handshake::{
    CommitPayload, HandshakePayload, HandshakePurpose, HelloPayload, HelloRole,
    SessionConfirmPayload, local_identity_wins_rekey_glare, transcript_from_hellos,
    verify_handshake_for_role,
};
use crate::identity::PeerIdentity;
use crate::protocol::{
    DirectionId, HANDSHAKE_FRAME_TIMEOUT_SECS, HANDSHAKE_TOTAL_TIMEOUT_SECS, MAX_CONTENT,
    MessageType, REKEY_DRAIN_TIMEOUT_SECS, REKEY_INTERVAL_SECS, REKEY_MESSAGE_LIMIT,
    REKEY_RETRY_SECS, SAS_DECISION_TIMEOUT_SECS, SessionId,
};
use crate::wire::Frame;

const LATE_REKEY_FRAME_GRACE: u8 = 8;
const REKEY_REJECTION_WARNING_THRESHOLD: u8 = 3;

/// Source of randomness for ephemeral keys and nonces.
pub trait Entropy {
    fn fill(&mut self, dest: &mut [u8]);
}

/// Operating-system CSPRNG.
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest);
    }
}

/// Opaque handle for one armed deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeadlineId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineKind {
    /// Waiting for the next handshake frame (§11, 15 s).
    HandshakeFrame,
    /// Waiting for the local human SAS decision (§11, 120 s).
    SasDecision,
    /// Whole-handshake budget (§11, 180 s).
    HandshakeTotal,
    /// Time- or retry-driven rekey trigger.
    RekeyDue,
    /// Superseded session leaves DRAINING.
    Drain,
}

pub enum Input {
    /// Begin the connection. The initiator sends COMMIT; the responder waits.
    Start,
    FrameReceived(Frame),
    SasDecision(bool),
    LocalSend(Zeroizing<Vec<u8>>),
    LocalClose(CloseReason),
    RequestRekey,
    Timeout(DeadlineId),
    TransportClosed,
    /// The driver could not decode a frame. `respond` is false for an
    /// unsupported version, which must be closed without a protocol response.
    Malformed {
        respond: bool,
    },
}

pub enum Effect {
    Send(Frame),
    SetDeadline {
        id: DeadlineId,
        kind: DeadlineKind,
        after: Duration,
    },
    CancelDeadline(DeadlineId),
    RequestSas {
        words: [&'static str; 3],
        peer_identity: PeerIdentity,
    },
    Deliver(Zeroizing<Vec<u8>>),
    Notify(Event),
    CloseTransport,
}

// Message bodies and frame bytes must never reach logs through `{:?}`.
impl fmt::Debug for Input {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Start => "Input::Start",
            Self::FrameReceived(_) => "Input::FrameReceived",
            Self::SasDecision(_) => "Input::SasDecision",
            Self::LocalSend(_) => "Input::LocalSend",
            Self::LocalClose(_) => "Input::LocalClose",
            Self::RequestRekey => "Input::RequestRekey",
            Self::Timeout(_) => "Input::Timeout",
            Self::TransportClosed => "Input::TransportClosed",
            Self::Malformed { .. } => "Input::Malformed",
        })
    }
}

impl fmt::Debug for Effect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Send(_) => "Effect::Send",
            Self::SetDeadline { .. } => "Effect::SetDeadline",
            Self::CancelDeadline(_) => "Effect::CancelDeadline",
            Self::RequestSas { .. } => "Effect::RequestSas",
            Self::Deliver(_) => "Effect::Deliver",
            Self::Notify(_) => "Effect::Notify",
            Self::CloseTransport => "Effect::CloseTransport",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Established {
        peer_identity: PeerIdentity,
    },
    RekeyStarted,
    RekeyCompleted,
    RekeyFailed(RekeyFailure),
    /// A DATA frame was dropped without ending the session.
    DataRejected,
    SendRejected(SendRejection),
    Closed(CloseCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyFailure {
    Timeout,
    IdentityMismatch,
    Invalid,
    Repeated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendRejection {
    NotActive,
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCause {
    Local,
    /// Peer CLOSE. Unauthenticated (D-017): never present as proof of intent.
    PeerUnauthenticated(CloseReason),
    TransportLost,
    ProtocolError,
    AuthenticationFailure,
    SasRejected,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    Idle,
    Handshaking,
    Active,
    Rekeying,
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Handshaking,
    Established,
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Hello,
    Reveal,
    Sas,
    AuthResp,
    AuthInit,
    ConfirmResp,
    ConfirmInit,
}

struct Session {
    id: SessionId,
    peer: PeerIdentity,
    sender: DataSender,
    receiver: DataReceiver,
}

impl Session {
    fn new(keys: &SessionKeys, role: HelloRole, peer: PeerIdentity) -> Self {
        let (send_dir, send_key, recv_dir, recv_key) = match role {
            HelloRole::Initiator => (
                DirectionId::InitiatorToResponder,
                keys.initiator_to_responder,
                DirectionId::ResponderToInitiator,
                keys.responder_to_initiator,
            ),
            HelloRole::Responder => (
                DirectionId::ResponderToInitiator,
                keys.responder_to_initiator,
                DirectionId::InitiatorToResponder,
                keys.initiator_to_responder,
            ),
        };

        Self {
            id: keys.session_id,
            peer,
            sender: DataSender::new(keys.session_id, send_dir, send_key),
            receiver: DataReceiver::new(keys.session_id, recv_dir, recv_key),
        }
    }
}

struct Run {
    purpose: HandshakePurpose,
    role: HelloRole,
    previous: Option<SessionId>,
    ephemeral: EphemeralKeypair,
    local_hello: HelloPayload,
    local_hello_frame: Option<Frame>,
    commit: Option<CommitPayload>,
    step: Step,
    remote_identity: Option<PeerIdentity>,
    shared: Option<Zeroizing<[u8; 32]>>,
    transcript: Option<Transcript>,
    hash: Option<[u8; 32]>,
    keys: Option<SessionKeys>,
    /// The only frame that may legitimately arrive during the local SAS wait:
    /// the initiator's AUTH, sent as soon as its user approved.
    early: Option<Frame>,
}

struct Candidate {
    keys: SessionKeys,
    peer: PeerIdentity,
    role: HelloRole,
}

pub struct Engine {
    role: HelloRole,
    identity: Arc<IdentityKeypair>,
    entropy: Box<dyn Entropy + Send>,
    phase: Phase,
    run: Option<Run>,
    active: Option<Session>,
    draining: Option<Session>,
    deadlines: Vec<(DeadlineId, DeadlineKind)>,
    next_deadline: u64,
    messages: u64,
    rekey_message_limit: u64,
    rekey_blocked: bool,
    late_rekey_frames: u8,
    consecutive_rekey_rejections: u8,
}

impl Engine {
    /// `role` is the transport role: the dialing side is the initiator.
    pub fn new(
        role: HelloRole,
        identity: IdentityKeypair,
        entropy: Box<dyn Entropy + Send>,
    ) -> Self {
        Self::with_shared_identity(role, Arc::new(identity), entropy)
    }

    /// Creates an engine sharing one identity seed with other engines.
    pub fn with_shared_identity(
        role: HelloRole,
        identity: Arc<IdentityKeypair>,
        entropy: Box<dyn Entropy + Send>,
    ) -> Self {
        Self {
            role,
            identity,
            entropy,
            phase: Phase::Idle,
            run: None,
            active: None,
            draining: None,
            deadlines: Vec::new(),
            next_deadline: 0,
            messages: 0,
            rekey_message_limit: REKEY_MESSAGE_LIMIT,
            rekey_blocked: false,
            late_rekey_frames: 0,
            consecutive_rekey_rejections: 0,
        }
    }

    /// Lowers the message-count rekey trigger. For tests and constrained links;
    /// the default is the spec value.
    pub fn set_rekey_message_limit(&mut self, limit: u64) {
        self.rekey_message_limit = limit.max(1);
    }

    pub fn state(&self) -> EngineState {
        match self.phase {
            Phase::Idle => EngineState::Idle,
            Phase::Handshaking => EngineState::Handshaking,
            Phase::Established if self.run.is_some() => EngineState::Rekeying,
            Phase::Established => EngineState::Active,
            Phase::Closed => EngineState::Closed,
        }
    }

    pub fn peer_identity(&self) -> Option<PeerIdentity> {
        self.active.as_ref().map(|session| session.peer)
    }

    pub fn active_session_id(&self) -> Option<SessionId> {
        self.active.as_ref().map(|session| session.id)
    }

    pub fn draining_session_id(&self) -> Option<SessionId> {
        self.draining.as_ref().map(|session| session.id)
    }

    /// Number of deadlines currently armed. Always small and bounded.
    pub fn armed_deadlines(&self) -> usize {
        self.deadlines.len()
    }

    pub fn handle(&mut self, input: Input) -> Vec<Effect> {
        let mut out = Vec::new();

        if self.phase == Phase::Closed {
            return out;
        }

        match input {
            Input::Start => self.start(&mut out),
            Input::FrameReceived(frame) => self.on_frame(frame, &mut out),
            Input::SasDecision(approved) => self.on_sas(approved, &mut out),
            Input::LocalSend(content) => self.on_send(&content, &mut out),
            Input::LocalClose(reason) => {
                self.terminate(CloseCause::Local, Some(reason), &mut out);
            }
            Input::RequestRekey => self.begin_rekey(&mut out),
            Input::Timeout(id) => self.on_timeout(id, &mut out),
            Input::TransportClosed => self.terminate(CloseCause::TransportLost, None, &mut out),
            Input::Malformed { respond } => self.terminate(
                CloseCause::ProtocolError,
                respond.then_some(CloseReason::ProtocolError),
                &mut out,
            ),
        }

        out
    }

    // ------------------------------------------------------------ deadlines

    fn arm(&mut self, kind: DeadlineKind, after: Duration, out: &mut Vec<Effect>) {
        self.cancel(kind, out);

        let id = DeadlineId(self.next_deadline);
        self.next_deadline += 1;
        self.deadlines.push((id, kind));
        out.push(Effect::SetDeadline { id, kind, after });
    }

    fn cancel(&mut self, kind: DeadlineKind, out: &mut Vec<Effect>) {
        self.deadlines.retain(|(id, existing)| {
            if *existing == kind {
                out.push(Effect::CancelDeadline(*id));
                false
            } else {
                true
            }
        });
    }

    fn cancel_all(&mut self, out: &mut Vec<Effect>) {
        for (id, _) in self.deadlines.drain(..) {
            out.push(Effect::CancelDeadline(id));
        }
    }

    /// Per-frame deadline policy. During an initial handshake the peer may be
    /// waiting on a human for up to the SAS timeout, so frames that follow the
    /// SAS point are bounded only by the total handshake deadline.
    fn rearm_frame_deadline(
        &mut self,
        purpose: HandshakePurpose,
        step: Step,
        out: &mut Vec<Effect>,
    ) {
        self.cancel(DeadlineKind::HandshakeFrame, out);

        let bounded = match purpose {
            HandshakePurpose::Rekey => true,
            HandshakePurpose::Initial => matches!(
                step,
                Step::Hello | Step::Reveal | Step::ConfirmResp | Step::ConfirmInit
            ),
        };

        if bounded {
            self.arm(
                DeadlineKind::HandshakeFrame,
                Duration::from_secs(HANDSHAKE_FRAME_TIMEOUT_SECS),
                out,
            );
        }
    }

    fn on_timeout(&mut self, id: DeadlineId, out: &mut Vec<Effect>) {
        let Some(position) = self.deadlines.iter().position(|(armed, _)| *armed == id) else {
            // Stale: it was cancelled or replaced after the driver queued it.
            return;
        };

        let (_, kind) = self.deadlines.remove(position);

        match kind {
            DeadlineKind::HandshakeFrame | DeadlineKind::HandshakeTotal => {
                if self.phase == Phase::Handshaking {
                    self.terminate(CloseCause::Timeout, Some(CloseReason::ResourceLimit), out);
                } else if self.run.is_some() {
                    self.fail_rekey(&Error::TransportTimeout, out);
                }
            }
            DeadlineKind::SasDecision => {
                self.terminate(
                    CloseCause::Timeout,
                    Some(CloseReason::AuthenticationFailure),
                    out,
                );
            }
            DeadlineKind::RekeyDue => {
                self.rekey_blocked = false;
                self.begin_rekey(out);
            }
            DeadlineKind::Drain => {
                self.draining = None;
            }
        }
    }

    // ---------------------------------------------------------------- start

    fn start(&mut self, out: &mut Vec<Effect>) {
        if self.phase != Phase::Idle {
            return;
        }

        self.phase = Phase::Handshaking;

        self.arm(
            DeadlineKind::HandshakeTotal,
            Duration::from_secs(HANDSHAKE_TOTAL_TIMEOUT_SECS),
            out,
        );

        if self.role == HelloRole::Initiator {
            if let Err(error) = self.start_initiator_run(HandshakePurpose::Initial, None, out) {
                self.fail_initial(&error, out);
                return;
            }
            self.rearm_frame_deadline(HandshakePurpose::Initial, Step::Hello, out);
        } else {
            self.arm(
                DeadlineKind::HandshakeFrame,
                Duration::from_secs(HANDSHAKE_FRAME_TIMEOUT_SECS),
                out,
            );
        }
    }

    fn fresh_keys(&mut self) -> (EphemeralKeypair, [u8; 16]) {
        let mut secret = Zeroizing::new([0u8; 32]);
        self.entropy.fill(secret.as_mut());

        let mut nonce = [0u8; 16];
        self.entropy.fill(&mut nonce);

        (EphemeralKeypair::from_bytes(&secret), nonce)
    }

    fn start_initiator_run(
        &mut self,
        purpose: HandshakePurpose,
        previous: Option<SessionId>,
        out: &mut Vec<Effect>,
    ) -> Result<()> {
        let (ephemeral, nonce) = self.fresh_keys();

        let local_hello = HelloPayload {
            cipher_suite: 1,
            purpose,
            role: HelloRole::Initiator,
            identity_public_key: self.identity.identity(),
            ephemeral_public_key: ephemeral.public_key(),
            nonce,
            previous_session_id: previous,
        };

        // The commitment binds these exact payload bytes, which are revealed
        // unchanged later.
        let hello_frame = local_hello.encode()?;

        let commit = CommitPayload {
            cipher_suite: 1,
            purpose,
            commitment: commit_hash(&hello_frame.payload),
            previous_session_id: previous,
        };

        out.push(Effect::Send(commit.encode()?));

        self.run = Some(Run {
            purpose,
            role: HelloRole::Initiator,
            previous,
            ephemeral,
            local_hello,
            local_hello_frame: Some(hello_frame),
            commit: None,
            step: Step::Hello,
            remote_identity: None,
            shared: None,
            transcript: None,
            hash: None,
            keys: None,
            early: None,
        });

        Ok(())
    }

    fn start_responder_run(&mut self, commit: CommitPayload, out: &mut Vec<Effect>) -> Result<()> {
        let (ephemeral, nonce) = self.fresh_keys();

        let local_hello = HelloPayload {
            cipher_suite: commit.cipher_suite,
            purpose: commit.purpose,
            role: HelloRole::Responder,
            identity_public_key: self.identity.identity(),
            ephemeral_public_key: ephemeral.public_key(),
            nonce,
            previous_session_id: commit.previous_session_id,
        };

        out.push(Effect::Send(local_hello.encode()?));

        let purpose = commit.purpose;

        self.run = Some(Run {
            purpose,
            role: HelloRole::Responder,
            previous: commit.previous_session_id,
            ephemeral,
            local_hello,
            local_hello_frame: None,
            commit: Some(commit),
            step: Step::Reveal,
            remote_identity: None,
            shared: None,
            transcript: None,
            hash: None,
            keys: None,
            early: None,
        });

        if purpose == HandshakePurpose::Rekey {
            self.arm(
                DeadlineKind::HandshakeTotal,
                Duration::from_secs(HANDSHAKE_TOTAL_TIMEOUT_SECS),
                out,
            );
            out.push(Effect::Notify(Event::RekeyStarted));
        }

        self.rearm_frame_deadline(purpose, Step::Reveal, out);

        Ok(())
    }

    // --------------------------------------------------------------- frames

    fn on_frame(&mut self, frame: Frame, out: &mut Vec<Effect>) {
        match self.phase {
            Phase::Idle | Phase::Closed => {
                self.terminate(
                    CloseCause::ProtocolError,
                    Some(CloseReason::ProtocolError),
                    out,
                );
            }
            Phase::Handshaking => self.on_frame_handshaking(frame, out),
            Phase::Established => match frame.message_type {
                MessageType::Data => self.on_data(&frame, out),
                MessageType::Close => self.on_close_frame(&frame, out),
                MessageType::Rekey | MessageType::SessionConfirm => self.on_rekey_frame(frame, out),
                MessageType::Handshake => self.terminate(
                    CloseCause::ProtocolError,
                    Some(CloseReason::ProtocolError),
                    out,
                ),
            },
        }
    }

    fn on_frame_handshaking(&mut self, frame: Frame, out: &mut Vec<Effect>) {
        if frame.message_type == MessageType::Close {
            self.on_close_frame(&frame, out);
            return;
        }

        let result = if self.run.is_none() {
            self.accept_first_commit(&frame, out).map(|()| None)
        } else {
            self.drive_run(frame, out)
        };

        match result {
            Ok(Some(candidate)) => self.complete_initial(candidate, out),
            Ok(None) => {}
            Err(error) => self.fail_initial(&error, out),
        }
    }

    fn accept_first_commit(&mut self, frame: &Frame, out: &mut Vec<Effect>) -> Result<()> {
        let commit = CommitPayload::decode(frame)?;

        if commit.cipher_suite != 1
            || commit.purpose != HandshakePurpose::Initial
            || commit.previous_session_id.is_some()
        {
            return Err(Error::InvalidHandshake);
        }

        self.start_responder_run(commit, out)
    }

    fn drive_run(&mut self, frame: Frame, out: &mut Vec<Effect>) -> Result<Option<Candidate>> {
        let mut run = self.run.take().ok_or(Error::InvalidStateTransition)?;

        match self.step_run(&mut run, frame, out) {
            Ok(Some(candidate)) => Ok(Some(candidate)),
            Ok(None) => {
                self.run = Some(run);
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn check_remote_hello(
        &self,
        run: &Run,
        remote: &HelloPayload,
        expected_role: HelloRole,
    ) -> Result<()> {
        if remote.role != expected_role
            || remote.cipher_suite != run.local_hello.cipher_suite
            || remote.purpose != run.purpose
            || remote.previous_session_id != run.previous
            || remote.identity_public_key == run.local_hello.identity_public_key
            || remote.ephemeral_public_key == run.local_hello.ephemeral_public_key
        {
            return Err(Error::InvalidHandshake);
        }

        if run.purpose == HandshakePurpose::Rekey {
            let peer = self
                .active
                .as_ref()
                .map(|session| session.peer)
                .ok_or(Error::InvalidStateTransition)?;

            if remote.identity_public_key != peer {
                return Err(Error::IdentityMismatch);
            }
        }

        Ok(())
    }

    fn step_run(
        &mut self,
        run: &mut Run,
        frame: Frame,
        out: &mut Vec<Effect>,
    ) -> Result<Option<Candidate>> {
        match run.step {
            Step::Hello => {
                let remote = HelloPayload::decode(&frame)?;
                self.check_remote_hello(run, &remote, HelloRole::Responder)?;

                let reveal = run
                    .local_hello_frame
                    .take()
                    .ok_or(Error::InvalidStateTransition)?;

                out.push(Effect::Send(reveal));

                self.after_hellos(run, &remote, out)
            }

            Step::Reveal => {
                let remote = HelloPayload::decode(&frame)?;
                self.check_remote_hello(run, &remote, HelloRole::Initiator)?;

                let commit = run.commit.as_ref().ok_or(Error::InvalidStateTransition)?;
                let expected = commit_hash(&frame.payload);

                if expected
                    .as_slice()
                    .ct_eq(commit.commitment.as_slice())
                    .unwrap_u8()
                    != 1
                {
                    return Err(Error::InvalidHandshake);
                }

                self.after_hellos(run, &remote, out)
            }

            Step::Sas => {
                if run.role == HelloRole::Responder
                    && run.early.is_none()
                    && frame.message_type == MessageType::Handshake
                {
                    run.early = Some(frame);
                    Ok(None)
                } else {
                    Err(Error::InvalidStateTransition)
                }
            }

            Step::AuthResp => {
                let auth = HandshakePayload::decode(&frame)?;

                if auth.stage != 1 || auth.responder_signature.is_none() {
                    return Err(Error::InvalidHandshake);
                }

                let (keys, hash) = Self::verify_auth(run, &auth)?;

                let confirm = SessionConfirmPayload {
                    session_id: keys.session_id,
                    role: HelloRole::Initiator,
                    confirmation: confirmation_mac(&keys.confirmation_key, &hash, true),
                };

                out.push(Effect::Send(confirm.encode()?));

                run.keys = Some(keys);
                run.step = Step::ConfirmResp;
                self.rearm_frame_deadline(run.purpose, run.step, out);

                Ok(None)
            }

            Step::AuthInit => {
                let auth = HandshakePayload::decode(&frame)?;

                if auth.stage != 0 || auth.responder_signature.is_some() {
                    return Err(Error::InvalidHandshake);
                }

                let (keys, hash) = Self::verify_auth(run, &auth)?;
                let transcript = run
                    .transcript
                    .as_ref()
                    .ok_or(Error::InvalidStateTransition)?;

                let response = HandshakePayload {
                    purpose: transcript.purpose,
                    stage: 1,
                    cipher_suite: transcript.cipher_suite,
                    initiator_identity: transcript.initiator_identity,
                    responder_identity: transcript.responder_identity,
                    initiator_ephemeral: transcript.initiator_ephemeral,
                    responder_ephemeral: transcript.responder_ephemeral,
                    initiator_nonce: transcript.initiator_nonce,
                    responder_nonce: transcript.responder_nonce,
                    previous_session_id: transcript.previous_session_id,
                    initiator_signature: auth.initiator_signature,
                    responder_signature: Some(self.identity.sign_transcript(&hash, false)),
                };

                out.push(Effect::Send(response.encode()?));

                run.keys = Some(keys);
                run.step = Step::ConfirmInit;
                self.rearm_frame_deadline(run.purpose, run.step, out);

                Ok(None)
            }

            Step::ConfirmResp => {
                let confirm = SessionConfirmPayload::decode(&frame)?;
                let keys = run.keys.take().ok_or(Error::InvalidStateTransition)?;
                let hash = run.hash.ok_or(Error::InvalidStateTransition)?;

                confirm.verify_from(&keys, &hash, HelloRole::Responder)?;

                Self::candidate(run, keys).map(Some)
            }

            Step::ConfirmInit => {
                let confirm = SessionConfirmPayload::decode(&frame)?;
                let keys = run.keys.take().ok_or(Error::InvalidStateTransition)?;
                let hash = run.hash.ok_or(Error::InvalidStateTransition)?;

                confirm.verify_from(&keys, &hash, HelloRole::Initiator)?;

                let reply = SessionConfirmPayload {
                    session_id: keys.session_id,
                    role: HelloRole::Responder,
                    confirmation: confirmation_mac(&keys.confirmation_key, &hash, false),
                };

                out.push(Effect::Send(reply.encode()?));

                Self::candidate(run, keys).map(Some)
            }
        }
    }

    fn verify_auth(run: &Run, auth: &HandshakePayload) -> Result<(SessionKeys, [u8; 32])> {
        let transcript = run
            .transcript
            .as_ref()
            .ok_or(Error::InvalidStateTransition)?;
        let shared = run.shared.as_ref().ok_or(Error::InvalidStateTransition)?;

        verify_handshake_for_role(auth, transcript, shared, true)
    }

    fn candidate(run: &Run, keys: SessionKeys) -> Result<Candidate> {
        Ok(Candidate {
            keys,
            peer: run.remote_identity.ok_or(Error::InvalidStateTransition)?,
            role: run.role,
        })
    }

    /// Both HELLOs are now known and validated.
    fn after_hellos(
        &mut self,
        run: &mut Run,
        remote: &HelloPayload,
        out: &mut Vec<Effect>,
    ) -> Result<Option<Candidate>> {
        let (initiator, responder) = match run.role {
            HelloRole::Initiator => (&run.local_hello, remote),
            HelloRole::Responder => (remote, &run.local_hello),
        };

        let transcript = transcript_from_hellos(initiator, responder)?;
        let hash = transcript_hash(&transcript.encode()?);
        let shared = run.ephemeral.shared_secret(&remote.ephemeral_public_key)?;

        run.shared = Some(shared);
        run.transcript = Some(transcript);
        run.hash = Some(hash);
        run.remote_identity = Some(remote.identity_public_key);

        match run.purpose {
            HandshakePurpose::Initial => {
                run.step = Step::Sas;

                self.cancel(DeadlineKind::HandshakeFrame, out);
                self.arm(
                    DeadlineKind::SasDecision,
                    Duration::from_secs(SAS_DECISION_TIMEOUT_SECS),
                    out,
                );

                out.push(Effect::RequestSas {
                    words: sas_words(&hash),
                    peer_identity: remote.identity_public_key,
                });

                Ok(None)
            }
            HandshakePurpose::Rekey => self.after_approval(run, out),
        }
    }

    /// SAS approved (initial) or identity continuity established (rekey).
    fn after_approval(
        &mut self,
        run: &mut Run,
        out: &mut Vec<Effect>,
    ) -> Result<Option<Candidate>> {
        let hash = run.hash.ok_or(Error::InvalidStateTransition)?;
        let transcript = run
            .transcript
            .as_ref()
            .ok_or(Error::InvalidStateTransition)?;

        match run.role {
            HelloRole::Initiator => {
                let auth = HandshakePayload {
                    purpose: transcript.purpose,
                    stage: 0,
                    cipher_suite: transcript.cipher_suite,
                    initiator_identity: transcript.initiator_identity,
                    responder_identity: transcript.responder_identity,
                    initiator_ephemeral: transcript.initiator_ephemeral,
                    responder_ephemeral: transcript.responder_ephemeral,
                    initiator_nonce: transcript.initiator_nonce,
                    responder_nonce: transcript.responder_nonce,
                    previous_session_id: transcript.previous_session_id,
                    initiator_signature: self.identity.sign_transcript(&hash, true),
                    responder_signature: None,
                };

                out.push(Effect::Send(auth.encode()?));

                run.step = Step::AuthResp;
            }
            HelloRole::Responder => {
                run.step = Step::AuthInit;

                if let Some(early) = run.early.take() {
                    return self.step_run(run, early, out);
                }
            }
        }

        self.rearm_frame_deadline(run.purpose, run.step, out);

        Ok(None)
    }

    // ------------------------------------------------------------------ SAS

    fn on_sas(&mut self, approved: bool, out: &mut Vec<Effect>) {
        let waiting = self.run.as_ref().is_some_and(|run| run.step == Step::Sas);

        if self.phase != Phase::Handshaking || !waiting {
            return;
        }

        self.cancel(DeadlineKind::SasDecision, out);

        if !approved {
            self.terminate(
                CloseCause::SasRejected,
                Some(CloseReason::AuthenticationFailure),
                out,
            );
            return;
        }

        let Some(mut run) = self.run.take() else {
            return;
        };

        match self.after_approval(&mut run, out) {
            Ok(Some(candidate)) => self.complete_initial(candidate, out),
            Ok(None) => self.run = Some(run),
            Err(error) => self.fail_initial(&error, out),
        }
    }

    // ----------------------------------------------------------- completion

    fn complete_initial(&mut self, candidate: Candidate, out: &mut Vec<Effect>) {
        self.cancel(DeadlineKind::HandshakeFrame, out);
        self.cancel(DeadlineKind::SasDecision, out);
        self.cancel(DeadlineKind::HandshakeTotal, out);

        self.active = Some(Session::new(
            &candidate.keys,
            candidate.role,
            candidate.peer,
        ));
        self.phase = Phase::Established;
        self.messages = 0;
        self.late_rekey_frames = 0;
        self.consecutive_rekey_rejections = 0;

        self.arm(
            DeadlineKind::RekeyDue,
            Duration::from_secs(REKEY_INTERVAL_SECS),
            out,
        );

        out.push(Effect::Notify(Event::Established {
            peer_identity: candidate.peer,
        }));
    }

    fn complete_rekey(&mut self, candidate: Candidate, out: &mut Vec<Effect>) {
        let valid = self.active.as_ref().is_some_and(|active| {
            active.peer == candidate.peer && active.id != candidate.keys.session_id
        });

        if !valid {
            self.fail_rekey(&Error::IdentityMismatch, out);
            return;
        }

        self.cancel(DeadlineKind::HandshakeFrame, out);
        self.cancel(DeadlineKind::HandshakeTotal, out);

        let replacement = Session::new(&candidate.keys, candidate.role, candidate.peer);

        // A second rekey inside the drain window replaces the older drainee.
        self.draining = self.active.replace(replacement);

        self.arm(
            DeadlineKind::Drain,
            Duration::from_secs(REKEY_DRAIN_TIMEOUT_SECS),
            out,
        );
        self.arm(
            DeadlineKind::RekeyDue,
            Duration::from_secs(REKEY_INTERVAL_SECS),
            out,
        );

        self.messages = 0;
        self.rekey_blocked = false;
        self.late_rekey_frames = 0;
        self.consecutive_rekey_rejections = 0;

        out.push(Effect::Notify(Event::RekeyCompleted));
    }

    // ---------------------------------------------------------------- rekey

    fn begin_rekey(&mut self, out: &mut Vec<Effect>) {
        if self.phase != Phase::Established || self.run.is_some() {
            return;
        }

        let Some(previous) = self.active_session_id() else {
            return;
        };

        if let Err(error) = self.start_initiator_run(HandshakePurpose::Rekey, Some(previous), out) {
            self.fail_rekey(&error, out);
            return;
        }

        self.arm(
            DeadlineKind::HandshakeTotal,
            Duration::from_secs(HANDSHAKE_TOTAL_TIMEOUT_SECS),
            out,
        );
        self.rearm_frame_deadline(HandshakePurpose::Rekey, Step::Hello, out);

        out.push(Effect::Notify(Event::RekeyStarted));
    }

    fn on_rekey_frame(&mut self, frame: Frame, out: &mut Vec<Effect>) {
        let Some(run) = self.run.as_ref() else {
            if self.late_rekey_frames > 0 {
                self.late_rekey_frames -= 1;
                return;
            }

            if frame.message_type == MessageType::Rekey {
                match CommitPayload::decode(&frame) {
                    Ok(commit) => self.on_incoming_commit(commit, out),
                    Err(_) => self.note_rekey_rejection(out),
                }
            } else if frame.message_type == MessageType::SessionConfirm {
                self.terminate(
                    CloseCause::ProtocolError,
                    Some(CloseReason::ProtocolError),
                    out,
                );
            } else {
                self.note_rekey_rejection(out);
            }

            return;
        };

        let may_be_glare = run.role == HelloRole::Initiator
            && run.step == Step::Hello
            && frame.message_type == MessageType::Rekey;

        if may_be_glare && let Ok(commit) = CommitPayload::decode(&frame) {
            self.resolve_glare(commit, out);
            return;
        }

        match self.drive_run(frame, out) {
            Ok(Some(candidate)) => self.complete_rekey(candidate, out),
            Ok(None) => {}
            Err(error) => self.fail_rekey(&error, out),
        }
    }

    fn on_incoming_commit(&mut self, commit: CommitPayload, out: &mut Vec<Effect>) {
        let references_active = commit.previous_session_id.is_some()
            && commit.previous_session_id == self.active_session_id();

        if commit.cipher_suite != 1
            || commit.purpose != HandshakePurpose::Rekey
            || !references_active
        {
            self.note_rekey_rejection(out);
            return;
        }

        self.consecutive_rekey_rejections = 0;
        if let Err(error) = self.start_responder_run(commit, out) {
            self.fail_rekey(&error, out);
        }
    }

    /// Spec §8.5: the greater raw identity key stays initiator.
    fn resolve_glare(&mut self, commit: CommitPayload, out: &mut Vec<Effect>) {
        let Some(peer) = self.peer_identity() else {
            return;
        };

        if commit.previous_session_id != self.run.as_ref().and_then(|run| run.previous) {
            self.note_rekey_rejection(out);
            return;
        }

        if local_identity_wins_rekey_glare(&self.identity.identity(), &peer) {
            return;
        }

        // Losing side: drop our commitment and ephemeral, then answer as responder.
        self.run = None;
        self.cancel(DeadlineKind::HandshakeFrame, out);
        self.cancel(DeadlineKind::HandshakeTotal, out);

        self.on_incoming_commit(commit, out);
    }

    /// A failed rekey discards only the candidate; the session stays usable
    /// and a later attempt is allowed after a pause (§8.4).
    fn fail_rekey(&mut self, error: &Error, out: &mut Vec<Effect>) {
        self.run = None;
        self.late_rekey_frames = LATE_REKEY_FRAME_GRACE;

        self.cancel(DeadlineKind::HandshakeFrame, out);
        self.cancel(DeadlineKind::HandshakeTotal, out);

        self.rekey_blocked = true;
        self.arm(
            DeadlineKind::RekeyDue,
            Duration::from_secs(REKEY_RETRY_SECS),
            out,
        );

        let failure = match error {
            Error::TransportTimeout => RekeyFailure::Timeout,
            Error::IdentityMismatch => RekeyFailure::IdentityMismatch,
            _ => RekeyFailure::Invalid,
        };

        out.push(Effect::Notify(Event::RekeyFailed(failure)));
    }

    fn note_rekey_rejection(&mut self, out: &mut Vec<Effect>) {
        if self.consecutive_rekey_rejections < REKEY_REJECTION_WARNING_THRESHOLD {
            self.consecutive_rekey_rejections += 1;
            if self.consecutive_rekey_rejections == REKEY_REJECTION_WARNING_THRESHOLD {
                out.push(Effect::Notify(Event::RekeyFailed(RekeyFailure::Repeated)));
            }
        }
    }

    fn fail_initial(&mut self, error: &Error, out: &mut Vec<Effect>) {
        let (cause, reason) = match error {
            Error::SasRejected => (CloseCause::SasRejected, CloseReason::AuthenticationFailure),
            Error::SignatureInvalid | Error::ConfirmationInvalid => (
                CloseCause::AuthenticationFailure,
                CloseReason::AuthenticationFailure,
            ),
            Error::IdentityMismatch => (
                CloseCause::AuthenticationFailure,
                CloseReason::IdentityChanged,
            ),
            _ => (CloseCause::ProtocolError, CloseReason::ProtocolError),
        };

        self.terminate(cause, Some(reason), out);
    }

    // ----------------------------------------------------------------- DATA

    fn on_send(&mut self, content: &[u8], out: &mut Vec<Effect>) {
        if content.len() > MAX_CONTENT {
            out.push(Effect::Notify(Event::SendRejected(SendRejection::TooLarge)));
            return;
        }

        let Some(active) = self
            .active
            .as_mut()
            .filter(|_| self.phase == Phase::Established)
        else {
            out.push(Effect::Notify(Event::SendRejected(
                SendRejection::NotActive,
            )));
            return;
        };

        match active.sender.encrypt(content) {
            Ok(frame) => {
                out.push(Effect::Send(frame));
                self.messages = self.messages.saturating_add(1);
                self.maybe_trigger_rekey(out);
            }
            Err(Error::DataTooLarge) => {
                out.push(Effect::Notify(Event::SendRejected(SendRejection::TooLarge)));
            }
            // Counter exhaustion or an internal failure: the session cannot
            // send safely any more.
            Err(_) => self.terminate(
                CloseCause::ProtocolError,
                Some(CloseReason::ProtocolError),
                out,
            ),
        }
    }

    fn on_data(&mut self, frame: &Frame, out: &mut Vec<Effect>) {
        let Some(active) = self.active.as_mut() else {
            return;
        };

        match active.receiver.decrypt(frame) {
            Ok(plaintext) => {
                out.push(Effect::Deliver(plaintext));
                self.messages = self.messages.saturating_add(1);
                self.maybe_trigger_rekey(out);
            }
            Err(active_error) => {
                if let Some(draining) = self.draining.as_mut()
                    && let Ok(plaintext) = draining.receiver.decrypt(frame)
                {
                    out.push(Effect::Deliver(plaintext));
                    return;
                }

                if is_malformed(&active_error) {
                    self.terminate(
                        CloseCause::ProtocolError,
                        Some(CloseReason::ProtocolError),
                        out,
                    );
                } else {
                    out.push(Effect::Notify(Event::DataRejected));
                }
            }
        }
    }

    fn maybe_trigger_rekey(&mut self, out: &mut Vec<Effect>) {
        if self.messages >= self.rekey_message_limit && !self.rekey_blocked && self.run.is_none() {
            self.begin_rekey(out);
        }
    }

    // ---------------------------------------------------------------- CLOSE

    fn on_close_frame(&mut self, frame: &Frame, out: &mut Vec<Effect>) {
        let Ok(close) = ClosePayload::decode(frame) else {
            self.terminate(
                CloseCause::ProtocolError,
                Some(CloseReason::ProtocolError),
                out,
            );
            return;
        };

        if self.phase == Phase::Handshaking {
            // No session exists yet, so only an ID-less CLOSE is meaningful.
            if close.session_id.is_none() {
                self.terminate(CloseCause::PeerUnauthenticated(close.reason), None, out);
            }
            return;
        }

        match close.session_id {
            Some(id) if Some(id) == self.active_session_id() => {
                self.terminate(CloseCause::PeerUnauthenticated(close.reason), None, out);
            }
            Some(id) if Some(id) == self.draining_session_id() => {
                self.draining = None;
                self.cancel(DeadlineKind::Drain, out);
            }
            // Unknown or absent session ID: ignored (D-017).
            _ => {}
        }
    }

    fn terminate(
        &mut self,
        cause: CloseCause,
        notify_peer: Option<CloseReason>,
        out: &mut Vec<Effect>,
    ) {
        self.cancel_all(out);

        if let Some(reason) = notify_peer {
            let close = ClosePayload {
                session_id: self.active_session_id(),
                reason,
                detail: None,
            };

            if let Ok(frame) = close.encode() {
                out.push(Effect::Send(frame));
            }
        }

        out.push(Effect::Notify(Event::Closed(cause)));
        out.push(Effect::CloseTransport);

        self.run = None;
        self.active = None;
        self.draining = None;
        self.phase = Phase::Closed;
    }
}

/// Structurally invalid DATA ends the session (§4.1); authentication, replay
/// and window failures only drop the frame.
fn is_malformed(error: &Error) -> bool {
    matches!(
        error,
        Error::Encoding(_)
            | Error::NonCanonicalEncoding
            | Error::InvalidPayloadShape
            | Error::InvalidMapKey
            | Error::DuplicateMapKey(_)
            | Error::InvalidLength { .. }
            | Error::InvalidFrameLength(_)
            | Error::TruncatedFrame
            | Error::DataTooLarge
    )
}
