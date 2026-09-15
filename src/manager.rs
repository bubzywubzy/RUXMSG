//! Ownership and routing for active, rekeying, and draining sessions.
//!
//! `SessionManager` ensures that exactly one session originates DATA. During a
//! successful rekey it retains the predecessor only to receive eligible
//! in-flight frames until the bounded drain timeout expires.

use std::time::Instant;

use crate::data::{DataReceiver, DataSender};
use crate::engine::EstablishedSession;
use crate::error::{Error, Result};
use crate::handshake::{HelloRole, local_identity_wins_rekey_glare};
use crate::identity::PeerIdentity;
use crate::protocol::{DirectionId, SessionId};
use crate::session::{SessionLifecycle, SessionState};
use crate::wire::Frame;

/// A completed handshake paired with its lifecycle state tracker and directional ratchets.
#[derive(Debug)]
pub struct ManagedSession {
    lifecycle: SessionLifecycle,
    established: EstablishedSession,
    sender: DataSender,
    receiver: DataReceiver,
}

impl ManagedSession {
    fn new(established: EstablishedSession, local_role: HelloRole) -> Self {
        let (send_direction, send_key, receive_direction, receive_key) = match local_role {
            HelloRole::Initiator => (
                DirectionId::InitiatorToResponder,
                established.keys.initiator_to_responder,
                DirectionId::ResponderToInitiator,
                established.keys.responder_to_initiator,
            ),
            HelloRole::Responder => (
                DirectionId::ResponderToInitiator,
                established.keys.responder_to_initiator,
                DirectionId::InitiatorToResponder,
                established.keys.initiator_to_responder,
            ),
        };
        let session_id = established.keys.session_id;
        Self {
            lifecycle: SessionLifecycle::new(session_id),
            sender: DataSender::new(session_id, send_direction, send_key),
            receiver: DataReceiver::new(session_id, receive_direction, receive_key),
            established,
        }
    }

    /// Returns this managed session's protocol session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.lifecycle.session_id()
    }

    /// Returns the lifecycle state controlling DATA permissions.
    pub const fn state(&self) -> SessionState {
        self.lifecycle.state()
    }

    pub const fn can_originate_data(&self) -> bool {
        self.lifecycle.can_originate_data()
    }

    pub const fn can_receive_data(&self) -> bool {
        self.lifecycle.can_receive_data()
    }

    pub const fn peer_identity(&self) -> PeerIdentity {
        self.established.peer_identity
    }

    /// Borrows the authenticated handshake result for inspection.
    pub const fn established(&self) -> &EstablishedSession {
        &self.established
    }
}

/// Owns the active session plus, during a rekey drain window, the session it superseded.
///
/// Exactly one session is ever active. A superseded session is retained only long
/// enough that in-flight peer traffic encrypted under its keys is not dropped
/// mid-rekey; per D-008 no session key material is ever persisted through this type.
#[derive(Debug)]
pub struct SessionManager {
    active: ManagedSession,
    draining: Option<ManagedSession>,
}

impl SessionManager {
    /// Wraps a freshly completed initial handshake as the active session.
    pub fn from_initial_handshake(
        established: EstablishedSession,
        local_role: HelloRole,
        now: Instant,
    ) -> Result<Self> {
        let mut active = ManagedSession::new(established, local_role);
        active.lifecycle.activate(now)?;
        Ok(Self {
            active,
            draining: None,
        })
    }

    /// Borrows the only session currently allowed to originate DATA.
    pub const fn active(&self) -> &ManagedSession {
        &self.active
    }

    /// Borrows the superseded receive-only session, if a drain is in progress.
    pub const fn draining(&self) -> Option<&ManagedSession> {
        self.draining.as_ref()
    }

    pub const fn active_session_id(&self) -> SessionId {
        self.active.lifecycle.session_id()
    }

    /// Decides which peer drives the next rekey handshake as initiator.
    ///
    /// Both peers evaluate this identically from their own local/remote identity
    /// view, so a clock-triggered rekey never needs live glare arbitration; the
    /// raw-key tie-break only matters if both sides race anyway (e.g. clock skew).
    pub fn rekey_role(&self, local_identity: &PeerIdentity) -> HelloRole {
        if local_identity_wins_rekey_glare(local_identity, &self.active.peer_identity()) {
            HelloRole::Initiator
        } else {
            HelloRole::Responder
        }
    }

    /// Reports whether time or sent-message policy requests a rekey.
    pub fn rekey_due(&self, now: Instant) -> bool {
        self.active.lifecycle.rekey_due(now)
    }

    /// Marks the active session as mid-rekey; it keeps sending/receiving DATA
    /// while a candidate handshake for its replacement is negotiated.
    pub fn begin_rekey(&mut self) -> Result<()> {
        self.active.lifecycle.begin_rekey()
    }

    /// Promotes a completed rekey candidate to active and drains the old session.
    pub fn complete_rekey(
        &mut self,
        candidate: EstablishedSession,
        local_role: HelloRole,
        now: Instant,
    ) -> Result<()> {
        if candidate.keys.session_id == self.active.session_id() {
            return Err(Error::InvalidStateTransition);
        }
        let mut new_active = ManagedSession::new(candidate, local_role);
        new_active.lifecycle.activate(now)?;
        let mut superseded = std::mem::replace(&mut self.active, new_active);
        superseded.lifecycle.begin_draining(now)?;
        self.draining = Some(superseded);
        Ok(())
    }

    /// Encrypts and frames outbound content on the active session only.
    ///
    /// A DRAINING session is never used to originate DATA; only the active
    /// session's lifecycle (ACTIVE or REKEYING) is eligible to send.
    pub fn encrypt(&mut self, content: &[u8]) -> Result<Frame> {
        self.active.lifecycle.record_sent_data()?;
        self.active.sender.encrypt(content)
    }

    /// Decrypts inbound DATA, routing it to whichever session (active or
    /// draining) the frame's embedded session ID and directional AEAD match.
    pub fn decrypt(&mut self, frame: &Frame) -> Result<Vec<u8>> {
        if !self.active.lifecycle.can_receive_data() {
            return Err(Error::InvalidStateTransition);
        }
        match self.active.receiver.decrypt(frame) {
            Ok(plaintext) => Ok(plaintext),
            Err(active_err) => match &mut self.draining {
                Some(draining) if draining.lifecycle.can_receive_data() => {
                    draining.receiver.decrypt(frame)
                }
                _ => Err(active_err),
            },
        }
    }

    /// Drops the superseded session once its receive-only drain window elapses.
    pub fn expire_drain(&mut self, now: Instant) {
        if let Some(draining) = &mut self.draining
            && draining.lifecycle.drain_expired(now)
        {
            draining.lifecycle.close();
            self.draining = None;
        }
    }

    /// Closes the active and any draining session and drops the drain state.
    pub fn close(&mut self) {
        self.active.lifecycle.close();
        if let Some(draining) = &mut self.draining {
            draining.lifecycle.close();
        }
        self.draining = None;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::crypto::derive_session_keys;

    fn established(seed: u8, peer: [u8; 32]) -> EstablishedSession {
        let shared_secret = [seed; 32];
        let transcript_hash = [seed.wrapping_add(1); 32];
        EstablishedSession {
            keys: derive_session_keys(&shared_secret, &transcript_hash).unwrap(),
            transcript_hash,
            peer_identity: PeerIdentity::from_bytes(peer),
        }
    }

    #[test]
    fn rekey_promotes_candidate_and_drains_previous_session() {
        let now = Instant::now();
        let mut manager = SessionManager::from_initial_handshake(
            established(1, [9; 32]),
            HelloRole::Initiator,
            now,
        )
        .unwrap();
        let old_id = manager.active_session_id();

        manager.begin_rekey().unwrap();
        let candidate = established(2, [9; 32]);
        let new_id = candidate.keys.session_id;
        manager
            .complete_rekey(candidate, HelloRole::Initiator, now)
            .unwrap();

        assert_ne!(old_id, new_id);
        assert_eq!(manager.active_session_id(), new_id);
        let draining = manager.draining().unwrap();
        assert_eq!(draining.session_id(), old_id);
        assert_eq!(draining.state(), SessionState::Draining);

        manager.expire_drain(now);
        assert!(manager.draining().is_some());

        manager.expire_drain(now + Duration::from_secs(16));
        assert!(manager.draining().is_none());
    }

    #[test]
    fn complete_rekey_rejects_a_candidate_reusing_the_active_session_id() {
        let now = Instant::now();
        let initial = established(1, [9; 32]);
        let session_id = initial.keys.session_id;
        let mut manager =
            SessionManager::from_initial_handshake(initial, HelloRole::Initiator, now).unwrap();
        manager.begin_rekey().unwrap();
        let mut duplicate = established(2, [9; 32]);
        duplicate.keys.session_id = session_id;
        assert_eq!(
            manager.complete_rekey(duplicate, HelloRole::Initiator, now),
            Err(Error::InvalidStateTransition)
        );
    }

    #[test]
    fn rekey_role_is_deterministic_from_the_raw_key_tie_break() {
        let now = Instant::now();
        let manager = SessionManager::from_initial_handshake(
            established(1, [9; 32]),
            HelloRole::Initiator,
            now,
        )
        .unwrap();
        assert_eq!(
            manager.rekey_role(&PeerIdentity::from_bytes([200; 32])),
            HelloRole::Initiator
        );
        assert_eq!(
            manager.rekey_role(&PeerIdentity::from_bytes([1; 32])),
            HelloRole::Responder
        );
    }

    #[test]
    fn draining_session_never_originates_data_once_superseded() {
        let now = Instant::now();
        let initiator = established(1, [9; 32]);
        let mut manager =
            SessionManager::from_initial_handshake(initiator, HelloRole::Initiator, now).unwrap();

        manager.begin_rekey().unwrap();
        // REKEYING still originates DATA on the current session per the spec.
        manager.encrypt(b"still active").unwrap();

        let candidate = established(2, [9; 32]);
        manager
            .complete_rekey(candidate, HelloRole::Initiator, now)
            .unwrap();
        let draining = manager.draining().unwrap();
        assert_eq!(draining.state(), SessionState::Draining);
        assert!(!draining.can_originate_data());
        assert!(draining.can_receive_data());

        manager.expire_drain(now + Duration::from_secs(16));
        assert!(manager.draining().is_none());
    }
}
