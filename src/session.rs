//! Session lifecycle state and rekey timing policy.

use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::protocol::{
    REKEY_DRAIN_TIMEOUT_SECS, REKEY_INTERVAL_SECS, REKEY_MESSAGE_LIMIT, SessionId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Handshaking,
    Active,
    Rekeying,
    Draining,
    Closed,
}

#[derive(Debug, Clone)]
pub struct SessionLifecycle {
    session_id: SessionId,
    state: SessionState,
    established_at: Option<Instant>,
    sent_messages: u64,
    drain_started_at: Option<Instant>,
}

impl SessionLifecycle {
    /// Creates a session in the non-data-capable `Handshaking` state.
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            state: SessionState::Handshaking,
            established_at: None,
            sent_messages: 0,
            drain_started_at: None,
        }
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Activates a confirmed initial session or rekey candidate.
    pub fn activate(&mut self, now: Instant) -> Result<()> {
        if self.state != SessionState::Handshaking && self.state != SessionState::Rekeying {
            return Err(Error::InvalidStateTransition);
        }
        self.state = SessionState::Active;
        self.established_at = Some(now);
        self.drain_started_at = None;
        Ok(())
    }

    /// Marks an active session as rekeying while it remains usable for DATA.
    pub fn begin_rekey(&mut self) -> Result<()> {
        if self.state != SessionState::Active {
            return Err(Error::InvalidStateTransition);
        }
        self.state = SessionState::Rekeying;
        Ok(())
    }

    /// Makes a superseded session receive-only for the bounded drain window.
    pub fn begin_draining(&mut self, now: Instant) -> Result<()> {
        if self.state != SessionState::Active && self.state != SessionState::Rekeying {
            return Err(Error::InvalidStateTransition);
        }
        self.state = SessionState::Draining;
        self.drain_started_at = Some(now);
        Ok(())
    }

    /// Permanently closes the session and disables DATA.
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
        self.drain_started_at = None;
    }

    /// Per the state-transition contract, REKEYING sessions keep sending on
    /// the current keys until the candidate is confirmed; only DRAINING and
    /// CLOSED sessions may never originate new DATA.
    pub const fn can_originate_data(&self) -> bool {
        matches!(self.state, SessionState::Active | SessionState::Rekeying)
    }

    /// DRAINING sessions may still accept already-in-flight DATA.
    pub const fn can_receive_data(&self) -> bool {
        matches!(
            self.state,
            SessionState::Active | SessionState::Rekeying | SessionState::Draining
        )
    }

    pub fn record_sent_data(&mut self) -> Result<()> {
        if !self.can_originate_data() {
            return Err(Error::InvalidStateTransition);
        }
        self.sent_messages = self
            .sent_messages
            .checked_add(1)
            .ok_or(Error::CounterOverflow)?;
        Ok(())
    }

    pub fn rekey_due(&self, now: Instant) -> bool {
        self.established_at.is_some_and(|established| {
            now.duration_since(established) >= Duration::from_secs(REKEY_INTERVAL_SECS)
        }) || self.sent_messages >= REKEY_MESSAGE_LIMIT
    }

    pub fn drain_expired(&self, now: Instant) -> bool {
        self.drain_started_at.is_some_and(|started| {
            now.duration_since(started) >= Duration::from_secs(REKEY_DRAIN_TIMEOUT_SECS)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_requires_activation_before_data_or_rekey() {
        let mut lifecycle = SessionLifecycle::new(SessionId::from_bytes([3; 16]));
        assert_eq!(
            lifecycle.record_sent_data(),
            Err(Error::InvalidStateTransition)
        );
        lifecycle.activate(Instant::now()).unwrap();
        lifecycle.record_sent_data().unwrap();
        lifecycle.begin_rekey().unwrap();
        // REKEYING sessions remain usable for sending until the candidate wins.
        lifecycle.record_sent_data().unwrap();
    }

    #[test]
    fn draining_sessions_may_receive_but_never_originate_data() {
        let mut lifecycle = SessionLifecycle::new(SessionId::from_bytes([4; 16]));
        lifecycle.activate(Instant::now()).unwrap();
        lifecycle.begin_draining(Instant::now()).unwrap();
        assert!(lifecycle.can_receive_data());
        assert!(!lifecycle.can_originate_data());
        assert_eq!(
            lifecycle.record_sent_data(),
            Err(Error::InvalidStateTransition)
        );
    }
}
