//! Directional message-key ratchets and bounded replay tracking.
//!
//! Chain state is session-local secret material. Receiving reordering is
//! supported only within the configured skipped-key and replay limits.

use std::collections::BTreeMap;

use crate::crypto::derive_message_key;
use crate::error::{Error, Result};
use crate::protocol::{DirectionId, MAX_SKIPPED_KEYS, REPLAY_WINDOW_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayStatus {
    New,
    Duplicate,
    TooOld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bits: u64,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// Creates an empty 64-message replay window.
    pub const fn new() -> Self {
        Self {
            highest: None,
            bits: 0,
        }
    }

    /// Classifies a counter without mutating the window.
    pub fn classify(&self, counter: u64) -> ReplayStatus {
        let Some(highest) = self.highest else {
            return ReplayStatus::New;
        };

        if counter > highest {
            return ReplayStatus::New;
        }

        let distance = highest - counter;

        if distance >= u64::from(REPLAY_WINDOW_SIZE) {
            ReplayStatus::TooOld
        } else if self.bits & (1u64 << distance) != 0 {
            ReplayStatus::Duplicate
        } else {
            ReplayStatus::New
        }
    }

    /// Accepts a new counter and records it, rejecting duplicates and old data.
    pub fn accept(&mut self, counter: u64) -> Result<()> {
        if self.classify(counter) != ReplayStatus::New {
            return Err(Error::ReplayRejected);
        }

        match self.highest {
            None => {
                self.highest = Some(counter);
                self.bits = 1;
            }

            Some(highest) if counter > highest => {
                let shift = counter - highest;

                self.bits = if shift >= 64 {
                    1
                } else {
                    (self.bits << shift) | 1
                };

                self.highest = Some(counter);
            }

            Some(highest) => {
                self.bits |= 1u64 << (highest - counter);
            }
        }

        Ok(())
    }

    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }
}

#[derive(Debug, Clone)]
pub struct ReceivingChain {
    chain_key: [u8; 32],
    next_counter: u64,

    // Keys that have been derived but have not yet been committed after
    // successful authentication.
    skipped: BTreeMap<u64, [u8; 32]>,

    direction: DirectionId,
}

impl ReceivingChain {
    /// Creates a receiving chain whose next expected counter is zero.
    pub fn new(chain_key: [u8; 32], direction: DirectionId) -> Self {
        Self {
            chain_key,
            next_counter: 0,
            skipped: BTreeMap::new(),
            direction,
        }
    }

    /// Derives or retrieves the key for `counter` without consuming it.
    ///
    /// Keys remain retained until `commit_message_key()` is called after
    /// successful authentication and plaintext validation.
    pub fn prepare_message_key(&mut self, counter: u64) -> Result<[u8; 32]> {
        // Do not remove the key here. Authentication may still fail.
        if let Some(key) = self.skipped.get(&counter) {
            return Ok(*key);
        }

        if counter < self.next_counter {
            return Err(Error::MessageKeyUnavailable(counter));
        }

        let gap = counter - self.next_counter;

        if gap > u64::from(MAX_SKIPPED_KEYS) || self.skipped.len() >= usize::from(MAX_SKIPPED_KEYS)
        {
            return Err(Error::SkippedKeyLimit);
        }

        // Derive and retain keys for counters before the target so that
        // reordered messages can still be authenticated later.
        while self.next_counter < counter {
            let (key, next) = derive_message_key(&self.chain_key, self.direction);

            self.skipped.insert(self.next_counter, key);

            self.chain_key = next;

            self.next_counter = self
                .next_counter
                .checked_add(1)
                .ok_or(Error::CounterOverflow)?;
        }

        // Derive the target key and retain it as well. It must survive an
        // authentication failure so that a legitimate frame using the same
        // counter can be retried.
        let (key, next) = derive_message_key(&self.chain_key, self.direction);

        self.chain_key = next;

        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(Error::CounterOverflow)?;

        self.skipped.insert(counter, key);

        Ok(key)
    }

    /// Commits a successfully authenticated message key.
    ///
    /// This is the only operation that consumes a prepared message key.
    pub fn commit_message_key(&mut self, counter: u64) -> Result<()> {
        if self.skipped.remove(&counter).is_some() {
            Ok(())
        } else {
            Err(Error::MessageKeyUnavailable(counter))
        }
    }

    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_accepts_reordering_but_rejects_duplicates() {
        let mut window = ReplayWindow::new();

        window.accept(4).unwrap();
        window.accept(2).unwrap();

        assert_eq!(window.classify(2), ReplayStatus::Duplicate);
        assert_eq!(window.classify(0), ReplayStatus::New);
        assert_eq!(window.classify(4), ReplayStatus::Duplicate);
    }

    #[test]
    fn receiving_chain_bounds_skipped_key_derivation() {
        let mut chain = ReceivingChain::new([1; 32], DirectionId::InitiatorToResponder);

        assert_eq!(chain.prepare_message_key(65), Err(Error::SkippedKeyLimit));

        assert!(chain.prepare_message_key(64).is_ok());
        assert_eq!(chain.skipped_len(), 65);
    }

    #[test]
    fn prepared_message_key_is_retained_until_commit() {
        let mut chain = ReceivingChain::new([1; 32], DirectionId::InitiatorToResponder);

        let first_key = chain.prepare_message_key(0).unwrap();

        assert_eq!(chain.skipped_len(), 1);

        // Preparing the same counter again must return the same key rather
        // than deriving a new key or consuming the existing one.
        let second_key = chain.prepare_message_key(0).unwrap();

        assert_eq!(first_key, second_key);
        assert_eq!(chain.skipped_len(), 1);
    }

    #[test]
    fn committed_message_key_is_consumed() {
        let mut chain = ReceivingChain::new([1; 32], DirectionId::InitiatorToResponder);

        let _key = chain.prepare_message_key(0).unwrap();

        chain.commit_message_key(0).unwrap();

        // The key must not be recoverable after commitment.
        assert_eq!(
            chain.prepare_message_key(0),
            Err(Error::MessageKeyUnavailable(0))
        );
    }
}
