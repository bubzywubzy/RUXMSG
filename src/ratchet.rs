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

    /// Derives the key for `counter`, retaining bounded skipped keys for reorder.
    pub fn message_key(&mut self, counter: u64) -> Result<[u8; 32]> {
        if let Some(key) = self.skipped.remove(&counter) {
            return Ok(key);
        }
        if counter < self.next_counter {
            return Err(Error::MessageKeyUnavailable(counter));
        }
        let gap = counter - self.next_counter;
        if gap > u64::from(MAX_SKIPPED_KEYS) || self.skipped.len() >= usize::from(MAX_SKIPPED_KEYS)
        {
            return Err(Error::SkippedKeyLimit);
        }
        while self.next_counter < counter {
            let (key, next) = derive_message_key(&self.chain_key, self.direction);
            self.skipped.insert(self.next_counter, key);
            self.chain_key = next;
            self.next_counter = self
                .next_counter
                .checked_add(1)
                .ok_or(Error::CounterOverflow)?;
        }
        let (key, next) = derive_message_key(&self.chain_key, self.direction);
        self.chain_key = next;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(Error::CounterOverflow)?;
        Ok(key)
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
        assert_eq!(chain.message_key(65), Err(Error::SkippedKeyLimit));
        assert!(chain.message_key(64).is_ok());
        assert_eq!(chain.skipped_len(), 64);
    }
}
