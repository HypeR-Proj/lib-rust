// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Cursor and payload protocol, independent of mapping and notification syscalls.

use super::{Config, QueueError};
use core::sync::atomic::Ordering::{Relaxed, SeqCst};

pub(super) const HEAD: usize = 0;
pub(super) const SPACE_ARMED: usize = 1;
pub(super) const CLOSED: usize = 2;
pub(super) const TAIL: usize = 0;
pub(super) const DATA_ARMED: usize = 1;
pub(super) const HEADER_WORDS: usize = 8;

pub(super) trait Words {
    fn load(&self, index: usize, order: core::sync::atomic::Ordering) -> crate::Result<u64>;
    fn store(
        &self,
        index: usize,
        value: u64,
        order: core::sync::atomic::Ordering,
    ) -> crate::Result<()>;
}

/// Local state never trusts a peer to supply an address or rewind a cursor.
pub(super) struct Cursor {
    pub(super) position: u64,
    peer: u64,
    config: Config,
}

impl Cursor {
    pub(super) fn new(config: Config) -> Self {
        Self {
            position: 0,
            peer: 0,
            config,
        }
    }

    fn observe_tail(&mut self, control: &impl Words) -> Result<u64, QueueError> {
        let tail = control.load(TAIL, SeqCst)?;
        if tail < self.peer
            || tail > self.position
            || self.position - tail > self.config.slots as u64
        {
            return Err(QueueError::InvalidPeer);
        }
        self.peer = tail;
        Ok(tail)
    }

    fn observe_head(&mut self, data: &impl Words) -> Result<u64, QueueError> {
        let head = data.load(HEAD, SeqCst)?;
        if head < self.peer
            || head < self.position
            || head - self.position > self.config.slots as u64
        {
            return Err(QueueError::InvalidPeer);
        }
        self.peer = head;
        Ok(head)
    }

    fn slot(&self) -> usize {
        // Geometry is validated once locally; mutable peer state never changes it.
        HEADER_WORDS
            + (self.position % self.config.slots as u64) as usize * self.config.slot_words()
    }

    pub(super) fn writable(&mut self, control: &impl Words) -> Result<bool, QueueError> {
        if self.position == u64::MAX {
            return Err(QueueError::CounterExhausted);
        }
        Ok(self.position - self.observe_tail(control)? < self.config.slots as u64)
    }

    pub(super) fn readable(&mut self, data: &impl Words) -> Result<bool, QueueError> {
        if self.observe_head(data)? != self.position {
            return Ok(true);
        }
        match data.load(CLOSED, SeqCst)? {
            0 => Ok(false),
            1 => {
                // Acquiring CLOSED precedes the final head reread: a graceful
                // producer publishes its final head before the close marker.
                if self.observe_head(data)? == self.position {
                    Err(QueueError::Closed)
                } else {
                    Ok(true)
                }
            }
            _ => Err(QueueError::InvalidPeer),
        }
    }

    /// Success is the publication commit point; notification is a separate step.
    pub(super) fn push(
        &mut self,
        data: &impl Words,
        control: &impl Words,
        bytes: &[u8],
    ) -> Result<(), QueueError> {
        if bytes.len() > self.config.message_bytes {
            return Err(QueueError::MessageTooLarge {
                maximum: self.config.message_bytes,
            });
        }
        if !self.writable(control)? {
            return Err(QueueError::Full);
        }
        let slot = self.slot();
        for (index, chunk) in bytes.chunks(8).enumerate() {
            let mut word = [0; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            data.store(slot + 1 + index, u64::from_le_bytes(word), Relaxed)?;
        }
        data.store(slot, bytes.len() as u64, Relaxed)?;
        let next = self.position + 1;
        // The single SC order with DATA_ARMED prevents both sides missing the
        // other's publication during arm/recheck. This also releases payload.
        data.store(HEAD, next, SeqCst)?;
        self.position = next;
        Ok(())
    }

    pub(super) fn pop(
        &mut self,
        data: &impl Words,
        control: &impl Words,
        output: &mut [u8],
    ) -> Result<usize, QueueError> {
        if !self.readable(data)? {
            return Err(QueueError::Empty);
        }
        let next = self
            .position
            .checked_add(1)
            .ok_or(QueueError::CounterExhausted)?;
        let slot = self.slot();
        let length =
            usize::try_from(data.load(slot, Relaxed)?).map_err(|_| QueueError::InvalidPeer)?;
        if length > self.config.message_bytes {
            return Err(QueueError::InvalidPeer);
        }
        if length > output.len() {
            return Err(QueueError::BufferTooSmall { required: length });
        }
        // Only private buffers contain ordinary bytes. A malicious producer may
        // change atomic payload words, but cannot manufacture references or bounds.
        for (index, chunk) in output[..length].chunks_mut(8).enumerate() {
            let word = data.load(slot + 1 + index, Relaxed)?.to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        control.store(TAIL, next, SeqCst)?;
        self.position = next;
        Ok(length)
    }
}

/// Execute real publication and notification as distinct, testable commit stages.
pub(super) fn send_batch(
    cursor: &mut Cursor,
    data: &impl Words,
    control: &impl Words,
    input: &[&[u8]],
    notify: impl FnOnce() -> Result<(), QueueError>,
) -> super::BatchOutcome {
    let mut outcome = super::BatchOutcome {
        completed: 0,
        stop: None,
    };
    for bytes in input {
        match cursor.push(data, control, bytes) {
            Ok(()) => outcome.completed += 1,
            Err(error) => {
                outcome.stop = Some(error);
                break;
            }
        }
    }
    complete_batch(outcome, notify)
}

pub(super) fn receive_batch(
    cursor: &mut Cursor,
    data: &impl Words,
    control: &impl Words,
    output: &mut [super::ReceiveSlot<'_>],
    peer_dead: bool,
    notify: impl FnOnce() -> Result<(), QueueError>,
) -> super::BatchOutcome {
    let mut outcome = super::BatchOutcome {
        completed: 0,
        stop: None,
    };
    for slot in output.iter_mut() {
        slot.length = None;
    }
    for slot in output {
        match cursor.pop(data, control, slot.buffer) {
            Ok(length) => {
                slot.length = Some(length);
                outcome.completed += 1;
            }
            Err(QueueError::Empty) if peer_dead => {
                outcome.stop = Some(QueueError::PeerDied);
                break;
            }
            Err(error) => {
                outcome.stop = Some(error);
                break;
            }
        }
    }
    complete_batch(outcome, notify)
}

fn complete_batch(
    mut outcome: super::BatchOutcome,
    notify: impl FnOnce() -> Result<(), QueueError>,
) -> super::BatchOutcome {
    if outcome.completed != 0
        && let Err(error) = notify()
    {
        outcome.stop = Some(error);
    }
    outcome
}
