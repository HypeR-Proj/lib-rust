// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Bounded single-producer/single-consumer messages in shared RAM.
//!
//! Each direction owns two VMOs: producer-written data and consumer-written
//! control. Peers receive read-only views of each other's words. Two Events
//! carry coalesced readiness hints; a `ByteChannel` carries endpoint lifetime.
//! Only aligned atomic u64 words are shared, never Rust references to payload.
//! Queue geometry is agreed out of band and cannot be changed by shared metadata.
//! A successful send means publication, not acknowledgement by the receiver.
//! Nonblocking batches do not issue lifecycle-query syscalls: use the matching
//! `wait_*_until` on Full/Empty to observe peer death. Polling alone may continue
//! reporting Full/Empty after a peer exits. No transport supports DMA retirement.
//! Peers must obey the same-width atomic access discipline; corrupt values are
//! bounded and rejected, but arbitrary mixed-width/non-atomic aliases are outside
//! the Rust memory-model contract of the unsafe mapping boundary.

mod endpoint;
mod mapping;
mod protocol;
pub use endpoint::{Consumer, Producer};

use crate::event::Event;
use crate::handle::{ByteChannelObject, OwnedHandle, Rights, VmoObject};
use crate::memory::{PAGE_SIZE, WritableVmo};

/// The wire layout version; negotiate it alongside geometry before transferring caps.
pub const VERSION: u32 = 1;
pub const MAX_SLOTS: usize = 1024;
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_DATA_BYTES: usize = 16 * 1024 * 1024;

/// Immutable local geometry. Slots carry a length word plus padded payload words.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    slots: usize,
    message_bytes: usize,
}
impl Config {
    pub fn new(slots: usize, message_bytes: usize) -> Result<Self, QueueError> {
        if slots == 0
            || slots > MAX_SLOTS
            || message_bytes == 0
            || message_bytes > MAX_MESSAGE_BYTES
        {
            return Err(QueueError::InvalidConfig);
        }
        let config = Self {
            slots,
            message_bytes,
        };
        if config.data_bytes() > MAX_DATA_BYTES {
            return Err(QueueError::InvalidConfig);
        }
        Ok(config)
    }
    pub const fn slots(self) -> usize {
        self.slots
    }
    pub const fn message_bytes(self) -> usize {
        self.message_bytes
    }
    fn slot_words(self) -> usize {
        1 + self.message_bytes.div_ceil(8)
    }
    fn data_bytes(self) -> usize {
        ((protocol::HEADER_WORDS + self.slots * self.slot_words()) * 8).div_ceil(PAGE_SIZE as usize)
            * PAGE_SIZE as usize
    }
}

/// Queue-level outcomes preserve whether any messages have already committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    InvalidConfig,
    InvalidPeer,
    CounterExhausted,
    Full,
    Empty,
    /// Graceful producer close, observed after draining its final publication.
    Closed,
    /// Lifetime peer closed without an observed graceful marker. Delivery of the
    /// last unobserved publication is unknown; this is not a clean EOF promise.
    PeerDied,
    MessageTooLarge {
        maximum: usize,
    },
    BufferTooSmall {
        required: usize,
    },
    System(crate::Error),
    Poisoned,
}
impl From<crate::Error> for QueueError {
    fn from(error: crate::Error) -> Self {
        Self::System(error)
    }
}
impl core::fmt::Display for QueueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "shared queue: {self:?}")
    }
}
impl core::error::Error for QueueError {}
impl QueueError {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::InvalidPeer | Self::CounterExhausted | Self::System(_) | Self::Poisoned
        )
    }
}

/// `completed` messages committed even if `stop` reports a notification failure.
/// Retry only the suffix. A notification/protocol failure closes the endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct BatchOutcome {
    pub completed: usize,
    pub stop: Option<QueueError>,
}

/// A private destination; only a successfully consumed message is exposed.
pub struct ReceiveSlot<'a> {
    buffer: &'a mut [u8],
    length: Option<usize>,
}
impl<'a> ReceiveSlot<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            length: None,
        }
    }
    pub fn message(&self) -> Option<&[u8]> {
        self.length.map(|length| &self.buffer[..length])
    }
}

/// Transfer these five capabilities before mapping. Keep geometry/version in the
/// surrounding protocol. Do not duplicate a role into concurrent local owners.
pub struct ProducerParts {
    pub config: Config,
    pub data: OwnedHandle<VmoObject>,
    pub control: OwnedHandle<VmoObject>,
    pub data_ready: Event,
    pub space_ready: Event,
    pub lifetime: OwnedHandle<ByteChannelObject>,
}
pub struct ConsumerParts {
    pub config: Config,
    pub data: OwnedHandle<VmoObject>,
    pub control: OwnedHandle<VmoObject>,
    pub data_ready: Event,
    pub space_ready: Event,
    pub lifetime: OwnedHandle<ByteChannelObject>,
}

/// Creates and populates all backing before exposing either endpoint. Each peer
/// has WRITE only on its own VMO. Failure drops all provisional capabilities.
pub fn create_pair(config: Config) -> crate::Result<(ProducerParts, ConsumerParts)> {
    let data = populated(config.data_bytes())?;
    let control = populated(PAGE_SIZE as usize)?;
    let read = Rights::READ
        .union(Rights::MAP)
        .union(Rights::INSPECT)
        .union(Rights::TRANSFER);
    let write = read.union(Rights::WRITE);
    let event_rights = Rights::WAIT
        .union(Rights::SIGNAL)
        .union(Rights::INSPECT)
        .union(Rights::TRANSFER);
    let notify_rights = Rights::SIGNAL
        .union(Rights::INSPECT)
        .union(Rights::TRANSFER);
    let data_ready = Event::create()?;
    let space_ready = Event::create()?;
    let (producer_life, consumer_life) = crate::channel::create_pair()?;
    let life_rights = Rights::WAIT.union(Rights::TRANSFER).union(Rights::INSPECT);
    let producer_life = producer_life
        .replace(life_rights)
        .map_err(|failure| match failure {
            crate::handle::ReplaceFailure::Rejected(failure) => failure.error(),
            crate::handle::ReplaceFailure::Committed(error) => error,
        })?;
    let consumer_life = consumer_life
        .replace(life_rights)
        .map_err(|failure| match failure {
            crate::handle::ReplaceFailure::Rejected(failure) => failure.error(),
            crate::handle::ReplaceFailure::Committed(error) => error,
        })?;
    Ok((
        ProducerParts {
            config,
            data: data.as_handle_ref().duplicate(write)?,
            control: control.as_handle_ref().duplicate(read)?,
            data_ready: Event::from_handle(data_ready.as_handle_ref().duplicate(notify_rights)?),
            space_ready: Event::from_handle(space_ready.as_handle_ref().duplicate(event_rights)?),
            lifetime: producer_life,
        },
        ConsumerParts {
            config,
            data: data.as_handle_ref().duplicate(read)?,
            control: control.as_handle_ref().duplicate(write)?,
            data_ready: Event::from_handle(data_ready.as_handle_ref().duplicate(event_rights)?),
            space_ready: Event::from_handle(space_ready.as_handle_ref().duplicate(notify_rights)?),
            lifetime: consumer_life,
        },
    ))
}

fn populated(bytes: usize) -> crate::Result<WritableVmo> {
    let vmo = WritableVmo::create(bytes as u64)?;
    let zeros = [0u8; PAGE_SIZE as usize];
    for offset in (0..bytes).step_by(zeros.len()) {
        vmo.write_all_at(offset as u64, &zeros)?;
    }
    Ok(vmo)
}

impl protocol::Words for mapping::AtomicWords {
    fn load(&self, index: usize, order: core::sync::atomic::Ordering) -> crate::Result<u64> {
        self.load(index, order)
    }
    fn store(
        &self,
        index: usize,
        value: u64,
        order: core::sync::atomic::Ordering,
    ) -> crate::Result<()> {
        self.store(index, value, order)
    }
}

#[cfg(test)]
#[path = "../tests/shared_queue.rs"]
mod tests;
