// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Bounded, nonblocking forwarding between byte channels.

use crate::channel::ByteChannel;
use crate::handle::ByteChannelObject;
use crate::wait::{ObjectSignals, WaitItem};
use crate::{Error, Result, Status};

/// One direction of a multiplexed byte-channel relay.
///
/// The caller supplies storage for one complete message and retains both
/// endpoints. A pending message is never overwritten or partially forwarded.
/// Use a buffer of `channel::MAX_MESSAGE_BYTES` to accept every valid message.
/// Readiness is advisory: `poll` never blocks, even after an obsolete signal.
/// The owner must continue servicing its other directions while this relay
/// waits for input or destination capacity.
pub struct ByteRelay<'owner> {
    source: ByteChannel<'owner>,
    destination: ByteChannel<'owner>,
    buffer: &'owner mut [u8],
    pending: Option<usize>,
    finished: bool,
}

impl<'owner> ByteRelay<'owner> {
    #[must_use]
    pub fn new(
        source: ByteChannel<'owner>,
        destination: ByteChannel<'owner>,
        buffer: &'owner mut [u8],
    ) -> Self {
        Self {
            source,
            destination,
            buffer,
            pending: None,
            finished: false,
        }
    }

    /// Performs at most one nonblocking read or write.
    ///
    /// Returns whether progress occurred. Source EOF is successful completion,
    /// after queued messages drain; a closed destination is an error. The caller
    /// decides whether completion closes any other endpoint.
    pub fn poll(&mut self) -> Result<bool> {
        if self.finished {
            return Ok(false);
        }
        if let Some(length) = self.pending {
            return match self.destination.try_send(&self.buffer[..length]) {
                Ok(()) => {
                    self.pending = None;
                    Ok(true)
                }
                Err(Error::Status(Status::WOULD_BLOCK)) => Ok(false),
                Err(error) => Err(error),
            };
        }
        match self.source.try_receive(self.buffer) {
            Ok(length) => {
                self.pending = Some(length);
                Ok(true)
            }
            Err(Error::Status(Status::WOULD_BLOCK)) => Ok(false),
            Err(Error::Status(Status::PEER_CLOSED)) => {
                self.finished = true;
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    /// Returns the next input/capacity condition, or `None` after source EOF.
    #[must_use]
    pub fn wait_item(&self) -> Option<WaitItem<'owner>> {
        if self.finished {
            return None;
        }
        let (handle, desired) = if self.pending.is_some() {
            (
                self.destination.as_handle_ref(),
                ObjectSignals::<ByteChannelObject>::WRITABLE,
            )
        } else {
            (
                self.source.as_handle_ref(),
                ObjectSignals::<ByteChannelObject>::READABLE,
            )
        };
        Some(WaitItem::new(
            handle,
            desired.union(ObjectSignals::<ByteChannelObject>::PEER_CLOSED),
        ))
    }

    /// Reports whether a received message still needs destination capacity.
    #[must_use]
    pub const fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }
}
