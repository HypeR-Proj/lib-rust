// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Safe handle-free `ByteChannel` message transport.

pub use crate::relay::ByteRelay;

use crate::handle::{ByteChannelObject, HandleRef, OwnedHandle};
use crate::{Error, Result, Status};

const _: () = assert!(hyper_abi::HYPER_NATIVE_BYTE_CHANNEL_MAX_MESSAGE_BYTES <= usize::MAX as u64);
/// Maximum payload carried by one byte-channel message.
pub const MAX_MESSAGE_BYTES: usize =
    hyper_abi::HYPER_NATIVE_BYTE_CHANNEL_MAX_MESSAGE_BYTES as usize;

/// Creates a connected pair of exclusively owned byte-channel endpoints.
pub fn create_pair() -> Result<(
    OwnedHandle<ByteChannelObject>,
    OwnedHandle<ByteChannelObject>,
)> {
    // SAFETY: this safe layer validates and assumes ownership of both
    // successful results before exposing them.
    let result = raw_create_pair();
    Status::from_raw(result.status).into_result()?;
    // SAFETY: an OK BYTE_CHANNEL_CREATE result transfers ownership of every
    // distinct nonzero output, including malformed output pairs.
    unsafe { crate::handle::adopt_produced_handle_pair([result.value0, result.value1]) }
}

#[cfg(not(test))]
fn raw_create_pair() -> hyper_sys::CallResult {
    // SAFETY: `create_pair` assumes ownership of every successful result.
    unsafe { hyper_sys::byte_channel_create() }
}

#[cfg(test)]
fn raw_create_pair() -> hyper_sys::CallResult {
    hyper_sys::CallResult {
        status: hyper_abi::HYPER_NATIVE_STATUS_OK,
        value0: u64::from(hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL),
        value1: u64::from(hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL) + 256,
    }
}

/// Borrowed `ByteChannel` endpoint supplied by process startup.
///
/// This initial binding deliberately does not expose capability transfer. A
/// message sent through this type contains bytes only, so receiving it never
/// creates hidden handle ownership.
pub struct ByteChannel<'owner> {
    handle: HandleRef<'owner, ByteChannelObject>,
}

impl<'owner> ByteChannel<'owner> {
    pub(crate) const fn from_handle(handle: HandleRef<'owner, ByteChannelObject>) -> Self {
        Self { handle }
    }

    /// Returns the borrowed endpoint authority for typed multi-object waits.
    #[must_use]
    pub const fn as_handle_ref(&self) -> HandleRef<'owner, ByteChannelObject> {
        self.handle
    }

    /// Sends one complete message, waiting while peer capacity is exhausted.
    pub fn send(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::MessageTooLarge {
                bytes: bytes.len() as u64,
                handles: 0,
            });
        }
        loop {
            match self.try_send(bytes) {
                Ok(()) => return Ok(()),
                Err(Error::Status(Status::WOULD_BLOCK)) => {
                    if self.wait_writable()? == WaitOutcome::PeerClosed {
                        return Err(Error::Status(Status::PEER_CLOSED));
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Attempts to send one complete message without waiting for capacity.
    pub fn try_send(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::MessageTooLarge {
                bytes: bytes.len() as u64,
                handles: 0,
            });
        }
        // SAFETY: the owner borrow keeps the endpoint live, and `bytes`
        // remains readable for the complete non-retaining syscall.
        Status::from_raw(unsafe {
            hyper_sys::byte_channel_write(self.handle.raw().get(), bytes.as_ptr(), bytes.len())
        })
        .into_result()
    }

    /// Receives one complete handle-free message, waiting until one arrives.
    pub fn receive(&self, bytes: &mut [u8]) -> Result<usize> {
        loop {
            match self.try_receive(bytes) {
                Ok(actual) => return Ok(actual),
                Err(Error::Status(Status::WOULD_BLOCK)) => {
                    if self.wait_readable()? == WaitOutcome::PeerClosed {
                        return Err(Error::Status(Status::PEER_CLOSED));
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Attempts to receive one complete message without waiting.
    pub fn try_receive(&self, bytes: &mut [u8]) -> Result<usize> {
        let capacity = bytes.len().min(MAX_MESSAGE_BYTES);
        // SAFETY: the owner borrow keeps the endpoint live, and `bytes` is
        // uniquely writable for `capacity` bytes during the call.
        let result = unsafe {
            hyper_sys::byte_channel_read(self.handle.raw().get(), bytes.as_mut_ptr(), capacity)
        };
        match Status::from_raw(result.status) {
            Status::OK => {
                let actual = usize::try_from(result.value0).map_err(|_| Error::InvalidResponse)?;
                if actual > capacity || result.value1 != 0 {
                    return Err(Error::InvalidResponse);
                }
                Ok(actual)
            }
            Status::BUFFER_TOO_SMALL => Err(Error::MessageTooLarge {
                bytes: result.value0,
                handles: result.value1,
            }),
            failure => Err(Error::Status(failure)),
        }
    }

    fn wait_readable(&self) -> Result<WaitOutcome> {
        self.wait_for(hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_READABLE)
    }

    fn wait_writable(&self) -> Result<WaitOutcome> {
        self.wait_for(hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_WRITABLE)
    }

    fn wait_for(&self, desired: u64) -> Result<WaitOutcome> {
        let awaited = desired | hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_PEER_CLOSED;
        // SAFETY: the startup borrow retains this waitable endpoint throughout
        // the call.
        let result = unsafe {
            hyper_sys::object_wait_one(
                self.handle.raw().get(),
                awaited,
                hyper_abi::HYPER_NATIVE_DEADLINE_INFINITE,
            )
        };
        Status::from_raw(result.status).into_result()?;
        classify_wait(result.value0, desired)
    }
}

impl OwnedHandle<ByteChannelObject> {
    /// Borrows this owned endpoint as a byte-message channel.
    #[must_use]
    pub fn as_byte_channel(&self) -> ByteChannel<'_> {
        ByteChannel::from_handle(self.as_handle_ref())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaitOutcome {
    Desired,
    PeerClosed,
}

fn classify_wait(observed: u64, desired: u64) -> Result<WaitOutcome> {
    if observed & desired == desired {
        // READABLE wins over PEER_CLOSED so a receiver drains queued data.
        // A sender simply retries and obtains the definitive write status.
        Ok(WaitOutcome::Desired)
    } else if observed & hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_PEER_CLOSED != 0 {
        Ok(WaitOutcome::PeerClosed)
    } else {
        Err(Error::InvalidResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::{WaitOutcome, classify_wait, create_pair};
    use crate::Error;

    #[test]
    fn peer_close_terminates_a_wait_without_the_desired_signal() {
        let peer_closed = hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_PEER_CLOSED;
        let readable = hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_READABLE;
        assert_eq!(
            classify_wait(peer_closed, readable),
            Ok(WaitOutcome::PeerClosed)
        );
    }

    #[test]
    fn readable_data_wins_when_peer_close_is_observed_together() {
        let peer_closed = hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_PEER_CLOSED;
        let readable = hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_READABLE;
        assert_eq!(
            classify_wait(peer_closed | readable, readable),
            Ok(WaitOutcome::Desired)
        );
    }

    #[test]
    fn unrelated_wake_is_rejected_as_a_kernel_protocol_violation() {
        let readable = hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_READABLE;
        assert_eq!(classify_wait(0, readable), Err(Error::InvalidResponse));
    }

    #[test]
    fn pair_creation_returns_distinct_exclusive_owners() -> crate::Result<()> {
        let (first, second) = create_pair()?;
        assert_ne!(first.as_handle_ref().raw(), second.as_handle_ref().raw());
        Ok(())
    }
}
