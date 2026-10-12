// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use crate::Status;

/// Failure reported by the safe Native OS binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The kernel rejected an otherwise well-formed Native operation.
    Status(Status),
    /// The installed kernel does not implement the SDK's required ABI.
    UnsupportedAbi { revision: u64, features: u64 },
    /// A trusted runtime or kernel response violated the Native ABI contract.
    InvalidResponse,
    /// One channel message exceeded the receiving binding's bounded storage.
    MessageTooLarge { bytes: u64, handles: u64 },
    /// A MOVE source option did not contain an owned handle.
    MissingHandle,
    /// A receive slot still owns a capability from an earlier message.
    OccupiedReceiveSlot,
    /// Capability dispositions repeated a source or violated local metadata.
    InvalidCapabilityDisposition,
    /// The runtime did not provide a valid parsed startup record.
    InvalidStartup,
    /// A typed capability did not identify the object kind its contract names.
    UnexpectedObjectKind { expected: u32, actual: u32 },
    /// A `Directory` path was empty, too long, or contained an embedded NUL byte.
    InvalidPath,
    /// A requested file range cannot be represented by the Native ABI.
    OffsetOverflow,
    /// An exact file read reached the immutable end of the file early.
    UnexpectedEndOfFile {
        completed: usize,
        expected: usize,
        file_size: u64,
    },
    /// A process name violated the Native builder contract.
    InvalidProcessName,
    /// One argv entry exceeded its bound or contained an embedded NUL byte.
    InvalidProcessArgument,
    /// One environment entry was not a bounded `name=value` string.
    InvalidProcessEnvironment,
    /// A CPU affinity bitmap was empty or exceeded the ABI bound.
    InvalidProcessAffinity,
    /// A multi-object wait was empty or exceeded the ABI item bound.
    InvalidWaitSet,
    /// A relative duration cannot form a finite absolute monotonic deadline.
    DeadlineOverflow,
    /// A VMO size or transfer range was empty, unaligned, or out of bounds.
    InvalidMemoryRange,
}

pub type Result<T> = core::result::Result<T, Error>;

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for Error {}
