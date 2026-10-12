// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use crate::{Error, Result};

/// One status value returned by the `HypeR` Native ABI.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status(hyper_abi::HyperNativeStatus);

impl Status {
    pub const OK: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_OK);
    pub const INVALID_ARGUMENT: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_INVALID_ARGUMENT);
    pub const BAD_HANDLE: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_BAD_HANDLE);
    pub const ACCESS_DENIED: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_ACCESS_DENIED);
    pub const NOT_SUPPORTED: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_NOT_SUPPORTED);
    pub const NO_MEMORY: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_NO_MEMORY);
    pub const BAD_STATE: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_BAD_STATE);
    pub const FAULT: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_FAULT);
    pub const RESOURCE_LIMIT: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_RESOURCE_LIMIT);
    pub const BUSY: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_BUSY);
    pub const INTERNAL: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_INTERNAL);
    pub const TIMED_OUT: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_TIMED_OUT);
    pub const CANCELLED: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_CANCELLED);
    pub const WOULD_BLOCK: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_WOULD_BLOCK);
    pub const BUFFER_TOO_SMALL: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_BUFFER_TOO_SMALL);
    pub const PEER_CLOSED: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_PEER_CLOSED);
    pub const ALREADY_EXISTS: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_ALREADY_EXISTS);
    pub const NOT_EMPTY: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_NOT_EMPTY);
    pub const NOT_FOUND: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_NOT_FOUND);

    pub const NOT_DIRECTORY: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_NOT_DIRECTORY);
    pub const IS_DIRECTORY: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_IS_DIRECTORY);
    pub const SYMLINK_LOOP: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_SYMLINK_LOOP);
    pub const IO_ERROR: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_IO_ERROR);
    pub const NO_SPACE: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_NO_SPACE);
    pub const READ_ONLY: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_READ_ONLY);
    pub const CROSS_DEVICE: Self = Self(hyper_abi::HYPER_NATIVE_STATUS_CROSS_DEVICE);

    #[must_use]
    pub const fn from_raw(raw: hyper_abi::HyperNativeStatus) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn as_raw(self) -> hyper_abi::HyperNativeStatus {
        self.0
    }

    pub(crate) fn into_result(self) -> Result<()> {
        if self == Self::OK {
            Ok(())
        } else {
            Err(Error::Status(self))
        }
    }
}
