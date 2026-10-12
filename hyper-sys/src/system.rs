// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! ABI discovery and system clocks.

use crate::ffi::{ffi_abi_query, ffi_clock_get_monotonic, ffi_native_call6};
use crate::{CallResult, abi};

/// Queries the Native ABI revision and feature mask.
///
/// # Safety
///
/// The caller must be executing as a `HypeR` Native process through the runtime
/// and syscall veneer installed with this crate.
#[inline]
pub unsafe fn abi_query() -> CallResult {
    // SAFETY: the caller establishes the Native runtime and syscall contract.
    unsafe { ffi_abi_query() }
}

/// Queries a public scalar system configuration item.
///
/// # Safety
/// The caller must execute as a Native process with the matching syscall veneer.
#[inline]
pub unsafe fn system_config(key: u64) -> CallResult {
    // SAFETY: caller establishes the Native execution contract; no pointers.
    unsafe { ffi_native_call6(abi::HYPER_NATIVE_SYS_SYSTEM_CONFIG, key, 0, 0, 0, 0, 0) }
}

/// Reads absolute nanoseconds from the kernel monotonic clock domain.
///
/// # Safety
///
/// The caller must be executing as a `HypeR` Native process through the runtime
/// and syscall veneer installed with this crate.
#[inline]
pub unsafe fn clock_get_monotonic() -> CallResult {
    // SAFETY: the caller establishes the Native runtime and syscall contract.
    unsafe { ffi_clock_get_monotonic() }
}

/// Invokes Native `clock_get_realtime`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn clock_get_realtime() -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe { ffi_native_call6(abi::HYPER_NATIVE_SYS_CLOCK_GET_REALTIME, 0, 0, 0, 0, 0, 0) }
}
