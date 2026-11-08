// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Manually signalled Native Event objects.

use crate::{CallResult, abi, ffi};

/// Creates an initially clear Event with the standard constructor rights.
///
/// # Safety
/// On success the caller must adopt the unique handle returned in `value0`.
pub unsafe fn event_create() -> CallResult {
    // SAFETY: the caller adopts the returned owner; all reserved arguments are zero.
    unsafe {
        ffi::ffi_native_invoke6(
            ffi::ffi_native_object_factory(),
            abi::HYPER_NATIVE_OP_EVENT_CREATE,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Atomically clears and asserts Event signals. Overlapping masks are rejected.
///
/// # Safety
/// `event` must remain a live Event handle throughout the invocation.
pub unsafe fn event_signal(
    event: abi::HyperNativeHandle,
    clear: u64,
    set: u64,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller retains the borrowed Event for this non-retaining call.
    unsafe {
        ffi::ffi_native_invoke6(
            event,
            abi::HYPER_NATIVE_OP_EVENT_SIGNAL,
            clear,
            set,
            0,
            0,
            0,
            0,
        )
        .status
    }
}
