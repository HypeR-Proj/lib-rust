// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Capability handle ownership and object identity.

use crate::ffi::{ffi_handle_close, ffi_native_call6};
use crate::{CallResult, abi};

/// Closes one raw process handle.
///
/// # Safety
///
/// The caller must exclusively own `handle` and must prevent every subsequent
/// use of that value, including use through safe wrappers.
#[inline]
pub unsafe fn handle_close(handle: abi::HyperNativeHandle) -> abi::HyperNativeStatus {
    // SAFETY: the caller owns the raw capability and its close transition.
    unsafe { ffi_handle_close(handle) }
}

/// Duplicates one raw process handle with attenuated rights.
///
/// # Safety
///
/// `source` must remain live for the call. The caller assumes exclusive
/// ownership of a nonzero handle returned in `value0` only when the status is
/// `OK`.
#[inline]
pub unsafe fn handle_duplicate(source: abi::HyperNativeHandle, rights: u64) -> CallResult {
    // SAFETY: the caller establishes the source-handle lifetime and ownership
    // contract for the returned value.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_HANDLE_DUPLICATE,
            source,
            rights,
            0,
            0,
            0,
            0,
        )
    }
}

/// Replaces one raw process handle with an attenuated value.
///
/// # Safety
///
/// The caller must exclusively own `source`. An `OK` result consumes it and
/// transfers exclusive ownership of the nonzero `value0` handle to the caller;
/// every failure preserves ownership of `source`.
#[inline]
pub unsafe fn handle_replace(source: abi::HyperNativeHandle, rights: u64) -> CallResult {
    // SAFETY: the caller owns the source's consume-on-success transition.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_HANDLE_REPLACE,
            source,
            rights,
            0,
            0,
            0,
            0,
        )
    }
}

/// Retrieves handle-local metadata into one ABI record.
///
/// # Safety
///
/// `handle` must remain live during the call and `info` must be aligned and
/// writable for one complete [`abi::HyperNativeHandleInfo`] record.
#[inline]
pub unsafe fn handle_get_info(
    handle: abi::HyperNativeHandle,
    info: *mut abi::HyperNativeHandleInfo,
) -> CallResult {
    // SAFETY: the caller establishes both handle and output-pointer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_HANDLE_GET_INFO,
            handle,
            info.addr() as u64,
            core::mem::size_of::<abi::HyperNativeHandleInfo>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Retrieves object identity and kind into one ABI record.
///
/// # Safety
///
/// `handle` must remain live during the call and carry `INSPECT` rights.
/// `info` must be aligned and writable for one complete
/// [`abi::HyperNativeObjectBasicInfo`] record.
#[inline]
pub unsafe fn object_get_basic_info(
    handle: abi::HyperNativeHandle,
    info: *mut abi::HyperNativeObjectBasicInfo,
) -> CallResult {
    // SAFETY: the caller establishes both handle and output-pointer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_OBJECT_GET_BASIC_INFO,
            handle,
            info.addr() as u64,
            core::mem::size_of::<abi::HyperNativeObjectBasicInfo>() as u64,
            0,
            0,
            0,
        )
    }
}
