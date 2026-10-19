// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Raw supervisor-controlled diagnostic retention operations.

use crate::{CallResult, abi, ffi::ffi_native_invoke6};

/// Returns a linear retirement controller for a not-yet-started child.
///
/// # Safety
/// The builder must remain live with WRITE and `RETAIN_PROCESS`. Success transfers the returned control handle to the caller.
pub unsafe fn process_builder_retain(builder: u64, max_bytes: u64, timeout_ns: u64) -> CallResult {
    // SAFETY: The caller retains the required live capabilities.
    unsafe {
        ffi_native_invoke6(
            builder,
            abi::HYPER_NATIVE_OP_PROCESS_BUILDER_RETAIN,
            max_bytes,
            timeout_ns,
            0,
            0,
            0,
            0,
        )
    }
}

/// Opens a revocable diagnostic view after the stopped scene is ready.
///
/// # Safety
/// The controller must remain live with `INSPECT_DETAILS`. Success transfers the returned view handle to the caller.
pub unsafe fn process_retirement_open_view(control: u64) -> CallResult {
    // SAFETY: The caller retains the required live capabilities.
    unsafe {
        ffi_native_invoke6(
            control,
            abi::HYPER_NATIVE_OP_PROCESS_RETIREMENT_OPEN_VIEW,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Permanently permits cleanup; repeated release is harmless.
///
/// # Safety
/// The controller must remain live with RETIRE for this call.
pub unsafe fn process_retirement_release(control: u64) -> CallResult {
    // SAFETY: The caller retains the required live capabilities.
    unsafe {
        ffi_native_invoke6(
            control,
            abi::HYPER_NATIVE_OP_PROCESS_RETIREMENT_RELEASE,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Copies one bounded diagnostic record without faulting in target memory.
///
/// # Safety
/// `handle` must remain live with the required inspection rights and `output`
/// must be aligned and writable for one complete ABI record.
pub unsafe fn process_retirement_get_info(
    handle: u64,
    output: *mut abi::HyperNativeProcessRetirementInfo,
) -> CallResult {
    // SAFETY: The caller supplies the live handle and writable record.
    unsafe {
        ffi_native_invoke6(
            handle,
            abi::HYPER_NATIVE_OP_PROCESS_RETIREMENT_GET_INFO,
            output.addr() as u64,
            core::mem::size_of::<abi::HyperNativeProcessRetirementInfo>() as u64,
            0,
            0,
            0,
            0,
        )
    }
}

/// Copies one bounded diagnostic record without faulting in target memory.
///
/// # Safety
/// `handle` must remain live with the required inspection rights and `output`
/// must be aligned and writable for one complete ABI record.
pub unsafe fn crash_view_get_info(
    handle: u64,
    output: *mut abi::HyperNativeProcessRetirementInfo,
) -> CallResult {
    // SAFETY: The caller supplies the live handle and writable record.
    unsafe {
        ffi_native_invoke6(
            handle,
            abi::HYPER_NATIVE_OP_CRASH_VIEW_GET_INFO,
            output.addr() as u64,
            core::mem::size_of::<abi::HyperNativeProcessRetirementInfo>() as u64,
            0,
            0,
            0,
            0,
        )
    }
}

/// Copies one bounded diagnostic record without faulting in target memory.
///
/// # Safety
/// `handle` must remain live with the required inspection rights and `output`
/// must be aligned and writable for one complete ABI record.
pub unsafe fn crash_view_thread(
    handle: u64,
    index: u64,
    output: *mut abi::HyperNativeCrashThread,
) -> CallResult {
    // SAFETY: The caller supplies the live handle and writable record.
    unsafe {
        ffi_native_invoke6(
            handle,
            abi::HYPER_NATIVE_OP_CRASH_VIEW_THREAD,
            index,
            output.addr() as u64,
            core::mem::size_of::<abi::HyperNativeCrashThread>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Copies one bounded diagnostic record without faulting in target memory.
///
/// # Safety
/// `handle` must remain live with the required inspection rights and `output`
/// must be aligned and writable for one complete ABI record.
pub unsafe fn crash_view_mapping(
    handle: u64,
    index: u64,
    output: *mut abi::HyperNativeCrashMapping,
) -> CallResult {
    // SAFETY: The caller supplies the live handle and writable record.
    unsafe {
        ffi_native_invoke6(
            handle,
            abi::HYPER_NATIVE_OP_CRASH_VIEW_MAPPING,
            index,
            output.addr() as u64,
            core::mem::size_of::<abi::HyperNativeCrashMapping>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Copies one bounded diagnostic record without faulting in target memory.
///
/// # Safety
/// `handle` must remain live with the required inspection rights and `output`
/// must be aligned and writable for one complete ABI record.
pub unsafe fn crash_view_handle(
    handle: u64,
    index: u64,
    output: *mut abi::HyperNativeCrashHandle,
) -> CallResult {
    // SAFETY: The caller supplies the live handle and writable record.
    unsafe {
        ffi_native_invoke6(
            handle,
            abi::HYPER_NATIVE_OP_CRASH_VIEW_HANDLE,
            index,
            output.addr() as u64,
            core::mem::size_of::<abi::HyperNativeCrashHandle>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Reads retained private resident bytes; never requests target page-in.
///
/// # Safety
/// `view` must remain live with READ. `output` must be writable for `length`
/// bytes, with length at most `CRASH_READ_MAX_BYTES`.
pub unsafe fn crash_view_read(
    view: u64,
    address: u64,
    output: *mut u8,
    length: usize,
) -> CallResult {
    // SAFETY: The caller supplies the capability and writable slice.
    unsafe {
        ffi_native_invoke6(
            view,
            abi::HYPER_NATIVE_OP_CRASH_VIEW_READ,
            address,
            output.addr() as u64,
            length as u64,
            0,
            0,
            0,
        )
    }
}
