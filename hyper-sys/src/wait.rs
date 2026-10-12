// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Signal waits, wait sets, and atomic-address synchronization.

use crate::ffi::{ffi_atomic_wait, ffi_atomic_wake, ffi_native_call6, ffi_object_wait_one};
use crate::{CallResult, abi};

/// Waits for signals on one raw process handle.
///
/// # Safety
///
/// `object` must remain a live waitable handle for the duration of the call.
#[inline]
pub unsafe fn object_wait_one(
    object: abi::HyperNativeHandle,
    signals: u64,
    deadline: u64,
) -> CallResult {
    // SAFETY: the caller keeps the raw handle live across the syscall.
    unsafe { ffi_object_wait_one(object, signals, deadline) }
}

/// Waits for one member of a raw object-wait array.
///
/// # Safety
///
/// Every record must contain a live handle with wait rights and a valid signal
/// mask for that object's kind. `items` must remain readable for `item_count`
/// complete records throughout the call.
#[inline]
pub unsafe fn object_wait_many(
    items: *const abi::HyperNativeObjectWaitItem,
    item_count: usize,
    deadline: u64,
) -> CallResult {
    // SAFETY: the caller establishes the array and borrowed-handle contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_OBJECT_WAIT_MANY,
            items.addr() as u64,
            item_count as u64,
            deadline,
            0,
            0,
            0,
        )
    }
}

/// Invokes Native `atomic_wait`.
///
/// # Safety
/// Handles, addresses and thread entry state must satisfy the Native ABI;
/// referenced memory must remain live through the operation or thread lifetime.
pub unsafe fn atomic_wait(
    address: *const u32,
    expected: u32,
    deadline: u64,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller upholds the raw syscall contract.
    unsafe { ffi_atomic_wait(address, expected, deadline) }
}

/// Invokes Native `atomic_wake`.
///
/// # Safety
/// Handles, addresses and thread entry state must satisfy the Native ABI;
/// referenced memory must remain live through the operation or thread lifetime.
pub unsafe fn atomic_wake(address: *const u32, count: u32) -> CallResult {
    // SAFETY: the caller upholds the raw syscall contract.
    unsafe { ffi_atomic_wake(address, count) }
}

/// Creates a `WaitSet` and transfers exclusive ownership of the returned handle.
///
/// # Safety
///
/// Every borrowed handle must remain live with the required rights.
pub unsafe fn wait_set_create(capacity: usize) -> CallResult {
    // SAFETY: the caller establishes handle validity and output ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_WAIT_SET_CREATE,
            capacity as u64,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Invokes Native `wait_set_add`.
///
/// # Safety
///
/// Every borrowed handle must remain live with the required rights.
pub unsafe fn wait_set_add(
    set: abi::HyperNativeHandle,
    source: abi::HyperNativeHandle,
    signals: u64,
) -> CallResult {
    // SAFETY: the caller establishes handle validity and output ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_WAIT_SET_ADD,
            set,
            source,
            signals,
            0,
            0,
            0,
        )
    }
}

/// Invokes Native `wait_set_rearm`.
///
/// # Safety
///
/// Every borrowed handle must remain live with the required rights.
pub unsafe fn wait_set_rearm(set: abi::HyperNativeHandle, registration: u64) -> CallResult {
    // SAFETY: the caller establishes handle validity and output ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_WAIT_SET_REARM,
            set,
            registration,
            0,
            0,
            0,
            0,
        )
    }
}

/// Invokes Native `wait_set_remove`.
///
/// # Safety
///
/// Every borrowed handle must remain live with the required rights.
pub unsafe fn wait_set_remove(set: abi::HyperNativeHandle, registration: u64) -> CallResult {
    // SAFETY: the caller establishes handle validity and output ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_WAIT_SET_REMOVE,
            set,
            registration,
            0,
            0,
            0,
            0,
        )
    }
}

/// Invokes Native `wait_set_wait`.
///
/// # Safety
///
/// The handle must remain live and output must be writable for `output_size` bytes.
pub unsafe fn wait_set_wait(
    set: abi::HyperNativeHandle,
    deadline: u64,
    output: *mut u8,
    output_size: usize,
) -> CallResult {
    // SAFETY: the caller pins the handle and provides writable output storage.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_WAIT_SET_WAIT,
            set,
            deadline,
            output as u64,
            output_size as u64,
            0,
            0,
        )
    }
}
