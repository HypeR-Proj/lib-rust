// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Scheduling operations retain the target handle as the invocation receiver.

use crate::{abi, ffi::ffi_native_invoke6};

/// Reads the current thread's scheduling configuration.
/// # Safety
/// Output must be a writable complete record for the duration of the call.
pub unsafe fn thread_get_current_scheduling(
    output: *mut abi::HyperNativeSchedulingParameters,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller supplies the valid output record.
    unsafe {
        ffi_native_invoke6(
            crate::ffi::ffi_native_execution_context(),
            abi::HYPER_NATIVE_OP_THREAD_GET_CURRENT_SCHEDULING,
            output as u64,
            0,
            0,
            0,
            0,
            0,
        )
        .status
    }
}
/// Changes only the calling thread, subject to its execution-context grant.
/// # Safety
/// Input must be a readable complete record for the duration of the call.
pub unsafe fn thread_set_current_scheduling(
    input: *const abi::HyperNativeSchedulingParameters,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller supplies the valid input record.
    unsafe {
        ffi_native_invoke6(
            crate::ffi::ffi_native_execution_context(),
            abi::HYPER_NATIVE_OP_THREAD_SET_CURRENT_SCHEDULING,
            input as u64,
            0,
            0,
            0,
            0,
            0,
        )
        .status
    }
}
macro_rules! scheduling_operations {
    ($get:ident, $set:ident, $get_op:ident, $set_op:ident) => {
        /// Reads scheduling configuration through INSPECT authority.
        /// # Safety
        /// The handle must remain live and output must identify a writable record.
        pub unsafe fn $get(
            handle: abi::HyperNativeHandle,
            output: *mut abi::HyperNativeSchedulingParameters,
        ) -> abi::HyperNativeStatus {
            // SAFETY: the caller supplies the live handle and writable record.
            unsafe { ffi_native_invoke6(handle, abi::$get_op, output as u64, 0, 0, 0, 0, 0).status }
        }
        /// Atomically changes configuration under the target's scheduling rights.
        /// # Safety
        /// The handle must remain live and input must identify a readable record.
        pub unsafe fn $set(
            handle: abi::HyperNativeHandle,
            input: *const abi::HyperNativeSchedulingParameters,
        ) -> abi::HyperNativeStatus {
            // SAFETY: the caller supplies the live handle and readable record.
            unsafe { ffi_native_invoke6(handle, abi::$set_op, input as u64, 0, 0, 0, 0, 0).status }
        }
    };
}
scheduling_operations!(
    thread_get_scheduling,
    thread_set_scheduling,
    HYPER_NATIVE_OP_THREAD_GET_SCHEDULING,
    HYPER_NATIVE_OP_THREAD_SET_SCHEDULING
);
scheduling_operations!(
    virtual_cpu_get_scheduling,
    virtual_cpu_set_scheduling,
    HYPER_NATIVE_OP_VIRTUAL_CPU_GET_SCHEDULING,
    HYPER_NATIVE_OP_VIRTUAL_CPU_SET_SCHEDULING
);

/// Sets the child's initial configuration and explicitly delegated scheduling rights.
/// # Safety
/// Builder must remain live and input must identify a readable complete record.
pub unsafe fn process_builder_set_scheduling(
    builder: abi::HyperNativeHandle,
    input: *const abi::HyperNativeSchedulingParameters,
    delegated_rights: u64,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller supplies the live builder and readable record.
    unsafe {
        ffi_native_invoke6(
            builder,
            abi::HYPER_NATIVE_OP_PROCESS_BUILDER_SET_SCHEDULING,
            input as u64,
            delegated_rights,
            0,
            0,
            0,
            0,
        )
        .status
    }
}
