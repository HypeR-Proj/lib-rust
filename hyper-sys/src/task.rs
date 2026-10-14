// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Process construction, resource domains, and thread lifecycle.

use crate::ffi::{
    ffi_native_call6, ffi_process_exit, ffi_thread_create, ffi_thread_exit,
    ffi_thread_request_stop, ffi_thread_sleep, ffi_thread_start, ffi_thread_yield,
};
use crate::{CallResult, abi};

/// Creates an independently accounted child resource domain.
///
/// # Safety
///
/// `parent` must remain live with create-resource-domain rights and `limits`
/// must identify one readable ABI limits record. On success, the caller owns
/// the returned nonzero handle in `value0`.
#[inline]
pub unsafe fn resource_domain_create(
    parent: abi::HyperNativeHandle,
    limits: *const abi::HyperNativeResourceLimits,
) -> CallResult {
    // SAFETY: the caller establishes the borrowed input and output ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_RESOURCE_DOMAIN_CREATE,
            parent,
            limits as u64,
            core::mem::size_of::<abi::HyperNativeResourceLimits>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Creates a task group charged to `resource_domain`.
///
/// # Safety
///
/// Both input handles must remain live with their required rights. On
/// success, the caller owns the returned nonzero handle in `value0`.
#[inline]
pub unsafe fn task_group_create(
    factory: abi::HyperNativeHandle,
    resource_domain: abi::HyperNativeHandle,
) -> CallResult {
    // SAFETY: the caller establishes borrowed inputs and output ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_TASK_GROUP_CREATE,
            factory,
            resource_domain,
            0,
            0,
            0,
            0,
        )
    }
}

/// Derives a wait-only Process observer.
///
/// # Safety
///
/// `handle` must remain live with wait, transfer and request-stop rights for this call.
/// Successful observer derivation transfers ownership of the returned handle.
#[inline]
pub unsafe fn process_derive_observer(handle: abi::HyperNativeHandle) -> CallResult {
    // SAFETY: the caller establishes the live capability contract.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_DERIVE_OBSERVER,
            handle,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Requests stop for all members of a task group.
///
/// # Safety
///
/// `handle` must remain live with request-stop rights for this call.
/// Successful observer derivation transfers ownership of the returned handle.
#[inline]
pub unsafe fn task_group_request_stop(handle: abi::HyperNativeHandle) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the live capability contract.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_TASK_GROUP_REQUEST_STOP,
            handle,
            0,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Retrieves terminal and lifecycle information for one raw Process handle.
///
/// # Safety
///
/// `process` must remain live with inspect rights. `info` must be aligned and
/// writable for one complete process-info record.
#[inline]
pub unsafe fn process_get_info(
    process: abi::HyperNativeHandle,
    info: *mut abi::HyperNativeProcessInfo,
) -> CallResult {
    // SAFETY: the caller establishes the handle and output-pointer contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_GET_INFO,
            process,
            info.addr() as u64,
            core::mem::size_of::<abi::HyperNativeProcessInfo>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Creates a mutable process builder from five borrowed authorities.
///
/// # Safety
///
/// Every input handle must remain live for the call and satisfy its exact ABI
/// kind and rights contract. On `OK`, the caller exclusively owns the nonzero
/// builder handle returned in `value0`.
#[inline]
pub unsafe fn process_builder_create(
    factory: abi::HyperNativeHandle,
    group: abi::HyperNativeHandle,
    domain: abi::HyperNativeHandle,
    executable: abi::HyperNativeHandle,
    loader: abi::HyperNativeHandle,
) -> CallResult {
    // SAFETY: the caller establishes all borrowed authority and result-owner
    // contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_BUILDER_CREATE,
            factory,
            group,
            domain,
            executable,
            loader,
            0,
        )
    }
}

/// Sets the builder's process/thread name.
///
/// # Safety
///
/// `builder` must remain live with write rights and `name` must remain readable
/// for `name_size` bytes.
#[inline]
pub unsafe fn process_builder_set_name(
    builder: abi::HyperNativeHandle,
    name: *const u8,
    name_size: usize,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the handle and buffer contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_BUILDER_SET_NAME,
            builder,
            name.addr() as u64,
            name_size as u64,
            0,
            0,
            0,
        )
        .status
    }
}

/// Replaces the builder's bounded opaque userspace startup payload.
///
/// # Safety
/// `builder` must remain live with WRITE rights; `data` must be readable for `size` bytes.
#[inline]
pub unsafe fn process_builder_set_data(
    builder: abi::HyperNativeHandle,
    data: *const u8,
    size: usize,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes handle and input-buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_BUILDER_SET_DATA,
            builder,
            data.addr() as u64,
            size as u64,
            0,
            0,
            0,
        )
        .status
    }
}

/// Replaces the process builder's CPU affinity mask.
///
/// # Safety
///
/// `builder` must remain live with write rights and `words` must remain
/// readable for `word_count` `u64` values.
#[inline]
pub unsafe fn process_builder_set_affinity(
    builder: abi::HyperNativeHandle,
    words: *const u64,
    word_count: usize,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the handle and buffer contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_BUILDER_SET_AFFINITY,
            builder,
            words.addr() as u64,
            word_count as u64,
            0,
            0,
            0,
        )
        .status
    }
}

/// Adds one capability disposition to a process builder.
///
/// # Safety
///
/// `builder` and `source` must satisfy the ABI kind, rights, and lifetime
/// contracts. MOVE consumes `source` only on `OK`; DUPLICATE preserves it on
/// every result.
#[inline]
pub unsafe fn process_builder_add_handle(
    builder: abi::HyperNativeHandle,
    source: abi::HyperNativeHandle,
    purpose: u32,
    expected_kind: u32,
    rights: u64,
    operation: u32,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes both handle contracts and owns the
    // operation-dependent commit transition.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_BUILDER_ADD_HANDLE,
            builder,
            source,
            u64::from(purpose),
            u64::from(expected_kind),
            rights,
            u64::from(operation),
        )
        .status
    }
}

/// Irreversibly seals a process builder.
///
/// # Safety
///
/// `builder` must remain live with write rights for the call.
#[inline]
pub unsafe fn process_builder_seal(builder: abi::HyperNativeHandle) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the borrowed builder contract.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_BUILDER_SEAL,
            builder,
            0,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Starts and consumes one sealed process builder.
///
/// # Safety
///
/// The caller must exclusively own `builder`. `OK` consumes it and publishes
/// a supervisor Process handle in `value0` and a READ/WAIT `ByteChannel` in
/// `value1`. The child runs userspace-loader; callers must consume its startup
/// result before reporting application readiness. Every syscall failure preserves
/// `builder`; a later loader failure does not restore it.
#[inline]
pub unsafe fn process_builder_start(builder: abi::HyperNativeHandle) -> CallResult {
    // SAFETY: the caller owns the builder's consume-on-success transition.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_BUILDER_START,
            builder,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Aborts and consumes one process builder.
///
/// # Safety
///
/// The caller must exclusively own `builder`. `OK` consumes it; every failure
/// preserves ownership.
#[inline]
pub unsafe fn process_builder_abort(builder: abi::HyperNativeHandle) -> abi::HyperNativeStatus {
    // SAFETY: the caller owns the builder's consume-on-success transition.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_BUILDER_ABORT,
            builder,
            0,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Requests asynchronous termination of a Process.
///
/// # Safety
///
/// `process` must remain live with request-stop rights for the call.
#[inline]
pub unsafe fn process_request_stop(process: abi::HyperNativeHandle) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the borrowed Process contract.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_REQUEST_STOP,
            process,
            0,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Yields the calling Native Thread.
///
/// # Safety
///
/// The caller must be executing through the `HypeR` Native runtime.
#[inline]
pub unsafe fn thread_yield() -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the Native execution contract.
    unsafe { ffi_thread_yield() }
}

/// Terminates the calling Native Thread.
///
/// # Safety
///
/// The caller must be executing through the `HypeR` Native runtime and must not
/// rely on destructors after this terminal transition.
#[inline]
pub unsafe fn thread_exit(status: i64) -> ! {
    // SAFETY: the caller authorizes the non-returning Thread transition.
    unsafe { ffi_thread_exit(status) }
}

/// Terminates the calling Native Process.
///
/// # Safety
///
/// The caller must be executing through the `HypeR` Native runtime and must not
/// rely on destructors after this terminal transition.
#[inline]
pub unsafe fn process_exit(status: i64) -> ! {
    // SAFETY: the caller authorizes the non-returning Process transition.
    unsafe { ffi_process_exit(status) }
}

/// Invokes Native `thread_create`.
///
/// # Safety
/// Handles, addresses and thread entry state must satisfy the Native ABI;
/// referenced memory must remain live through the operation or thread lifetime.
pub unsafe fn thread_create(
    entry: u64,
    stack: u64,
    tls: u64,
    argument: u64,
    affinity_words: *const u64,
    affinity_word_count: usize,
) -> CallResult {
    // SAFETY: the caller upholds the raw syscall contract, including the
    // borrowed little-endian affinity array (or null/zero for inheritance).
    unsafe {
        ffi_thread_create(
            entry,
            stack,
            tls,
            argument,
            affinity_words,
            affinity_word_count,
        )
    }
}

/// Invokes Native `thread_start`.
///
/// # Safety
/// Handles, addresses and thread entry state must satisfy the Native ABI;
/// referenced memory must remain live through the operation or thread lifetime.
pub unsafe fn thread_start(thread: u64) -> abi::HyperNativeStatus {
    // SAFETY: the caller upholds the raw syscall contract.
    unsafe { ffi_thread_start(thread) }
}

/// Invokes Native `thread_request_stop`.
///
/// # Safety
/// Handles, addresses and thread entry state must satisfy the Native ABI;
/// referenced memory must remain live through the operation or thread lifetime.
pub unsafe fn thread_request_stop(thread: u64) -> abi::HyperNativeStatus {
    // SAFETY: the caller upholds the raw syscall contract.
    unsafe { ffi_thread_request_stop(thread) }
}

/// Invokes Native `thread_sleep`.
///
/// # Safety
/// Handles, addresses and thread entry state must satisfy the Native ABI;
/// referenced memory must remain live through the operation or thread lifetime.
pub unsafe fn thread_sleep(deadline: u64) -> abi::HyperNativeStatus {
    // SAFETY: the caller upholds the raw syscall contract.
    unsafe { ffi_thread_sleep(deadline) }
}

/// Returns the calling process's observation-only KOID.
///
/// # Safety
/// The caller must execute in a Native process using the matching SDK.
pub unsafe fn process_get_current_id() -> CallResult {
    // SAFETY: this call has no pointers or capability arguments.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_GET_CURRENT_ID,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Select whether a sealed child's root VMAR receives residency authority.
///
/// # Safety
/// `builder` must remain live with WRITE and `LOCK_MEMORY` rights.
pub unsafe fn process_builder_set_memory_lock(
    builder: u64,
    enabled: bool,
) -> abi::HyperNativeStatus {
    // SAFETY: The caller retains the capability for the non-retaining syscall.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PROCESS_BUILDER_SET_MEMORY_LOCK,
            builder,
            u64::from(enabled),
            0,
            0,
            0,
            0,
        )
        .status
    }
}
