// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Scoped task, object, CPU, and memory observation.

use crate::ffi::ffi_native_call6;
use crate::{CallResult, abi};

/// Scans one fixed-capacity page of Processes visible through a task inspector.
///
/// # Safety
///
/// `inspector` must remain live with inspect rights. `records` must be writable
/// for `capacity` complete records, and capacity must equal the ABI page size.
#[inline]
pub unsafe fn task_inspector_scan_processes(
    inspector: abi::HyperNativeHandle,
    cursor: u64,
    records: *mut abi::HyperNativeTaskProcess,
    capacity: usize,
) -> CallResult {
    // SAFETY: the caller establishes the handle and output-array contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_TASK_INSPECTOR_SCAN_PROCESSES,
            inspector,
            cursor,
            records.addr() as u64,
            capacity as u64,
            0,
            0,
        )
    }
}

/// Scans one fixed-capacity page of Threads visible through a task inspector.
///
/// # Safety
///
/// The typed handle and complete writable record-array contracts must hold.
#[inline]
pub unsafe fn task_inspector_scan_threads(
    inspector: abi::HyperNativeHandle,
    cursor: u64,
    records: *mut abi::HyperNativeTaskThread,
    capacity: usize,
) -> CallResult {
    // SAFETY: the caller establishes the handle and output-array contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_TASK_INSPECTOR_SCAN_THREADS,
            inspector,
            cursor,
            records.addr() as u64,
            capacity as u64,
            0,
            0,
        )
    }
}

/// Scans one fixed-capacity page of global object observations.
///
/// # Safety
///
/// The typed handle and complete writable record-array contracts must hold.
#[inline]
pub unsafe fn object_inspector_scan_objects(
    inspector: abi::HyperNativeHandle,
    cursor: u64,
    records: *mut abi::HyperNativeObjectInspection,
    capacity: usize,
) -> CallResult {
    // SAFETY: the caller establishes the handle and output-array contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_OBJECT_INSPECTOR_SCAN_OBJECTS,
            inspector,
            cursor,
            records.addr() as u64,
            capacity as u64,
            0,
            0,
        )
    }
}

/// Scans handles owned by one visible Process KOID.
///
/// # Safety
///
/// The typed handle and complete writable record-array contracts must hold.
#[inline]
pub unsafe fn object_inspector_scan_handles(
    inspector: abi::HyperNativeHandle,
    process_koid: u64,
    cursor: u64,
    records: *mut abi::HyperNativeHandleInspection,
    capacity: usize,
) -> CallResult {
    // SAFETY: the caller establishes the handle and output-array contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_OBJECT_INSPECTOR_SCAN_HANDLES,
            inspector,
            process_koid,
            cursor,
            records.addr() as u64,
            capacity as u64,
            0,
        )
    }
}

/// Derives a Process-scoped inspector from a wider inspector.
///
/// # Safety
///
/// Both handles must remain live with the ABI-required rights. On `OK`, the
/// caller assumes exclusive ownership of the returned nonzero handle.
#[inline]
unsafe fn inspector_derive(
    syscall: u64,
    inspector: abi::HyperNativeHandle,
    scope: abi::HyperNativeHandle,
) -> CallResult {
    // SAFETY: the caller owns successful output-handle adoption.
    unsafe { ffi_native_call6(syscall, inspector, scope, 0, 0, 0, 0) }
}

macro_rules! inspector_derivation {
    ($name:ident, $syscall:ident, $scope:literal) => {
        #[doc = concat!("Derives an inspector scoped to one ", $scope, ".")]
        ///
        /// # Safety
        ///
        /// Both handles must remain live with the ABI-required rights. On
        /// `OK`, the caller assumes exclusive ownership of the returned handle.
        #[inline]
        pub unsafe fn $name(
            inspector: abi::HyperNativeHandle,
            scope: abi::HyperNativeHandle,
        ) -> CallResult {
            // SAFETY: the caller owns successful output-handle adoption.
            unsafe { inspector_derive(abi::$syscall, inspector, scope) }
        }
    };
}

inspector_derivation!(
    task_inspector_derive_process,
    HYPER_NATIVE_SYS_TASK_INSPECTOR_DERIVE_PROCESS,
    "Process"
);
inspector_derivation!(
    task_inspector_derive_task_group,
    HYPER_NATIVE_SYS_TASK_INSPECTOR_DERIVE_TASK_GROUP,
    "TaskGroup"
);
inspector_derivation!(
    task_inspector_derive_resource_domain,
    HYPER_NATIVE_SYS_TASK_INSPECTOR_DERIVE_RESOURCE_DOMAIN,
    "ResourceDomain"
);
inspector_derivation!(
    object_inspector_derive_process,
    HYPER_NATIVE_SYS_OBJECT_INSPECTOR_DERIVE_PROCESS,
    "Process"
);
inspector_derivation!(
    object_inspector_derive_task_group,
    HYPER_NATIVE_SYS_OBJECT_INSPECTOR_DERIVE_TASK_GROUP,
    "TaskGroup"
);
inspector_derivation!(
    object_inspector_derive_resource_domain,
    HYPER_NATIVE_SYS_OBJECT_INSPECTOR_DERIVE_RESOURCE_DOMAIN,
    "ResourceDomain"
);

/// Reads one immutable physical-memory accounting snapshot.
///
/// # Safety
///
/// `observation` must designate one writable ABI observation record.
pub unsafe fn memory_inspector_read(
    inspector: abi::HyperNativeHandle,
    observation: *mut abi::HyperNativeMemoryObservation,
) -> CallResult {
    // SAFETY: the caller owns the pointer contract stated above.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_MEMORY_INSPECTOR_READ,
            inspector,
            observation.addr() as u64,
            core::mem::size_of::<abi::HyperNativeMemoryObservation>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Reads one immutable scheduler CPU-time snapshot.
///
/// # Safety
///
/// `observation` must designate one writable ABI observation record.
pub unsafe fn cpu_inspector_read(
    inspector: abi::HyperNativeHandle,
    observation: *mut abi::HyperNativeCpuObservation,
) -> CallResult {
    // SAFETY: the caller owns the pointer contract stated above.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_CPU_INSPECTOR_READ,
            inspector,
            observation.addr() as u64,
            core::mem::size_of::<abi::HyperNativeCpuObservation>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Reads object-local details using an explicitly privileged inspector.
///
/// # Safety
/// The inspector must remain live. `record` must point to one complete writable
/// ABI record. The process and target values are diagnostic selectors only.
pub unsafe fn object_inspector_read_details(
    inspector: abi::HyperNativeHandle,
    process: u64,
    target: u64,
    cursor: u64,
    record: *mut abi::HyperNativeObjectDetails,
) -> CallResult {
    // SAFETY: the caller guarantees the writable output and handle lifetime.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_OBJECT_INSPECTOR_READ_DETAILS,
            inspector,
            process,
            target,
            cursor,
            record.addr() as u64,
            core::mem::size_of::<abi::HyperNativeObjectDetails>() as u64,
        )
    }
}
