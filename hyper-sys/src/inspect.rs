// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Scoped task, object, CPU, and memory observation.

use crate::ffi::ffi_native_invoke6;
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
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_TASK_INSPECTOR_SCAN_PROCESSES,
            cursor,
            records.addr() as u64,
            capacity as u64,
            core::mem::size_of::<abi::HyperNativeTaskProcess>() as u64,
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
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_TASK_INSPECTOR_SCAN_THREADS,
            cursor,
            records.addr() as u64,
            capacity as u64,
            core::mem::size_of::<abi::HyperNativeTaskThread>() as u64,
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
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_OBJECT_INSPECTOR_SCAN_OBJECTS,
            cursor,
            records.addr() as u64,
            capacity as u64,
            core::mem::size_of::<abi::HyperNativeObjectInspection>() as u64,
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
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_OBJECT_INSPECTOR_SCAN_HANDLES,
            process_koid,
            cursor,
            records.addr() as u64,
            capacity as u64,
            core::mem::size_of::<abi::HyperNativeHandleInspection>() as u64,
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
    operation: u64,
    inspector: abi::HyperNativeHandle,
    scope: abi::HyperNativeHandle,
) -> CallResult {
    // SAFETY: the caller owns successful output-handle adoption.
    unsafe { ffi_native_invoke6(inspector, operation, scope, 0, 0, 0, 0, 0) }
}

macro_rules! inspector_derivation {
    ($name:ident, $operation:ident, $scope:literal) => {
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
            unsafe { inspector_derive(abi::$operation, inspector, scope) }
        }
    };
}

inspector_derivation!(
    task_inspector_derive_process,
    HYPER_NATIVE_OP_TASK_INSPECTOR_DERIVE_PROCESS,
    "Process"
);
inspector_derivation!(
    task_inspector_derive_task_group,
    HYPER_NATIVE_OP_TASK_INSPECTOR_DERIVE_TASK_GROUP,
    "TaskGroup"
);
inspector_derivation!(
    task_inspector_derive_resource_domain,
    HYPER_NATIVE_OP_TASK_INSPECTOR_DERIVE_RESOURCE_DOMAIN,
    "ResourceDomain"
);
inspector_derivation!(
    object_inspector_derive_process,
    HYPER_NATIVE_OP_OBJECT_INSPECTOR_DERIVE_PROCESS,
    "Process"
);
inspector_derivation!(
    object_inspector_derive_task_group,
    HYPER_NATIVE_OP_OBJECT_INSPECTOR_DERIVE_TASK_GROUP,
    "TaskGroup"
);
inspector_derivation!(
    object_inspector_derive_resource_domain,
    HYPER_NATIVE_OP_OBJECT_INSPECTOR_DERIVE_RESOURCE_DOMAIN,
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
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_MEMORY_INSPECTOR_READ,
            observation.addr() as u64,
            core::mem::size_of::<abi::HyperNativeMemoryObservation>() as u64,
            0,
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
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_CPU_INSPECTOR_READ,
            observation.addr() as u64,
            core::mem::size_of::<abi::HyperNativeCpuObservation>() as u64,
            0,
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
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_OBJECT_INSPECTOR_READ_DETAILS,
            process,
            target,
            cursor,
            record.addr() as u64,
            core::mem::size_of::<abi::HyperNativeObjectDetails>() as u64,
            0,
        )
    }
}

/// Reads one topic-specific memory diagnostic record.
///
/// # Safety
/// `record` must designate `size` writable bytes and the inspector must remain
/// live. The topic selects the ABI record layout; no pointer is retained.
pub unsafe fn memory_inspector_read_statistics(
    inspector: abi::HyperNativeHandle,
    topic: u32,
    index: u32,
    record: *mut u8,
    size: usize,
) -> CallResult {
    // SAFETY: The caller owns the output buffer contract above.
    unsafe {
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_MEMORY_INSPECTOR_READ_STATISTICS,
            topic as u64,
            index as u64,
            record.addr() as u64,
            size as u64,
            0,
            0,
        )
    }
}

/// Starts one bounded global PMU capture with explicit configuration authority.
/// # Safety
/// The inspector must remain live with `SET_ATTRIBUTES` rights.
pub unsafe fn cpu_inspector_profile_start(
    inspector: abi::HyperNativeHandle,
    period: u64,
    seconds: u64,
) -> CallResult {
    // SAFETY: The caller supplies the borrowed authority; arguments are scalars.
    unsafe {
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_CPU_INSPECTOR_PROFILE_START,
            period,
            seconds,
            0,
            0,
            0,
            0,
        )
    }
}
/// Requests PMU stop. BUSY means one or more CPUs still need to acknowledge.
/// # Safety
/// The inspector must remain live with `SET_ATTRIBUTES` rights.
pub unsafe fn cpu_inspector_profile_stop(
    inspector: abi::HyperNativeHandle,
    generation: u64,
) -> CallResult {
    // SAFETY: The caller supplies the borrowed authority; generation is a scalar.
    unsafe {
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_CPU_INSPECTOR_PROFILE_STOP,
            generation,
            0,
            0,
            0,
            0,
            0,
        )
    }
}
/// Reads PMU metadata (`cpu=u64::MAX`) or one bounded call-chain record.
/// # Safety
/// The inspector needs `INSPECT_DETAILS`; output must span size writable bytes.
pub unsafe fn cpu_inspector_profile_read(
    inspector: abi::HyperNativeHandle,
    generation: u64,
    cpu: u64,
    cursor: u64,
    output: *mut u8,
    size: usize,
) -> CallResult {
    // SAFETY: The caller owns the complete output range for this invocation.
    unsafe {
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_CPU_INSPECTOR_PROFILE_READ,
            generation,
            cpu,
            cursor,
            output.addr() as u64,
            size as u64,
            0,
        )
    }
}

/// Starts one bounded global tracepoint capture with explicit configuration authority.
/// # Safety
/// The inspector must remain live with `SET_ATTRIBUTES` rights. `config` must
/// point to a readable, initialized `TraceConfig` for the duration of the call.
pub unsafe fn cpu_inspector_trace_start(
    inspector: abi::HyperNativeHandle,
    config: *const abi::HyperNativeTraceConfig,
) -> CallResult {
    // SAFETY: The caller keeps the authority and readable configuration alive.
    unsafe {
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_CPU_INSPECTOR_TRACE_START,
            config as u64,
            core::mem::size_of::<abi::HyperNativeTraceConfig>() as u64,
            0,
            0,
            0,
            0,
        )
    }
}
/// Closes trace admission. BUSY means a short in-flight ring writer needs joining.
/// # Safety
/// The inspector must remain live with `SET_ATTRIBUTES` rights.
pub unsafe fn cpu_inspector_trace_stop(
    inspector: abi::HyperNativeHandle,
    generation: u64,
) -> CallResult {
    // SAFETY: The caller supplies the borrowed authority; generation is a scalar.
    unsafe {
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_CPU_INSPECTOR_TRACE_STOP,
            generation,
            0,
            0,
            0,
            0,
            0,
        )
    }
}
/// Releases a stopped capture; active captures are rejected with BUSY.
/// # Safety
/// The inspector must remain live with `SET_ATTRIBUTES` rights.
pub unsafe fn cpu_inspector_trace_clear(
    inspector: abi::HyperNativeHandle,
    generation: u64,
) -> CallResult {
    // SAFETY: The caller supplies the borrowed authority; generation is a scalar.
    unsafe {
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_CPU_INSPECTOR_TRACE_CLEAR,
            generation,
            0,
            0,
            0,
            0,
            0,
        )
    }
}
/// Reads trace metadata (`cpu=u64::MAX`), a thread name (`cpu=u64::MAX-1`),
/// or a bounded batch of events for an online CPU.
/// # Safety
/// The inspector needs `INSPECT_DETAILS`; output must span size writable bytes.
pub unsafe fn cpu_inspector_trace_read(
    inspector: abi::HyperNativeHandle,
    generation: u64,
    cpu: u64,
    cursor: u64,
    output: *mut u8,
    size: usize,
) -> CallResult {
    // SAFETY: The caller owns the complete output range for this invocation.
    unsafe {
        ffi_native_invoke6(
            inspector,
            abi::HYPER_NATIVE_OP_CPU_INSPECTOR_TRACE_READ,
            generation,
            cpu,
            cursor,
            output.addr() as u64,
            size as u64,
            0,
        )
    }
}
