// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Guest creation, configuration, and virtual CPU control.

use crate::ffi::ffi_native_call6;
use crate::{CallResult, abi};

/// Derives one resource-domain-bound VM creation lease.
///
/// # Safety
///
/// Both input handles must remain live. On success, the caller owns the
/// returned nonzero handle in `value0`.
#[inline]
pub unsafe fn virtual_machine_creation_lease_create(
    authority: abi::HyperNativeHandle,
    resource_domain: abi::HyperNativeHandle,
) -> CallResult {
    // SAFETY: the caller establishes the borrowed input and output ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_MACHINE_CREATION_LEASE_CREATE,
            authority,
            resource_domain,
            0,
            0,
            0,
            0,
        )
    }
}

/// Creates a pending VM and consumes `lease` only on success.
///
/// # Safety
///
/// `configuration` must remain readable for the complete call. The caller
/// must honor the consume-on-success contract for `lease` and adopt the
/// returned handle in `value0` only on success.
#[inline]
pub unsafe fn virtual_machine_create(
    lease: abi::HyperNativeHandle,
    configuration: *const abi::HyperNativeVirtualMachineConfiguration,
) -> CallResult {
    // SAFETY: the caller establishes input pointer and handle ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_MACHINE_CREATE,
            lease,
            configuration.addr() as u64,
            core::mem::size_of::<abi::HyperNativeVirtualMachineConfiguration>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Attaches the writable guest-memory VMO to a pending VM.
///
/// # Safety
///
/// Both handles must remain live for the complete call.
#[inline]
pub unsafe fn pending_virtual_machine_set_memory(
    pending: abi::HyperNativeHandle,
    vmo: abi::HyperNativeHandle,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes both borrowed handle lifetimes.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PENDING_VIRTUAL_MACHINE_SET_MEMORY,
            pending,
            vmo,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Commits a virtual-serial device capability into a pending VM.
///
/// # Safety
///
/// Both handles must remain live for the complete call. The caller must honor
/// the consume-on-success contract for `serial`.
#[inline]
pub unsafe fn pending_virtual_machine_set_virtual_serial(
    pending: abi::HyperNativeHandle,
    serial: abi::HyperNativeHandle,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes both handle lifetimes and ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PENDING_VIRTUAL_MACHINE_SET_VIRTUAL_SERIAL,
            pending,
            serial,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Sets the boot-vCPU initial machine state.
///
/// # Safety
///
/// `bootstrap` must remain readable and `pending` live for the complete call.
#[inline]
pub unsafe fn pending_virtual_machine_set_bootstrap(
    pending: abi::HyperNativeHandle,
    bootstrap: *const abi::HyperNativeVirtualCpuBootstrap,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes pointer validity and handle lifetime.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PENDING_VIRTUAL_MACHINE_SET_BOOTSTRAP,
            pending,
            bootstrap.addr() as u64,
            core::mem::size_of::<abi::HyperNativeVirtualCpuBootstrap>() as u64,
            0,
            0,
            0,
        )
        .status
    }
}

/// Seals a fully configured pending VM.
///
/// # Safety
///
/// `pending` must remain live for the complete call.
#[inline]
pub unsafe fn pending_virtual_machine_seal(
    pending: abi::HyperNativeHandle,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the borrowed handle lifetime.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PENDING_VIRTUAL_MACHINE_SEAL,
            pending,
            0,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Installs a sealed VM in a dormant state and consumes `pending` only on
/// success.
///
/// # Safety
///
/// The caller must honor the consume-on-success contract and adopt both
/// returned handles only when the result status is `OK`.
#[inline]
pub unsafe fn pending_virtual_machine_install(pending: abi::HyperNativeHandle) -> CallResult {
    // SAFETY: the caller establishes input and returned-handle ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PENDING_VIRTUAL_MACHINE_INSTALL,
            pending,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Makes one installed dormant vCPU scheduler-runnable.
///
/// # Safety
///
/// `vcpu` must remain live with start rights for the complete call.
#[inline]
pub unsafe fn virtual_cpu_start(vcpu: abi::HyperNativeHandle) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the borrowed handle lifetime.
    unsafe { ffi_native_call6(abi::HYPER_NATIVE_SYS_VIRTUAL_CPU_START, vcpu, 0, 0, 0, 0, 0).status }
}

/// Replaces a vCPU's host-CPU affinity mask.
///
/// # Safety
/// `vcpu` must remain live with write rights and `words` must remain readable
/// for `word_count` little-endian `u64` values throughout the call.
#[inline]
pub unsafe fn virtual_cpu_set_affinity(
    vcpu: abi::HyperNativeHandle,
    words: *const u64,
    word_count: usize,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the handle and input buffer lifetimes.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_CPU_SET_AFFINITY,
            vcpu,
            words.addr() as u64,
            word_count as u64,
            0,
            0,
            0,
        )
        .status
    }
}

/// Aborts and consumes one pending VM only on success.
///
/// # Safety
///
/// The caller must honor the consume-on-success contract for `pending`.
#[inline]
pub unsafe fn pending_virtual_machine_abort(
    pending: abi::HyperNativeHandle,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes consuming handle ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PENDING_VIRTUAL_MACHINE_ABORT,
            pending,
            0,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Requests asynchronous VM stop.
///
/// # Safety
///
/// `machine` must remain live for the complete call.
#[inline]
pub unsafe fn virtual_machine_request_stop(
    machine: abi::HyperNativeHandle,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the borrowed handle lifetime.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_MACHINE_REQUEST_STOP,
            machine,
            0,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Reads installed VM metadata.
///
/// # Safety
///
/// `machine` must remain live and `info` writable for the complete call.
#[inline]
pub unsafe fn virtual_machine_get_info(
    machine: abi::HyperNativeHandle,
    info: *mut abi::HyperNativeVirtualMachineInfo,
) -> CallResult {
    // SAFETY: the caller establishes handle and pointer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_MACHINE_GET_INFO,
            machine,
            info.addr() as u64,
            core::mem::size_of::<abi::HyperNativeVirtualMachineInfo>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Reads installed vCPU metadata.
///
/// # Safety
///
/// `vcpu` must remain live and `info` writable for the complete call.
#[inline]
pub unsafe fn virtual_cpu_get_info(
    vcpu: abi::HyperNativeHandle,
    info: *mut abi::HyperNativeVirtualCpuInfo,
) -> CallResult {
    // SAFETY: the caller establishes handle and pointer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_CPU_GET_INFO,
            vcpu,
            info.addr() as u64,
            core::mem::size_of::<abi::HyperNativeVirtualCpuInfo>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Reads immutable board metadata without consuming the creation lease.
///
/// # Safety
/// `lease` must remain live and `info` writable for the complete call.
#[inline]
pub unsafe fn virtual_machine_creation_lease_get_platform_info(
    lease: abi::HyperNativeHandle,
    profile: u32,
    info: *mut abi::HyperNativeVirtualMachinePlatformInfo,
) -> CallResult {
    // SAFETY: the caller establishes handle and pointer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_MACHINE_CREATION_LEASE_GET_PLATFORM_INFO,
            lease,
            u64::from(profile),
            info.addr() as u64,
            core::mem::size_of::<abi::HyperNativeVirtualMachinePlatformInfo>() as u64,
            0,
            0,
        )
    }
}

/// Snapshots one pending guest power request without consuming it.
///
/// # Safety
///
/// `machine` must remain live and `request` writable for the complete call.
#[inline]
pub unsafe fn virtual_machine_get_power_request(
    machine: abi::HyperNativeHandle,
    request: *mut abi::HyperNativeVirtualMachinePowerRequest,
) -> CallResult {
    // SAFETY: The caller establishes handle and output validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_MACHINE_GET_POWER_REQUEST,
            machine,
            request.addr() as u64,
            core::mem::size_of::<abi::HyperNativeVirtualMachinePowerRequest>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Completes the exact pending power request.
///
/// # Safety
///
/// `machine` must remain live throughout the call.
#[inline]
pub unsafe fn virtual_machine_complete_power_request(
    machine: abi::HyperNativeHandle,
    request_id: u64,
    accept: u32,
) -> abi::HyperNativeStatus {
    // SAFETY: The caller retains the handle; scalar arguments borrow no memory.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_MACHINE_COMPLETE_POWER_REQUEST,
            machine,
            request_id,
            u64::from(accept),
            0,
            0,
            0,
        )
        .status
    }
}

/// Opens one configured vCPU control handle.
///
/// # Safety
///
/// `machine` must remain live; a successfully returned handle must be adopted once.
#[inline]
pub unsafe fn virtual_machine_open_vcpu(
    machine: abi::HyperNativeHandle,
    vcpu_id: u32,
) -> CallResult {
    // SAFETY: The caller retains the input and owns the returned capability.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_MACHINE_OPEN_VCPU,
            machine,
            u64::from(vcpu_id),
            0,
            0,
            0,
            0,
        )
    }
}

/// Registers one device aperture before a VM starts.
///
/// # Safety
/// The machine handle must remain live throughout the call.
#[inline]
pub unsafe fn virtual_machine_register_mmio(
    machine: abi::HyperNativeHandle,
    base: u64,
    length: u64,
    device: u64,
) -> abi::HyperNativeStatus {
    // SAFETY: The caller retains the handle; all remaining arguments are scalars.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_MACHINE_REGISTER_MMIO,
            machine,
            base,
            length,
            device,
            0,
            0,
        )
        .status
    }
}

/// Snapshots a pending MMIO instruction without consuming its continuation.
///
/// # Safety
/// The vCPU handle must remain live and request must be writable for the call.
#[inline]
pub unsafe fn virtual_cpu_get_mmio_request(
    vcpu: abi::HyperNativeHandle,
    request: *mut abi::HyperNativeVirtualCpuMmioRequest,
) -> CallResult {
    // SAFETY: The caller establishes handle and output validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_CPU_GET_MMIO_REQUEST,
            vcpu,
            request.addr() as u64,
            core::mem::size_of::<abi::HyperNativeVirtualCpuMmioRequest>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Completes an exact pending MMIO instruction, or aborts its VM.
///
/// # Safety
/// The vCPU handle must remain live throughout the call.
#[inline]
pub unsafe fn virtual_cpu_complete_mmio(
    vcpu: abi::HyperNativeHandle,
    id: u64,
    operation: u32,
    value: u64,
) -> abi::HyperNativeStatus {
    // SAFETY: The caller retains the handle; all remaining arguments are scalars.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_CPU_COMPLETE_MMIO,
            vcpu,
            id,
            u64::from(operation),
            value,
            0,
            0,
        )
        .status
    }
}

/// Freezes a writable VMO for explicitly shared guest use.
///
/// # Safety
/// The VMO handle remains live; adopt the returned memory handle exactly once.
#[inline]
pub unsafe fn guest_memory_create(vmo: abi::HyperNativeHandle) -> CallResult {
    // SAFETY: The caller retains the sole borrowed handle.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_GUEST_MEMORY_CREATE,
            vmo,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Adds a page-aligned region to a pending VM's immutable RAM layout.
///
/// # Safety
/// Both handles must remain live for the call.
#[inline]
pub unsafe fn pending_virtual_machine_map_memory(
    pending: abi::HyperNativeHandle,
    memory: abi::HyperNativeHandle,
    guest_offset: u64,
    source_offset: u64,
    length: u64,
) -> abi::HyperNativeStatus {
    // SAFETY: The caller retains both handles; remaining arguments are scalars.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PENDING_VIRTUAL_MACHINE_MAP_MEMORY,
            pending,
            memory,
            guest_offset,
            source_offset,
            length,
            0,
        )
        .status
    }
}

/// Executes the Native `pending_virtual_machine_assign_device` operation.
///
/// # Safety
/// Retain all input handles and provide valid readable/writable pointer ranges
/// as specified by the Native ABI for the complete non-retaining call.
#[inline]
pub unsafe fn pending_virtual_machine_assign_device(
    pending: u64,
    device: u64,
    base: u64,
    irq: u32,
) -> CallResult {
    // SAFETY: The caller establishes the ABI handle and memory contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PENDING_VIRTUAL_MACHINE_ASSIGN_DEVICE,
            pending,
            device,
            base,
            u64::from(irq),
            0,
            0,
        )
    }
}
