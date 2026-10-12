// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Safe Native virtual-machine construction and lifecycle bindings.

use core::num::NonZeroU64;

use crate::handle::{
    AnyObject, HandleRef, OwnedHandle, PendingVirtualMachineObject, ResourceDomainObject, Rights,
    TypedObject, VirtualCpuObject, VirtualMachineCreationAuthorityObject,
    VirtualMachineCreationLeaseObject, VirtualMachineObject, VirtualSerialObject, VmoObject,
};
use crate::{Error, Result, Status};

const CREATION_LEASE_RIGHTS: Rights = Rights::TRANSFER
    .union(Rights::INSPECT)
    .union(Rights::CREATE_VIRTUAL_MACHINE);
const PENDING_RIGHTS: Rights = Rights::TRANSFER
    .union(Rights::INSPECT)
    .union(Rights::WRITE)
    .union(Rights::START)
    .union(Rights::REQUEST_STOP);
const MACHINE_RIGHTS: Rights = Rights::TRANSFER
    .union(Rights::WRITE)
    .union(Rights::WAIT)
    .union(Rights::INSPECT)
    .union(Rights::REQUEST_STOP);
const VCPU_RIGHTS: Rights = Rights::TRANSFER
    .union(Rights::WRITE)
    .union(Rights::WAIT)
    .union(Rights::INSPECT)
    .union(Rights::START);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Architecture {
    Aarch64 = hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_ARCHITECTURE_AARCH64 as u32,
    Riscv64 = hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_ARCHITECTURE_RISCV64 as u32,
    X86_64 = hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_ARCHITECTURE_X86_64 as u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PlatformProfile {
    Aarch64Reference = hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE as u32,
    Riscv64Reference = hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE as u32,
}

impl PlatformProfile {
    #[must_use]
    pub const fn guest_ram_base(self) -> u64 {
        match self {
            Self::Aarch64Reference => {
                hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_GUEST_RAM_BASE
            }
            Self::Riscv64Reference => {
                hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE_GUEST_RAM_BASE
            }
        }
    }

    #[must_use]
    pub const fn device_tree_offset(self) -> u64 {
        match self {
            Self::Aarch64Reference => {
                hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_DTB_OFFSET
            }
            Self::Riscv64Reference => {
                hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE_DTB_OFFSET
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Configuration {
    pub guest_physical_base: u64,
    pub memory_size: u64,
    pub vcpu_count: u32,
    pub architecture: Architecture,
    pub platform_profile: PlatformProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualCpuBootstrap {
    pub entry: u64,
    pub stack: u64,
    pub arguments: [u64; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualMachinePhase {
    Installed,
    Running,
    Stopping,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualCpuPhase {
    Dormant,
    Started,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualCpuTermination {
    MemoryFault,
    Mmio,
    Synchronous,
    Administrative,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualMachineInfo {
    pub phase: VirtualMachinePhase,
    pub vcpu_count: u32,
    pub guest_physical_base: u64,
    pub memory_size: u64,
    /// Resident primary backing, including RAM and explicitly admitted shared pools.
    /// Excludes dynamically attached alias windows and runtime overhead.
    /// None while retirement prevents taking a memory snapshot.
    pub resident_memory_bytes: Option<u64>,
    pub architecture: Architecture,
    pub platform_profile: PlatformProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualCpuInfo {
    pub id: u32,
    pub phase: VirtualCpuPhase,
    pub scheduler_thread_id: u64,
    pub terminal: Option<VirtualCpuTermination>,
    /// Assigned physical CPU, not a claim that the vCPU is executing.
    /// Absent for retired threads or older kernels without placement observation.
    pub host_cpu: Option<u32>,
    /// Pending explicit migration destination at the same scheduler observation.
    pub migration_target: Option<u32>,
}

/// A rejected consume-on-success VM operation and its unchanged input handle.
pub struct ConsumingFailure<T: crate::handle::ObjectType> {
    error: Error,
    handle: OwnedHandle<T>,
}

impl<T: crate::handle::ObjectType> ConsumingFailure<T> {
    #[must_use]
    pub const fn error(&self) -> Error {
        self.error
    }

    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<T> {
        self.handle
    }
}

/// Derives creation authority sponsored by `domain` without creating a VM.
///
/// Pass the resulting lease to [`create`]. The domain supplies the new VM's
/// resource accounting; the parent authority and domain handles remain owned
/// by the caller.
pub fn derive_creation_lease(
    authority: HandleRef<'_, VirtualMachineCreationAuthorityObject>,
    domain: HandleRef<'_, ResourceDomainObject>,
) -> Result<OwnedHandle<VirtualMachineCreationLeaseObject>> {
    let authority_raw = authority.raw();
    let domain_raw = domain.raw();
    // SAFETY: both raw handles are borrowed for the complete call; successful
    // output is adopted exactly once below.
    let result = unsafe {
        hyper_sys::virtual_machine_creation_lease_create(authority_raw.get(), domain_raw.get())
    };
    Status::from_raw(result.status).into_result()?;
    adopt(
        result.value0,
        CREATION_LEASE_RIGHTS,
        &[authority_raw, domain_raw],
    )
}

/// Consumes a creation lease to produce an unpublished, configurable VM.
///
/// A rejected call returns the original lease in [`ConsumingFailure`]. After
/// success, attach memory and bootstrap state, then call [`seal`] and [`install`];
/// creation alone neither installs the VM nor starts a vCPU.
pub fn create(
    lease: OwnedHandle<VirtualMachineCreationLeaseObject>,
    configuration: Configuration,
) -> core::result::Result<
    OwnedHandle<PendingVirtualMachineObject>,
    ConsumingFailure<VirtualMachineCreationLeaseObject>,
> {
    let record = hyper_abi::HyperNativeVirtualMachineConfiguration {
        guest_physical_base: configuration.guest_physical_base,
        memory_size: configuration.memory_size,
        vcpu_count: configuration.vcpu_count,
        architecture: configuration.architecture as u32,
        platform_profile: configuration.platform_profile as u32,
        flags: 0,
    };
    let raw = lease.as_handle_ref().raw();
    // SAFETY: the stack record remains readable for the call and `lease`
    // remains owned until success is observed.
    let result = unsafe { hyper_sys::virtual_machine_create(raw.get(), &record) };
    let status = Status::from_raw(result.status);
    if status != Status::OK {
        return Err(ConsumingFailure {
            error: Error::Status(status),
            handle: lease,
        });
    }
    let _ = lease.into_raw();
    match adopt(result.value0, PENDING_RIGHTS, &[]) {
        Ok(pending) => Ok(pending),
        Err(_) => crate::handle::ownership_invariant(),
    }
}

pub fn set_memory(
    pending: HandleRef<'_, PendingVirtualMachineObject>,
    memory: HandleRef<'_, VmoObject>,
) -> Result<()> {
    // SAFETY: both handles remain borrowed for the complete call.
    Status::from_raw(unsafe {
        hyper_sys::pending_virtual_machine_set_memory(pending.raw().get(), memory.raw().get())
    })
    .into_result()
}

/// Transfers device-binding authority into the pending VM's serial device.
///
/// On failure, the returned value contains the unchanged virtual-serial handle.
pub fn set_virtual_serial(
    pending: HandleRef<'_, PendingVirtualMachineObject>,
    serial: OwnedHandle<VirtualSerialObject>,
) -> core::result::Result<(), ConsumingFailure<VirtualSerialObject>> {
    let raw = serial.as_handle_ref().raw();
    // SAFETY: both handles remain live for the complete call. Ownership of
    // `serial` is relinquished only after the kernel reports success.
    let status = Status::from_raw(unsafe {
        hyper_sys::pending_virtual_machine_set_virtual_serial(pending.raw().get(), raw.get())
    });
    if status != Status::OK {
        return Err(ConsumingFailure {
            error: Error::Status(status),
            handle: serial,
        });
    }
    let _ = serial.into_raw();
    Ok(())
}

pub fn set_bootstrap(
    pending: HandleRef<'_, PendingVirtualMachineObject>,
    bootstrap: VirtualCpuBootstrap,
) -> Result<()> {
    let record = hyper_abi::HyperNativeVirtualCpuBootstrap {
        entry: bootstrap.entry,
        stack: bootstrap.stack,
        argument0: bootstrap.arguments[0],
        argument1: bootstrap.arguments[1],
        argument2: bootstrap.arguments[2],
        argument3: bootstrap.arguments[3],
        vcpu_id: 0,
        flags: 0,
        reserved: 0,
    };
    // SAFETY: the handle and stack record remain valid for the complete call.
    Status::from_raw(unsafe {
        hyper_sys::pending_virtual_machine_set_bootstrap(pending.raw().get(), &record)
    })
    .into_result()
}

/// Validates the pending configuration and prepares resources for [`install`].
///
/// Success ends configuration but does not make the VM runnable. An incomplete
/// configuration is rejected before preparation. Once resource preparation
/// begins, a failure leaves the pending VM failed and requires recreating it.
pub fn seal(pending: HandleRef<'_, PendingVirtualMachineObject>) -> Result<()> {
    // SAFETY: the handle remains borrowed for the complete call.
    Status::from_raw(unsafe { hyper_sys::pending_virtual_machine_seal(pending.raw().get()) })
        .into_result()
}

/// Publishes a sealed VM and returns its VM handle and dormant boot-vCPU handle.
///
/// Success consumes `pending`; rejection returns it in [`ConsumingFailure`].
/// Execution is a separate step through [`start_vcpu`], so callers can finish
/// device binding and affinity setup before submitting the first vCPU.
pub fn install(
    pending: OwnedHandle<PendingVirtualMachineObject>,
) -> core::result::Result<
    (
        OwnedHandle<VirtualMachineObject>,
        OwnedHandle<VirtualCpuObject>,
    ),
    ConsumingFailure<PendingVirtualMachineObject>,
> {
    let raw = pending.as_handle_ref().raw();
    // SAFETY: ownership is retained until the consume-on-success result is
    // observed, then both returned handles are adopted exactly once.
    let result = unsafe { hyper_sys::pending_virtual_machine_install(raw.get()) };
    let status = Status::from_raw(result.status);
    if status != Status::OK {
        return Err(ConsumingFailure {
            error: Error::Status(status),
            handle: pending,
        });
    }
    let _ = pending.into_raw();
    // SAFETY: an OK PENDING_VIRTUAL_MACHINE_INSTALL result transfers ownership
    // of every distinct nonzero output, including a malformed pair. The helper
    // closes malformed outputs before this committed operation fails closed.
    let (machine_owner, vcpu_owner) = match unsafe {
        crate::handle::adopt_produced_handle_pair([result.value0, result.value1])
    } {
        Ok(pair) => pair,
        Err(_) => crate::handle::ownership_invariant(),
    };
    let machine = match validate_adopted::<VirtualMachineObject>(machine_owner, MACHINE_RIGHTS) {
        Ok(machine) => machine,
        Err(_) => crate::handle::ownership_invariant(),
    };
    let vcpu = match validate_adopted::<VirtualCpuObject>(vcpu_owner, VCPU_RIGHTS) {
        Ok(vcpu) => vcpu,
        Err(_) => crate::handle::ownership_invariant(),
    };
    Ok((machine, vcpu))
}

/// Maximum number of 64-bit CPU-mask words accepted for vCPU affinity.
pub const VCPU_AFFINITY_MAX_WORDS: usize =
    hyper_abi::HYPER_NATIVE_PROCESS_AFFINITY_MAX_WORDS as usize;

/// Replaces the allowed host CPUs. Keeps the current CPU if allowed; otherwise
/// the scheduler selects an allowed CPU and migrates the saved context.
/// Success accepts the update; a required handoff may finish after return.
pub fn set_vcpu_affinity(vcpu: HandleRef<'_, VirtualCpuObject>, words: &[u64]) -> Result<()> {
    let encoded = encode_vcpu_affinity(words)?;
    // SAFETY: the handle and bounded encoded mask remain borrowed for the call.
    Status::from_raw(unsafe {
        hyper_sys::virtual_cpu_set_affinity(vcpu.raw().get(), encoded.as_ptr(), words.len())
    })
    .into_result()
}

fn encode_vcpu_affinity(words: &[u64]) -> Result<[u64; VCPU_AFFINITY_MAX_WORDS]> {
    if words.is_empty()
        || words.len() > VCPU_AFFINITY_MAX_WORDS
        || words.iter().all(|word| *word == 0)
    {
        return Err(Error::Status(Status::INVALID_ARGUMENT));
    }
    let mut encoded = [0; VCPU_AFFINITY_MAX_WORDS];
    for (output, word) in encoded.iter_mut().zip(words) {
        *output = word.to_le();
    }
    Ok(encoded)
}

/// Makes an installed dormant vCPU scheduler-runnable exactly once.
pub fn start_vcpu(vcpu: HandleRef<'_, VirtualCpuObject>) -> Result<()> {
    // SAFETY: the typed vCPU handle remains borrowed for the complete call.
    Status::from_raw(unsafe { hyper_sys::virtual_cpu_start(vcpu.raw().get()) }).into_result()
}

pub fn abort(
    pending: OwnedHandle<PendingVirtualMachineObject>,
) -> core::result::Result<(), ConsumingFailure<PendingVirtualMachineObject>> {
    let raw = pending.as_handle_ref().raw();
    // SAFETY: ownership is retained until success is observed.
    let status = Status::from_raw(unsafe { hyper_sys::pending_virtual_machine_abort(raw.get()) });
    if status != Status::OK {
        return Err(ConsumingFailure {
            error: Error::Status(status),
            handle: pending,
        });
    }
    let _ = pending.into_raw();
    Ok(())
}

/// Requests asynchronous VM shutdown without waiting for resource retirement.
///
/// Use [`wait_terminated`] when the next operation depends on acknowledged
/// retirement; a successful stop request alone does not establish that boundary.
pub fn request_stop(machine: HandleRef<'_, VirtualMachineObject>) -> Result<()> {
    // SAFETY: the handle remains borrowed for the complete call.
    Status::from_raw(unsafe { hyper_sys::virtual_machine_request_stop(machine.raw().get()) })
        .into_result()
}

/// Waits for acknowledged VM retirement after a stop request or owner loss.
pub fn wait_terminated(machine: HandleRef<'_, VirtualMachineObject>, deadline: u64) -> Result<()> {
    let expected = hyper_abi::HYPER_NATIVE_SIGNAL_VIRTUAL_MACHINE_TERMINATED;
    // SAFETY: the typed VM handle remains borrowed across this non-retaining
    // wait operation.
    let result = unsafe { hyper_sys::object_wait_one(machine.raw().get(), expected, deadline) };
    Status::from_raw(result.status).into_result()?;
    if result.value0 & expected == expected {
        Ok(())
    } else {
        Err(Error::InvalidResponse)
    }
}

/// Waits until one vCPU has completed scheduler reaping and its terminal
/// reason is stable for inspection.
pub fn wait_vcpu_terminated(vcpu: HandleRef<'_, VirtualCpuObject>, deadline: u64) -> Result<()> {
    let expected = hyper_abi::HYPER_NATIVE_SIGNAL_VIRTUAL_CPU_TERMINATED;
    // SAFETY: the typed vCPU handle remains borrowed across this non-retaining
    // wait operation.
    let result = unsafe { hyper_sys::object_wait_one(vcpu.raw().get(), expected, deadline) };
    Status::from_raw(result.status).into_result()?;
    if result.value0 & expected == expected {
        Ok(())
    } else {
        Err(Error::InvalidResponse)
    }
}

/// A guaranteed local guest contract, valid across admitted CPU migration.
/// `riscv_isa` is a minimum subset, not a complete host extension enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualMachinePlatformInfo {
    pub architecture: Architecture,
    pub platform_profile: PlatformProfile,
    pub counter_frequency_hz: u64,
    pub riscv_isa: u64,
    pub aarch64_gic_version: u64,
}

pub fn platform_info(
    lease: HandleRef<'_, VirtualMachineCreationLeaseObject>,
    profile: PlatformProfile,
) -> Result<VirtualMachinePlatformInfo> {
    let mut record = hyper_abi::HyperNativeVirtualMachinePlatformInfo {
        architecture: 0,
        platform_profile: 0,
        counter_frequency_hz: 0,
        riscv_isa: 0,
        aarch64_gic_version: 0,
    };
    // SAFETY: the lease remains borrowed and the output record writable.
    let result = unsafe {
        hyper_sys::virtual_machine_creation_lease_get_platform_info(
            lease.raw().get(),
            profile as u32,
            &mut record,
        )
    };
    let _supported_size = crate::validate_info_result(
        result,
        hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_PLATFORM_INFO_MIN_SIZE,
    )?;
    let architecture = decode_architecture(record.architecture)?;
    let platform_profile = decode_platform_profile(record.platform_profile)?;
    if platform_profile != profile
        || record.counter_frequency_hz == 0
        || !matches!(
            (architecture, platform_profile),
            (Architecture::Aarch64, PlatformProfile::Aarch64Reference)
                | (Architecture::Riscv64, PlatformProfile::Riscv64Reference)
        )
        || (architecture != Architecture::Riscv64 && record.riscv_isa != 0)
        || match architecture {
            Architecture::Aarch64 => !matches!(record.aarch64_gic_version, 2 | 3),
            _ => record.aarch64_gic_version != 0,
        }
    {
        return Err(Error::InvalidResponse);
    }
    Ok(VirtualMachinePlatformInfo {
        architecture,
        platform_profile,
        counter_frequency_hz: record.counter_frequency_hz,
        riscv_isa: record.riscv_isa,
        aarch64_gic_version: record.aarch64_gic_version,
    })
}

pub fn machine_info(machine: HandleRef<'_, VirtualMachineObject>) -> Result<VirtualMachineInfo> {
    let mut record = hyper_abi::HyperNativeVirtualMachineInfo {
        phase: 0,
        vcpu_count: 0,
        guest_physical_base: 0,
        memory_size: 0,
        resident_memory_bytes: u64::MAX,
        architecture: 0,
        platform_profile: 0,
    };
    // SAFETY: the handle remains borrowed and the output record writable.
    let result = unsafe { hyper_sys::virtual_machine_get_info(machine.raw().get(), &mut record) };
    let supported_size = crate::validate_info_result(
        result,
        hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_INFO_MIN_SIZE,
    )?;
    Ok(VirtualMachineInfo {
        phase: decode_machine_phase(record.phase)?,
        vcpu_count: record.vcpu_count,
        guest_physical_base: record.guest_physical_base,
        memory_size: record.memory_size,
        resident_memory_bytes: decode_resident_memory(record.resident_memory_bytes, supported_size),
        architecture: decode_architecture(record.architecture)?,
        platform_profile: decode_platform_profile(record.platform_profile)?,
    })
}

fn decode_resident_memory(raw: u64, supported_size: usize) -> Option<u64> {
    let end = core::mem::offset_of!(
        hyper_abi::HyperNativeVirtualMachineInfo,
        resident_memory_bytes
    ) + core::mem::size_of::<u64>();
    (supported_size >= end && raw != u64::MAX).then_some(raw)
}

pub fn vcpu_info(vcpu: HandleRef<'_, VirtualCpuObject>) -> Result<VirtualCpuInfo> {
    let mut record = hyper_abi::HyperNativeVirtualCpuInfo {
        host_cpu: u32::MAX,
        migration_target: u32::MAX,
        vcpu_id: 0,
        phase: 0,
        scheduler_thread_id: 0,
        terminal_reason: 0,
        reserved: 0,
    };
    // SAFETY: the handle remains borrowed and the output record writable.
    let result = unsafe { hyper_sys::virtual_cpu_get_info(vcpu.raw().get(), &mut record) };
    let supported_size =
        crate::validate_info_result(result, hyper_abi::HYPER_NATIVE_VIRTUAL_CPU_INFO_MIN_SIZE)?;
    if record.reserved != 0 {
        return Err(Error::InvalidResponse);
    }
    let phase = decode_vcpu_phase(record.phase)?;
    let terminal = decode_vcpu_terminal(record.terminal_reason)?;
    if (phase == VirtualCpuPhase::Stopped) != terminal.is_some() {
        return Err(Error::InvalidResponse);
    }
    Ok(VirtualCpuInfo {
        id: record.vcpu_id,
        phase,
        scheduler_thread_id: record.scheduler_thread_id,
        terminal,
        host_cpu: decode_cpu_assignment(record.host_cpu, supported_size, 28),
        migration_target: decode_cpu_assignment(record.migration_target, supported_size, 32),
    })
}

fn decode_cpu_assignment(value: u32, supported_size: usize, field_end: usize) -> Option<u32> {
    (supported_size >= field_end && value != u32::MAX).then_some(value)
}

fn decode_architecture(raw: u32) -> Result<Architecture> {
    match raw {
        value if value == Architecture::Aarch64 as u32 => Ok(Architecture::Aarch64),
        value if value == Architecture::Riscv64 as u32 => Ok(Architecture::Riscv64),
        value if value == Architecture::X86_64 as u32 => Ok(Architecture::X86_64),
        _ => Err(Error::InvalidResponse),
    }
}

fn decode_platform_profile(raw: u32) -> Result<PlatformProfile> {
    match raw {
        value if value == PlatformProfile::Aarch64Reference as u32 => {
            Ok(PlatformProfile::Aarch64Reference)
        }
        value if value == PlatformProfile::Riscv64Reference as u32 => {
            Ok(PlatformProfile::Riscv64Reference)
        }
        _ => Err(Error::InvalidResponse),
    }
}

fn decode_machine_phase(raw: u32) -> Result<VirtualMachinePhase> {
    match u64::from(raw) {
        hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_PHASE_INSTALLED => {
            Ok(VirtualMachinePhase::Installed)
        }
        hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_PHASE_RUNNING => Ok(VirtualMachinePhase::Running),
        hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_PHASE_STOPPING => Ok(VirtualMachinePhase::Stopping),
        hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_PHASE_STOPPED => Ok(VirtualMachinePhase::Stopped),
        _ => Err(Error::InvalidResponse),
    }
}

fn decode_vcpu_phase(raw: u32) -> Result<VirtualCpuPhase> {
    match u64::from(raw) {
        hyper_abi::HYPER_NATIVE_VIRTUAL_CPU_PHASE_DORMANT => Ok(VirtualCpuPhase::Dormant),
        hyper_abi::HYPER_NATIVE_VIRTUAL_CPU_PHASE_STARTED => Ok(VirtualCpuPhase::Started),
        hyper_abi::HYPER_NATIVE_VIRTUAL_CPU_PHASE_STOPPED => Ok(VirtualCpuPhase::Stopped),
        _ => Err(Error::InvalidResponse),
    }
}

fn decode_vcpu_terminal(raw: u32) -> Result<Option<VirtualCpuTermination>> {
    match u64::from(raw) {
        hyper_abi::HYPER_NATIVE_VIRTUAL_CPU_TERMINAL_NONE => Ok(None),
        hyper_abi::HYPER_NATIVE_VIRTUAL_CPU_TERMINAL_MEMORY_FAULT => {
            Ok(Some(VirtualCpuTermination::MemoryFault))
        }
        hyper_abi::HYPER_NATIVE_VIRTUAL_CPU_TERMINAL_MMIO => Ok(Some(VirtualCpuTermination::Mmio)),
        hyper_abi::HYPER_NATIVE_VIRTUAL_CPU_TERMINAL_SYNCHRONOUS => {
            Ok(Some(VirtualCpuTermination::Synchronous))
        }
        hyper_abi::HYPER_NATIVE_VIRTUAL_CPU_TERMINAL_ADMINISTRATIVE => {
            Ok(Some(VirtualCpuTermination::Administrative))
        }
        _ => Err(Error::InvalidResponse),
    }
}

fn adopt<T: TypedObject>(
    raw: u64,
    rights: Rights,
    live_inputs: &[NonZeroU64],
) -> Result<OwnedHandle<T>> {
    // SAFETY: every caller invokes this exactly once for a successful syscall
    // result; malformed aliases of retained borrows are rejected first.
    let owner =
        unsafe { crate::handle::adopt_produced_handle_excluding::<AnyObject>(raw, live_inputs)? };
    validate_adopted(owner, rights)
}

fn validate_adopted<T: TypedObject>(
    owner: OwnedHandle<AnyObject>,
    rights: Rights,
) -> Result<OwnedHandle<T>> {
    let info = owner.info()?;
    if info.rights != rights {
        return Err(Error::InvalidResponse);
    }
    owner.downcast::<T>().map_err(|failure| failure.error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_requires_complete_appended_fields() {
        for size in 24..28 {
            assert_eq!(decode_cpu_assignment(2, size, 28), None);
        }
        assert_eq!(decode_cpu_assignment(2, 28, 28), Some(2));
        for size in 24..32 {
            assert_eq!(decode_cpu_assignment(3, size, 32), None);
        }
        assert_eq!(decode_cpu_assignment(3, 32, 32), Some(3));
        assert_eq!(decode_cpu_assignment(u32::MAX, 32, 32), None);
    }

    #[test]
    fn affinity_encoding_is_bounded_nonempty_and_little_endian() {
        assert!(encode_vcpu_affinity(&[]).is_err());
        assert!(encode_vcpu_affinity(&[0]).is_err());
        assert!(encode_vcpu_affinity(&[1; VCPU_AFFINITY_MAX_WORDS + 1]).is_err());
        let mut expected = [0; VCPU_AFFINITY_MAX_WORDS];
        expected[0] = 5_u64.to_le();
        expected[1] = (1_u64 << 63).to_le();
        assert_eq!(encode_vcpu_affinity(&[5, 1_u64 << 63]), Ok(expected));
    }

    #[test]
    fn resident_memory_requires_complete_appended_info_field() {
        for size in 32..40 {
            assert_eq!(decode_resident_memory(4096, size), None);
        }
        assert_eq!(decode_resident_memory(4096, 40), Some(4096));
        assert_eq!(decode_resident_memory(u64::MAX, 40), None);
        assert_eq!(decode_resident_memory(0, 48), Some(0));
    }

    #[test]
    fn virtual_machine_architectures_decode_to_typed_values() {
        assert_eq!(
            decode_architecture(
                hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_ARCHITECTURE_AARCH64 as u32
            ),
            Ok(Architecture::Aarch64)
        );
        assert_eq!(
            decode_architecture(
                hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_ARCHITECTURE_RISCV64 as u32
            ),
            Ok(Architecture::Riscv64)
        );
        assert_eq!(
            decode_architecture(hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_ARCHITECTURE_X86_64 as u32),
            Ok(Architecture::X86_64)
        );
        assert_eq!(decode_architecture(u32::MAX), Err(Error::InvalidResponse));
    }

    #[test]
    fn virtual_machine_platform_profiles_decode_to_typed_values() {
        assert_eq!(
            decode_platform_profile(
                hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE as u32,
            ),
            Ok(PlatformProfile::Aarch64Reference)
        );
        assert_eq!(
            decode_platform_profile(
                hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_RISCV64_REFERENCE as u32
            ),
            Ok(PlatformProfile::Riscv64Reference)
        );
        assert_eq!(
            decode_platform_profile(u32::MAX),
            Err(Error::InvalidResponse)
        );
    }
}

/// A guest request whose lifecycle policy belongs to the owning VM runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerOperation {
    CpuOn,
    CpuOff,
    SystemOff,
    SystemReset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowerRequest {
    pub id: u64,
    pub vcpu: u32,
    pub operation: PowerOperation,
    pub target: u32,
    pub entry: u64,
    pub context: u64,
}

/// Snapshots pending work. Only completion consumes it; multiple inspections
/// can observe the same ID, which must be completed at most once.
pub fn pending_power_request(
    machine: HandleRef<'_, VirtualMachineObject>,
) -> Result<Option<PowerRequest>> {
    let mut record = hyper_abi::HyperNativeVirtualMachinePowerRequest {
        id: 0,
        vcpu: 0,
        operation: 0,
        target: 0,
        reserved: 0,
        entry: 0,
        context: 0,
    };
    // SAFETY: The borrowed handle and writable record remain live for the call.
    let result =
        unsafe { hyper_sys::virtual_machine_get_power_request(machine.raw().get(), &mut record) };
    if Status::from_raw(result.status) == Status::WOULD_BLOCK {
        return Ok(None);
    }
    crate::validate_info_result(
        result,
        hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_POWER_REQUEST_MIN_SIZE,
    )?;
    if record.id == 0 || record.reserved != 0 {
        return Err(Error::InvalidResponse);
    }
    let operation = match u64::from(record.operation) {
        hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_POWER_CPU_ON => PowerOperation::CpuOn,
        hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_POWER_CPU_OFF => PowerOperation::CpuOff,
        hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_POWER_SYSTEM_OFF => PowerOperation::SystemOff,
        hyper_abi::HYPER_NATIVE_VIRTUAL_MACHINE_POWER_SYSTEM_RESET => PowerOperation::SystemReset,
        _ => return Err(Error::InvalidResponse),
    };
    Ok(Some(PowerRequest {
        id: record.id,
        vcpu: record.vcpu,
        operation,
        target: record.target,
        entry: record.entry,
        context: record.context,
    }))
}

/// Accepts or rejects one exact request; cancellation or an earlier completion
/// makes its ID stale. Acceptance does not imply global VM retirement finished.
pub fn complete_power_request(
    machine: HandleRef<'_, VirtualMachineObject>,
    request_id: u64,
    accept: bool,
) -> Result<()> {
    // SAFETY: The borrowed handle remains live throughout the call.
    Status::from_raw(unsafe {
        hyper_sys::virtual_machine_complete_power_request(
            machine.raw().get(),
            request_id,
            u32::from(accept),
        )
    })
    .into_result()
}

/// Opens control authority for a member of the VM's immutable CPU topology.
pub fn open_vcpu(
    machine: HandleRef<'_, VirtualMachineObject>,
    vcpu_id: u32,
) -> Result<OwnedHandle<VirtualCpuObject>> {
    // SAFETY: The input remains borrowed; the result is adopted once below.
    let result = unsafe { hyper_sys::virtual_machine_open_vcpu(machine.raw().get(), vcpu_id) };
    Status::from_raw(result.status).into_result()?;
    adopt(result.value0, VCPU_RIGHTS, &[machine.raw()])
}

/// Registers a device identity and page-aligned aperture before first vCPU start.
pub fn register_mmio(
    machine: HandleRef<'_, VirtualMachineObject>,
    base: u64,
    length: u64,
    device: NonZeroU64,
) -> Result<()> {
    // SAFETY: The borrowed machine capability remains live throughout the call.
    Status::from_raw(unsafe {
        hyper_sys::virtual_machine_register_mmio(machine.raw().get(), base, length, device.get())
    })
    .into_result()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioOperation {
    Read,
    Write(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioRequest {
    pub id: NonZeroU64,
    pub device: NonZeroU64,
    pub address: u64,
    /// Access width in bytes: 1, 2, 4 or 8.
    pub width: u32,
    pub operation: MmioOperation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioCompletion {
    Read(u64),
    Write,
    /// Stops the VM; it cannot safely resume this instruction.
    Abort,
}

/// Non-consuming inspection; use `MMIO_REQUEST` with `WaitSet` to wait for work.
pub fn pending_mmio(vcpu: HandleRef<'_, VirtualCpuObject>) -> Result<Option<MmioRequest>> {
    let mut record = hyper_abi::HyperNativeVirtualCpuMmioRequest {
        id: 0,
        device: 0,
        address: 0,
        value: 0,
        operation: 0,
        width: 0,
        reserved: 0,
    };
    // SAFETY: The typed handle and initialized output remain live for the call.
    let result = unsafe { hyper_sys::virtual_cpu_get_mmio_request(vcpu.raw().get(), &mut record) };
    if Status::from_raw(result.status) == Status::WOULD_BLOCK {
        return Ok(None);
    }
    crate::validate_info_result(
        result,
        hyper_abi::HYPER_NATIVE_VIRTUAL_CPU_MMIO_REQUEST_MIN_SIZE,
    )?;
    if record.reserved != 0 || !matches!(record.width, 1 | 2 | 4 | 8) {
        return Err(Error::InvalidResponse);
    }
    let operation = match (record.operation, record.value) {
        (0, 0) => MmioOperation::Read,
        (1, value) => MmioOperation::Write(value),
        _ => return Err(Error::InvalidResponse),
    };
    Ok(Some(MmioRequest {
        id: NonZeroU64::new(record.id).ok_or(Error::InvalidResponse)?,
        device: NonZeroU64::new(record.device).ok_or(Error::InvalidResponse)?,
        address: record.address,
        width: record.width,
        operation,
    }))
}

/// Completes one instruction. A stale ID or a mismatched read/write kind fails.
pub fn complete_mmio(
    vcpu: HandleRef<'_, VirtualCpuObject>,
    id: NonZeroU64,
    completion: MmioCompletion,
) -> Result<()> {
    let (operation, value) = match completion {
        MmioCompletion::Read(value) => (0, value),
        MmioCompletion::Write => (1, 0),
        MmioCompletion::Abort => (2, 0),
    };
    // SAFETY: The borrowed handle remains live throughout the call.
    Status::from_raw(unsafe {
        hyper_sys::virtual_cpu_complete_mmio(vcpu.raw().get(), id.get(), operation, value)
    })
    .into_result()
}

/// Freezes the VMO against Native writes and snapshots while any guest-memory
/// capability or installed guest mapping retains it. Physical backing remains
/// stable across sharing and source-handle closure.
pub fn create_guest_memory(
    vmo: HandleRef<'_, VmoObject>,
) -> Result<OwnedHandle<crate::handle::GuestMemoryObject>> {
    // SAFETY: The borrowed VMO remains live; returned ownership is adopted once.
    let result = unsafe { hyper_sys::guest_memory_create(vmo.raw().get()) };
    Status::from_raw(result.status).into_result()?;
    if result.value1 != 0 {
        return Err(Error::InvalidResponse);
    }
    adopt(
        result.value0,
        Rights::TRANSFER
            .union(Rights::DUPLICATE)
            .union(Rights::MAP)
            .union(Rights::INSPECT),
        &[vmo.raw()],
    )
}

/// Adds non-overlapping RAM coverage before seal. Offsets and length must be
/// page-aligned; sealing requires complete coverage of configured guest RAM.
pub fn map_guest_memory(
    pending: HandleRef<'_, PendingVirtualMachineObject>,
    memory: HandleRef<'_, crate::handle::GuestMemoryObject>,
    guest_offset: u64,
    source_offset: u64,
    length: u64,
) -> Result<()> {
    // SAFETY: Both typed handles remain borrowed throughout the call.
    Status::from_raw(unsafe {
        hyper_sys::pending_virtual_machine_map_memory(
            pending.raw().get(),
            memory.raw().get(),
            guest_offset,
            source_offset,
            length,
        )
    })
    .into_result()
}

/// Fixed affine DMA alias window. Actual admitted pages remain constrained by
/// the stable grant and the physical device's immutable DMA translation map.
pub const IO_MAX_CLIENTS: usize = hyper_abi::HYPER_NATIVE_IO_MAX_CLIENTS as usize;

/// `AArch64` reference GIC INTIDs, including SGIs and PPIs.
pub const AARCH64_INTERRUPT_COUNT: u32 =
    hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_INTERRUPT_COUNT as u32;
/// First reference-platform INTID available for assigned devices and I/O routes.
pub const AARCH64_DEVICE_INTERRUPT_BASE: u32 =
    hyper_abi::HYPER_NATIVE_VIRTUAL_PLATFORM_AARCH64_REFERENCE_DEVICE_INTERRUPT_BASE as u32;
pub const DYNAMIC_ALIAS_OFFSET: u64 = hyper_abi::HYPER_NATIVE_GUEST_DYNAMIC_ALIAS_OFFSET;
pub const DYNAMIC_PHYSICAL_LIMIT: u64 = hyper_abi::HYPER_NATIVE_GUEST_DYNAMIC_PHYSICAL_LIMIT;

pub struct GuestMapping {
    handle: OwnedHandle<crate::handle::GuestMappingObject>,
    token: u64,
}
impl GuestMapping {
    pub fn token(&self) -> u64 {
        self.token
    }
    /// Release requires a backend-origin quiescence proof after vhost drain.
    /// A failed release retains ownership; dropping alone quarantines the grant.
    /// `Status::WOULD_BLOCK` means the shared all-CPU synchronization transport
    /// is occupied: retry this same call without resetting or releasing Linux
    /// state again. `Status::BUSY` means the backend has not supplied its
    /// quiescence proof; complete backend drain/release before retrying.
    pub fn release(&self) -> Result<()> {
        // SAFETY: the mapping capability is borrowed through completion.
        let result =
            unsafe { hyper_sys::guest_mapping_release(self.handle.as_handle_ref().raw().get()) };
        Status::from_raw(result.status).into_result()?;
        if result.value0 != 0 || result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }
}

/// Populate and retain the entire stable grant as sparse affine DMA aliases in
/// an installed or running backend. No physical contiguity is required.
/// Admission is serialized with backend stop; a stopping backend rejects it.
/// `WOULD_BLOCK` means concurrent metadata growth exhausted the bounded
/// preparation retries; no mapping was published, so retrying create is safe.
pub fn map_shared_guest_memory(
    backend: HandleRef<'_, VirtualMachineObject>,
    memory: HandleRef<'_, crate::handle::GuestMemoryObject>,
    frontend_base: u64,
) -> Result<GuestMapping> {
    // SAFETY: input capabilities remain borrowed; the kernel retains its own
    // independent hardware mapping lease.
    let result = unsafe {
        hyper_sys::guest_mapping_create(backend.raw().get(), memory.raw().get(), frontend_base)
    };
    Status::from_raw(result.status).into_result()?;
    // SAFETY: successful create returns an independently owned mapping handle.
    let owner = unsafe {
        crate::handle::adopt_produced_handle_excluding::<AnyObject>(
            result.value0,
            &[backend.raw(), memory.raw()],
        )?
    };
    let rights = Rights::WRITE.union(Rights::TRANSFER).union(Rights::INSPECT);
    if result.value1 == 0 || owner.info()?.rights != rights {
        return Err(Error::InvalidResponse);
    }
    Ok(GuestMapping {
        handle: owner
            .downcast::<crate::handle::GuestMappingObject>()
            .map_err(|failure| failure.error())?,
        token: result.value1,
    })
}
