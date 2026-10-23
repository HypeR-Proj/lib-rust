// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Capability-scoped task and kernel-object observation.
//!
//! KOIDs and scan cursors are diagnostic values only. Native task operations
//! continue to require typed handles; this module intentionally provides no
//! lookup which converts an observed identifier into authority.

mod details;
pub mod memory;
pub mod profile;
pub use details::{
    DetailCursor, DetailRecord, DetailTarget, DeviceState, MappingPermissions, ObjectDetails,
    UserThreadPhase,
};

use core::num::NonZeroU64;

pub use crate::handle::Koid;

use crate::handle::{
    AnyObject, CpuInspectorObject, MemoryInspectorObject, ObjectInspectorObject, ObjectKind,
    ProcessObject, ResourceDomainObject, TaskGroupObject, TaskInspectorObject, TypedObject,
};
use crate::{Error, HandleRef, OwnedHandle, Result, Rights, Status};

pub const PROCESS_PAGE_CAPACITY: usize =
    hyper_abi::HYPER_NATIVE_TASK_INSPECTOR_PROCESS_PAGE_CAPACITY as usize;
pub const THREAD_PAGE_CAPACITY: usize =
    hyper_abi::HYPER_NATIVE_TASK_INSPECTOR_THREAD_PAGE_CAPACITY as usize;
pub const OBJECT_PAGE_CAPACITY: usize =
    hyper_abi::HYPER_NATIVE_OBJECT_INSPECTOR_OBJECT_PAGE_CAPACITY as usize;
pub const HANDLE_PAGE_CAPACITY: usize =
    hyper_abi::HYPER_NATIVE_OBJECT_INSPECTOR_HANDLE_PAGE_CAPACITY as usize;
const TASK_NAME_CAPACITY: usize = hyper_abi::HYPER_NATIVE_PROCESS_NAME_MAX_BYTES as usize;
const _: () = assert!(TASK_NAME_CAPACITY <= u8::MAX as usize);

const INSPECTOR_RIGHTS: Rights = Rights::DUPLICATE
    .union(Rights::TRANSFER)
    .union(Rights::INSPECT)
    .union(Rights::DERIVE);

/// Validated immutable task name returned by an inspector scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskName {
    bytes: [u8; TASK_NAME_CAPACITY],
    len: u8,
}

impl TaskName {
    fn decode(bytes: [u8; TASK_NAME_CAPACITY], length: u32) -> Result<Self> {
        let len = usize::try_from(length).map_err(|_| Error::InvalidResponse)?;
        let value = bytes.get(..len).ok_or(Error::InvalidResponse)?;
        core::str::from_utf8(value).map_err(|_| Error::InvalidResponse)?;
        if bytes[len..].iter().any(|byte| *byte != 0) {
            return Err(Error::InvalidResponse);
        }
        let len = u8::try_from(length).map_err(|_| Error::InvalidResponse)?;
        Ok(Self { bytes, len })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        let bytes = &self.bytes[..usize::from(self.len)];
        let Ok(name) = core::str::from_utf8(bytes) else {
            return "";
        };
        name
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessPhase {
    Prepared,
    Created,
    Running,
    Stopping,
    Stopped,
    Retiring,
    Retired,
}

impl ProcessPhase {
    fn decode(raw: u32) -> Result<Self> {
        match u64::from(raw) {
            hyper_abi::HYPER_NATIVE_PROCESS_PHASE_PREPARED => Ok(Self::Prepared),
            hyper_abi::HYPER_NATIVE_PROCESS_PHASE_CREATED => Ok(Self::Created),
            hyper_abi::HYPER_NATIVE_PROCESS_PHASE_RUNNING => Ok(Self::Running),
            hyper_abi::HYPER_NATIVE_PROCESS_PHASE_STOPPING => Ok(Self::Stopping),
            hyper_abi::HYPER_NATIVE_PROCESS_PHASE_STOPPED => Ok(Self::Stopped),
            hyper_abi::HYPER_NATIVE_PROCESS_PHASE_RETIRING => Ok(Self::Retiring),
            hyper_abi::HYPER_NATIVE_PROCESS_PHASE_RETIRED => Ok(Self::Retired),
            _ => Err(Error::InvalidResponse),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalReason {
    Requested,
    ThreadExited,
    ProcessExited,
    LastThreadExited,
    Fault,
    TaskGroupStop,
}

impl TerminalReason {
    fn decode(raw: u32) -> Result<Option<Self>> {
        match u64::from(raw) {
            hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_NONE => Ok(None),
            hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_REQUESTED => Ok(Some(Self::Requested)),
            hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_THREAD_EXITED => Ok(Some(Self::ThreadExited)),
            hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_PROCESS_EXITED => {
                Ok(Some(Self::ProcessExited))
            }
            hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_LAST_THREAD_EXITED => {
                Ok(Some(Self::LastThreadExited))
            }
            hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_FAULT => Ok(Some(Self::Fault)),
            hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_TASK_GROUP_STOP => {
                Ok(Some(Self::TaskGroupStop))
            }
            _ => Err(Error::InvalidResponse),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::ThreadExited => "thread-exited",
            Self::ProcessExited => "process-exited",
            Self::LastThreadExited => "last-thread-exited",
            Self::Fault => "fault",
            Self::TaskGroupStop => "task-group-stop",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadRole {
    Bootstrap,
    Idle,
    Kernel,
    User,
    Vcpu,
}

impl ThreadRole {
    fn decode(raw: u32) -> Result<Self> {
        match u64::from(raw) {
            hyper_abi::HYPER_NATIVE_THREAD_ROLE_BOOTSTRAP => Ok(Self::Bootstrap),
            hyper_abi::HYPER_NATIVE_THREAD_ROLE_IDLE => Ok(Self::Idle),
            hyper_abi::HYPER_NATIVE_THREAD_ROLE_KERNEL => Ok(Self::Kernel),
            hyper_abi::HYPER_NATIVE_THREAD_ROLE_USER => Ok(Self::User),
            hyper_abi::HYPER_NATIVE_THREAD_ROLE_VCPU => Ok(Self::Vcpu),
            _ => Err(Error::InvalidResponse),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Idle => "idle",
            Self::Kernel => "kernel",
            Self::User => "user",
            Self::Vcpu => "vcpu",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadRegistryPhase {
    Resident,
    Retiring,
}

impl ThreadRegistryPhase {
    fn decode(raw: u32) -> Result<Self> {
        match u64::from(raw) {
            hyper_abi::HYPER_NATIVE_THREAD_REGISTRY_RESIDENT => Ok(Self::Resident),
            hyper_abi::HYPER_NATIVE_THREAD_REGISTRY_RETIRING => Ok(Self::Retiring),
            _ => Err(Error::InvalidResponse),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Resident => "resident",
            Self::Retiring => "retiring",
        }
    }
}

/// Opaque position in one weakly consistent inspector scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanCursor(u64);

impl ScanCursor {
    pub const START: Self = Self(0);
}

/// One bounded scan result.
pub struct InspectionPage<T: Copy, const N: usize> {
    entries: [Option<T>; N],
    len: usize,
    next: Option<ScanCursor>,
}

impl<T: Copy, const N: usize> InspectionPage<T, N> {
    fn empty(next: Option<ScanCursor>) -> Self {
        Self {
            entries: [None; N],
            len: 0,
            next,
        }
    }

    fn push(&mut self, value: T) -> Result<()> {
        let slot = self
            .entries
            .get_mut(self.len)
            .ok_or(Error::InvalidResponse)?;
        *slot = Some(value);
        self.len += 1;
        Ok(())
    }

    pub fn entries(&self) -> impl Iterator<Item = &T> {
        self.entries[..self.len].iter().filter_map(Option::as_ref)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub const fn next(&self) -> Option<ScanCursor> {
        self.next
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessObservation {
    pub koid: Koid,
    pub name: TaskName,
    pub phase: ProcessPhase,
    pub terminal_reason: Option<TerminalReason>,
    pub pending_threads: u32,
    pub active_threads: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadObservation {
    pub koid: Koid,
    pub process_koid: Option<Koid>,
    pub name: TaskName,
    pub role: ThreadRole,
    pub registry_phase: ThreadRegistryPhase,
    pub runtime_ns: u64,
}

/// Physical allocation counters plus independently sampled reclaimability.
///
/// Direct kernel, slab, large heap, page tables, VMO, private guest, and file
/// cache bytes are disjoint. Guest-loaned bytes are a subset of VMO bytes,
/// counted once per backing lease, including aliases shared with an I/O VM.
/// Reserved memory and display totals are derived by consumers. All physical
/// categories describe resident backing, never virtual address-space capacity.
/// File-cache bytes include its dedicated heap metadata; those pages are
/// excluded from slab and large-heap bytes to keep the categories disjoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryObservation {
    pub captured_at_ns: u64,
    pub page_size: u64,
    pub total_bytes: u64,
    pub managed_bytes: u64,
    pub free_bytes: u64,
    pub kernel_bytes: u64,
    pub slab_bytes: u64,
    pub large_heap_bytes: u64,
    pub page_table_bytes: u64,
    pub vmo_bytes: u64,
    pub guest_loaned_bytes: u64,
    pub guest_private_bytes: u64,
    pub file_cache_bytes: u64,
    /// Whole slab pages recoverable by draining CPU-local magazines.
    /// None means the bounded concurrent census could not complete.
    pub slab_reclaimable_bytes: Option<u64>,
    /// Unpinned file payload pages plus shrinker-managed index/header backing;
    /// independent of the slab census. This is an estimate: live pins can retain
    /// a minimum metadata set, so not every byte is immediately recoverable.
    /// Some(0) is a successful observation of an empty reclaimable pool.
    pub file_cache_reclaimable_bytes: Option<u64>,
    /// Live ramfs payload capacity reservations, excluding archive contents.
    /// Logical bytes overlap heap backing, but exclude allocator overhead and
    /// rounding; they are not another physical category or reclaimable cache.
    pub ramfs_capacity_bytes: u64,
}

/// One immutable aggregate scheduler CPU-time observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuObservation {
    pub captured_at_ns: u64,
    pub online_cpus: u64,
    pub idle_ns: u64,
    pub kernel_thread_ns: u64,
    pub user_thread_ns: u64,
    pub vcpu_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectHandleState {
    Unpublished,
    Active(u64),
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectReferenceCounts {
    pub strong: u64,
    pub kernel_service: u64,
    pub vm_device_binding: u64,
    pub scheduler: u64,
    pub operation: u64,
    pub user_authority: u64,
    pub publication: u64,
    pub diagnostic: u64,
    pub retirement: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectObservation {
    pub koid: Koid,
    pub object_kind: ObjectKind,
    pub handles: ObjectHandleState,
    pub supported_rights: Rights,
    pub references: ObjectReferenceCounts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleObservation {
    pub process_koid: Koid,
    pub handle: u64,
    pub object_koid: Koid,
    pub rights: Rights,
    pub object_kind: ObjectKind,
    pub flags: u32,
}

/// Immutable task-observation authority.
pub struct TaskInspector {
    handle: OwnedHandle<TaskInspectorObject>,
}

impl TaskInspector {
    #[must_use]
    pub const fn from_handle(handle: OwnedHandle<TaskInspectorObject>) -> Self {
        Self { handle }
    }

    pub fn scan_processes(
        &self,
        cursor: ScanCursor,
    ) -> Result<InspectionPage<ProcessObservation, PROCESS_PAGE_CAPACITY>> {
        let mut records = [ZERO_PROCESS; PROCESS_PAGE_CAPACITY];
        let result = raw_ops::scan_processes(self.handle.as_handle_ref(), cursor.0, &mut records);
        let (count, next) = decode_scan_result(result, PROCESS_PAGE_CAPACITY)?;
        let mut page = InspectionPage::empty(next);
        for record in &records[..count] {
            page.push(ProcessObservation {
                koid: Koid::from_raw(record.koid)?,
                name: TaskName::decode(record.name, record.name_length)?,
                phase: ProcessPhase::decode(record.phase)?,
                terminal_reason: TerminalReason::decode(record.terminal_reason)?,
                pending_threads: record.pending_threads,
                active_threads: record.active_threads,
            })?;
        }
        Ok(page)
    }

    pub fn scan_threads(
        &self,
        cursor: ScanCursor,
    ) -> Result<InspectionPage<ThreadObservation, THREAD_PAGE_CAPACITY>> {
        let mut records = [ZERO_THREAD; THREAD_PAGE_CAPACITY];
        let result = raw_ops::scan_threads(self.handle.as_handle_ref(), cursor.0, &mut records);
        let (count, next) = decode_scan_result(result, THREAD_PAGE_CAPACITY)?;
        let mut page = InspectionPage::empty(next);
        for record in &records[..count] {
            page.push(ThreadObservation {
                koid: Koid::from_raw(record.koid)?,
                process_koid: NonZeroU64::new(record.process_koid).map(Koid::from_nonzero),
                name: TaskName::decode(record.name, record.name_length)?,
                role: ThreadRole::decode(record.role)?,
                registry_phase: ThreadRegistryPhase::decode(record.registry_phase)?,
                runtime_ns: record.runtime_ns,
            })?;
        }
        Ok(page)
    }

    pub fn derive_process(&self, process: HandleRef<'_, ProcessObject>) -> Result<TaskInspector> {
        let inspector = self.handle.as_handle_ref();
        adopt_inspector(
            raw_ops::derive_task_process(inspector, process),
            &[inspector.raw(), process.raw()],
        )
        .map(TaskInspector::from_handle)
    }

    pub fn derive_task_group(
        &self,
        group: HandleRef<'_, TaskGroupObject>,
    ) -> Result<TaskInspector> {
        let inspector = self.handle.as_handle_ref();
        adopt_inspector(
            raw_ops::derive_task_group(inspector, group),
            &[inspector.raw(), group.raw()],
        )
        .map(TaskInspector::from_handle)
    }

    pub fn derive_resource_domain(
        &self,
        domain: HandleRef<'_, ResourceDomainObject>,
    ) -> Result<TaskInspector> {
        let inspector = self.handle.as_handle_ref();
        adopt_inspector(
            raw_ops::derive_task_domain(inspector, domain),
            &[inspector.raw(), domain.raw()],
        )
        .map(TaskInspector::from_handle)
    }

    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, TaskInspectorObject> {
        self.handle.as_handle_ref()
    }
}

/// Immutable physical-memory observation authority.
pub struct MemoryInspector {
    handle: OwnedHandle<MemoryInspectorObject>,
}

impl MemoryInspector {
    #[must_use]
    pub const fn from_handle(handle: OwnedHandle<MemoryInspectorObject>) -> Self {
        Self { handle }
    }

    pub fn read(&self) -> Result<MemoryObservation> {
        let mut record = ZERO_MEMORY;
        // SAFETY: the typed handle remains borrowed and `record` is writable.
        let result = unsafe {
            hyper_sys::memory_inspector_read(self.handle.as_handle_ref().raw().get(), &mut record)
        };
        let _supported_size = crate::validate_info_result(
            result,
            hyper_abi::HYPER_NATIVE_MEMORY_OBSERVATION_MIN_SIZE,
        )?;
        validate_memory_observation(&record)?;
        Ok(MemoryObservation {
            captured_at_ns: record.captured_at_ns,
            page_size: record.page_size,
            total_bytes: record.total_bytes,
            managed_bytes: record.managed_bytes,
            free_bytes: record.free_bytes,
            kernel_bytes: record.kernel_bytes,
            slab_bytes: record.slab_bytes,
            large_heap_bytes: record.large_heap_bytes,
            page_table_bytes: record.page_table_bytes,
            vmo_bytes: record.vmo_bytes,
            guest_loaned_bytes: record.guest_loaned_bytes,
            guest_private_bytes: record.guest_private_bytes,
            file_cache_bytes: record.file_cache_bytes,
            ramfs_capacity_bytes: record.ramfs_capacity_bytes,
            slab_reclaimable_bytes: (record.slab_sample_complete == 1)
                .then_some(record.slab_reclaimable_bytes),
            file_cache_reclaimable_bytes: (record.file_cache_sample_complete == 1)
                .then_some(record.file_cache_reclaimable_bytes),
        })
    }
}

/// Scheduler CPU-time observation and optional, separately authorized PMU control.
pub struct CpuInspector {
    handle: OwnedHandle<CpuInspectorObject>,
}

impl CpuInspector {
    #[must_use]
    pub const fn from_handle(handle: OwnedHandle<CpuInspectorObject>) -> Self {
        Self { handle }
    }

    pub fn read(&self) -> Result<CpuObservation> {
        let mut record = ZERO_CPU;
        // SAFETY: the typed handle remains borrowed and `record` is writable.
        let result = unsafe {
            hyper_sys::cpu_inspector_read(self.handle.as_handle_ref().raw().get(), &mut record)
        };
        let _supported_size =
            crate::validate_info_result(result, hyper_abi::HYPER_NATIVE_CPU_OBSERVATION_MIN_SIZE)?;
        if record.reserved != 0 || record.reserved_clock != 0 || record.online_cpus == 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(CpuObservation {
            captured_at_ns: record.captured_at_ns,
            online_cpus: record.online_cpus,
            idle_ns: record.idle_ns,
            kernel_thread_ns: record.kernel_thread_ns,
            user_thread_ns: record.user_thread_ns,
            vcpu_ns: record.vcpu_ns,
        })
    }
}

fn validate_memory_observation(record: &hyper_abi::HyperNativeMemoryObservation) -> Result<()> {
    let allocated = record.managed_bytes.checked_sub(record.free_bytes);
    let physical = [
        record.kernel_bytes,
        record.slab_bytes,
        record.large_heap_bytes,
        record.page_table_bytes,
        record.vmo_bytes,
        record.guest_private_bytes,
        record.file_cache_bytes,
    ];
    let attributed = physical
        .iter()
        .try_fold(0u64, |sum, bytes| sum.checked_add(*bytes));
    let valid_census =
        |complete, bytes, limit| complete <= 1 && bytes <= limit && (complete == 1 || bytes == 0);
    let valid = record.page_size.is_power_of_two()
        && record.managed_bytes <= record.total_bytes
        && allocated
            .zip(attributed)
            .is_some_and(|(allocated, attributed)| attributed <= allocated)
        && record.guest_loaned_bytes <= record.vmo_bytes
        && valid_census(
            record.slab_sample_complete,
            record.slab_reclaimable_bytes,
            record.slab_bytes,
        )
        && valid_census(
            record.file_cache_sample_complete,
            record.file_cache_reclaimable_bytes,
            record.file_cache_bytes,
        )
        && physical
            .into_iter()
            .chain([
                record.total_bytes,
                record.managed_bytes,
                record.free_bytes,
                record.guest_loaned_bytes,
                record.slab_reclaimable_bytes,
                record.file_cache_reclaimable_bytes,
            ])
            .all(|bytes| bytes.is_multiple_of(record.page_size));
    if !valid {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}

/// Immutable kernel-object and Process-handle observation authority.
pub struct ObjectInspector {
    handle: OwnedHandle<ObjectInspectorObject>,
}

impl ObjectInspector {
    #[must_use]
    pub const fn from_handle(handle: OwnedHandle<ObjectInspectorObject>) -> Self {
        Self { handle }
    }

    pub fn scan_objects(
        &self,
        cursor: ScanCursor,
    ) -> Result<InspectionPage<ObjectObservation, OBJECT_PAGE_CAPACITY>> {
        let mut records = [ZERO_OBJECT; OBJECT_PAGE_CAPACITY];
        let result = raw_ops::scan_objects(self.handle.as_handle_ref(), cursor.0, &mut records);
        let (count, next) = decode_scan_result(result, OBJECT_PAGE_CAPACITY)?;
        let mut page = InspectionPage::empty(next);
        for record in &records[..count] {
            page.push(decode_object_observation(record)?)?;
        }
        Ok(page)
    }

    pub fn scan_handles(
        &self,
        process: Koid,
        cursor: ScanCursor,
    ) -> Result<InspectionPage<HandleObservation, HANDLE_PAGE_CAPACITY>> {
        let mut records = [ZERO_HANDLE; HANDLE_PAGE_CAPACITY];
        let result = raw_ops::scan_handles(
            self.handle.as_handle_ref(),
            process.get(),
            cursor.0,
            &mut records,
        );
        let (count, next) = decode_scan_result(result, HANDLE_PAGE_CAPACITY)?;
        let mut page = InspectionPage::empty(next);
        for record in &records[..count] {
            page.push(HandleObservation {
                process_koid: Koid::from_raw(record.process_koid)?,
                handle: record.handle,
                object_koid: Koid::from_raw(record.object_koid)?,
                rights: Rights::from_bits(record.rights).ok_or(Error::InvalidResponse)?,
                object_kind: ObjectKind::from_kernel(record.object_kind)?,
                flags: record.flags,
            })?;
        }
        Ok(page)
    }

    pub fn derive_process(&self, process: HandleRef<'_, ProcessObject>) -> Result<ObjectInspector> {
        let inspector = self.handle.as_handle_ref();
        adopt_object_inspector(
            raw_ops::derive_object_process(inspector, process),
            &[inspector.raw(), process.raw()],
        )
        .map(ObjectInspector::from_handle)
    }

    pub fn derive_task_group(
        &self,
        group: HandleRef<'_, TaskGroupObject>,
    ) -> Result<ObjectInspector> {
        let inspector = self.handle.as_handle_ref();
        adopt_object_inspector(
            raw_ops::derive_object_group(inspector, group),
            &[inspector.raw(), group.raw()],
        )
        .map(ObjectInspector::from_handle)
    }

    pub fn derive_resource_domain(
        &self,
        domain: HandleRef<'_, ResourceDomainObject>,
    ) -> Result<ObjectInspector> {
        let inspector = self.handle.as_handle_ref();
        adopt_object_inspector(
            raw_ops::derive_object_domain(inspector, domain),
            &[inspector.raw(), domain.raw()],
        )
        .map(ObjectInspector::from_handle)
    }

    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, ObjectInspectorObject> {
        self.handle.as_handle_ref()
    }
}

fn decode_object_observation(
    record: &hyper_abi::HyperNativeObjectInspection,
) -> Result<ObjectObservation> {
    let handles = match record.handle_state as u64 {
        hyper_abi::HYPER_NATIVE_OBJECT_HANDLE_STATE_UNPUBLISHED => ObjectHandleState::Unpublished,
        hyper_abi::HYPER_NATIVE_OBJECT_HANDLE_STATE_ACTIVE => {
            ObjectHandleState::Active(record.active_handles)
        }
        hyper_abi::HYPER_NATIVE_OBJECT_HANDLE_STATE_RETIRED => ObjectHandleState::Retired,
        _ => return Err(Error::InvalidResponse),
    };
    Ok(ObjectObservation {
        koid: Koid::from_raw(record.koid)?,
        object_kind: ObjectKind::from_kernel(record.object_kind)?,
        handles,
        supported_rights: Rights::from_bits(record.supported_rights)
            .ok_or(Error::InvalidResponse)?,
        references: ObjectReferenceCounts {
            strong: record.strong_references,
            kernel_service: record.kernel_service_references,
            vm_device_binding: record.vm_device_binding_references,
            scheduler: record.scheduler_references,
            operation: record.operation_references,
            user_authority: record.user_authority_references,
            publication: record.publication_references,
            diagnostic: record.diagnostic_references,
            retirement: record.retirement_references,
        },
    })
}

fn decode_scan_result(
    result: hyper_sys::CallResult,
    capacity: usize,
) -> Result<(usize, Option<ScanCursor>)> {
    Status::from_raw(result.status).into_result()?;
    let count = usize::try_from(result.value0).map_err(|_| Error::InvalidResponse)?;
    if count > capacity {
        return Err(Error::InvalidResponse);
    }
    Ok((
        count,
        (result.value1 != 0).then_some(ScanCursor(result.value1)),
    ))
}

fn adopt_inspector(
    result: hyper_sys::CallResult,
    live_inputs: &[NonZeroU64],
) -> Result<OwnedHandle<TaskInspectorObject>> {
    adopt_handle(result, TaskInspectorObject::KIND.as_raw(), live_inputs)?
        .downcast()
        .map_err(|failure| failure.error())
}

fn adopt_object_inspector(
    result: hyper_sys::CallResult,
    live_inputs: &[NonZeroU64],
) -> Result<OwnedHandle<ObjectInspectorObject>> {
    adopt_handle(result, ObjectInspectorObject::KIND.as_raw(), live_inputs)?
        .downcast()
        .map_err(|failure| failure.error())
}

fn adopt_handle(
    result: hyper_sys::CallResult,
    expected_kind: u32,
    live_inputs: &[NonZeroU64],
) -> Result<OwnedHandle<AnyObject>> {
    Status::from_raw(result.status).into_result()?;
    // SAFETY: successful derivation publishes one new owner unless malformed
    // output aliases an explicitly retained input borrow.
    let owner = unsafe {
        crate::handle::adopt_produced_handle_excluding::<AnyObject>(result.value0, live_inputs)?
    };
    let info = owner.info()?;
    if info.kind.as_raw() != expected_kind || info.rights != INSPECTOR_RIGHTS {
        return Err(Error::InvalidResponse);
    }
    Ok(owner)
}

const ZERO_PROCESS: hyper_abi::HyperNativeTaskProcess = hyper_abi::HyperNativeTaskProcess {
    koid: 0,
    phase: 0,
    terminal_reason: 0,
    pending_threads: 0,
    active_threads: 0,
    name_length: 0,
    reserved: 0,
    name: [0; 64],
};

const ZERO_THREAD: hyper_abi::HyperNativeTaskThread = hyper_abi::HyperNativeTaskThread {
    koid: 0,
    process_koid: 0,
    role: 0,
    registry_phase: 0,
    name_length: 0,
    reserved: 0,
    runtime_ns: 0,
    name: [0; 64],
};

const ZERO_MEMORY: hyper_abi::HyperNativeMemoryObservation =
    hyper_abi::HyperNativeMemoryObservation {
        captured_at_ns: 0,
        page_size: 0,
        total_bytes: 0,
        managed_bytes: 0,
        free_bytes: 0,
        kernel_bytes: 0,
        slab_bytes: 0,
        large_heap_bytes: 0,
        page_table_bytes: 0,
        vmo_bytes: 0,
        guest_loaned_bytes: 0,
        guest_private_bytes: 0,
        file_cache_bytes: 0,
        slab_reclaimable_bytes: 0,
        slab_sample_complete: 0,
        file_cache_reclaimable_bytes: 0,
        file_cache_sample_complete: 0,
        ramfs_capacity_bytes: 0,
    };

const ZERO_CPU: hyper_abi::HyperNativeCpuObservation = hyper_abi::HyperNativeCpuObservation {
    captured_at_ns: 0,
    reserved_clock: 0,
    online_cpus: 0,
    idle_ns: 0,
    kernel_thread_ns: 0,
    user_thread_ns: 0,
    vcpu_ns: 0,
    reserved: 0,
};

const ZERO_OBJECT: hyper_abi::HyperNativeObjectInspection =
    hyper_abi::HyperNativeObjectInspection {
        koid: 0,
        object_kind: 0,
        handle_state: 0,
        active_handles: 0,
        supported_rights: 0,
        strong_references: 0,
        kernel_service_references: 0,
        vm_device_binding_references: 0,
        scheduler_references: 0,
        operation_references: 0,
        user_authority_references: 0,
        publication_references: 0,
        diagnostic_references: 0,
        retirement_references: 0,
    };

const ZERO_HANDLE: hyper_abi::HyperNativeHandleInspection =
    hyper_abi::HyperNativeHandleInspection {
        process_koid: 0,
        handle: 0,
        object_koid: 0,
        rights: 0,
        object_kind: 0,
        flags: 0,
    };

#[cfg(not(test))]
mod raw_ops {
    use super::*;

    pub(super) fn scan_processes(
        inspector: HandleRef<'_, TaskInspectorObject>,
        cursor: u64,
        records: &mut [hyper_abi::HyperNativeTaskProcess; PROCESS_PAGE_CAPACITY],
    ) -> hyper_sys::CallResult {
        // SAFETY: the typed borrow remains live and the complete array is writable.
        unsafe {
            hyper_sys::task_inspector_scan_processes(
                inspector.raw().get(),
                cursor,
                records.as_mut_ptr(),
                records.len(),
            )
        }
    }

    pub(super) fn scan_threads(
        inspector: HandleRef<'_, TaskInspectorObject>,
        cursor: u64,
        records: &mut [hyper_abi::HyperNativeTaskThread; THREAD_PAGE_CAPACITY],
    ) -> hyper_sys::CallResult {
        // SAFETY: the typed borrow remains live and the complete array is writable.
        unsafe {
            hyper_sys::task_inspector_scan_threads(
                inspector.raw().get(),
                cursor,
                records.as_mut_ptr(),
                records.len(),
            )
        }
    }

    pub(super) fn scan_objects(
        inspector: HandleRef<'_, ObjectInspectorObject>,
        cursor: u64,
        records: &mut [hyper_abi::HyperNativeObjectInspection; OBJECT_PAGE_CAPACITY],
    ) -> hyper_sys::CallResult {
        // SAFETY: the typed borrow remains live and the complete array is writable.
        unsafe {
            hyper_sys::object_inspector_scan_objects(
                inspector.raw().get(),
                cursor,
                records.as_mut_ptr(),
                records.len(),
            )
        }
    }

    pub(super) fn scan_handles(
        inspector: HandleRef<'_, ObjectInspectorObject>,
        process_koid: u64,
        cursor: u64,
        records: &mut [hyper_abi::HyperNativeHandleInspection; HANDLE_PAGE_CAPACITY],
    ) -> hyper_sys::CallResult {
        // SAFETY: the typed borrow remains live and the complete array is writable.
        unsafe {
            hyper_sys::object_inspector_scan_handles(
                inspector.raw().get(),
                process_koid,
                cursor,
                records.as_mut_ptr(),
                records.len(),
            )
        }
    }

    macro_rules! derive {
        ($name:ident, $raw:ident, $source:ty, $target:ty) => {
            pub(super) fn $name(
                inspector: HandleRef<'_, $source>,
                target: HandleRef<'_, $target>,
            ) -> hyper_sys::CallResult {
                // SAFETY: typed borrows retain both input authorities; this
                // layer adopts the successful output exactly once.
                unsafe { hyper_sys::$raw(inspector.raw().get(), target.raw().get()) }
            }
        };
    }

    derive!(
        derive_task_process,
        task_inspector_derive_process,
        TaskInspectorObject,
        ProcessObject
    );
    derive!(
        derive_task_group,
        task_inspector_derive_task_group,
        TaskInspectorObject,
        TaskGroupObject
    );
    derive!(
        derive_task_domain,
        task_inspector_derive_resource_domain,
        TaskInspectorObject,
        ResourceDomainObject
    );
    derive!(
        derive_object_process,
        object_inspector_derive_process,
        ObjectInspectorObject,
        ProcessObject
    );
    derive!(
        derive_object_group,
        object_inspector_derive_task_group,
        ObjectInspectorObject,
        TaskGroupObject
    );
    derive!(
        derive_object_domain,
        object_inspector_derive_resource_domain,
        ObjectInspectorObject,
        ResourceDomainObject
    );
}

#[cfg(test)]
mod tests {
    use super::{
        ObjectHandleState, ProcessPhase, TASK_NAME_CAPACITY, TaskName, TerminalReason,
        ThreadRegistryPhase, ThreadRole, decode_object_observation, validate_memory_observation,
    };

    #[test]
    fn task_names_validate_length_and_utf8() -> crate::Result<()> {
        let mut bytes = [0_u8; TASK_NAME_CAPACITY];
        bytes[..4].copy_from_slice(b"init");
        assert_eq!(TaskName::decode(bytes, 4)?.as_str(), "init");
        assert_eq!(
            TaskName::decode(bytes, 65),
            Err(crate::Error::InvalidResponse)
        );

        let mut invalid = [0_u8; TASK_NAME_CAPACITY];
        invalid[0] = 0xff;
        assert_eq!(
            TaskName::decode(invalid, 1),
            Err(crate::Error::InvalidResponse)
        );
        let mut dirty_tail = [0_u8; TASK_NAME_CAPACITY];
        dirty_tail[0] = b'x';
        assert_eq!(
            TaskName::decode(dirty_tail, 0),
            Err(crate::Error::InvalidResponse)
        );
        Ok(())
    }

    #[test]
    fn task_enums_decode_only_declared_abi_values() -> crate::Result<()> {
        assert_eq!(ProcessPhase::decode(2)?.name(), "running");
        assert_eq!(
            TerminalReason::decode(5)?.map(TerminalReason::name),
            Some("fault")
        );
        assert_eq!(ThreadRole::decode(4)?.name(), "user");
        assert_eq!(ThreadRegistryPhase::decode(1)?.name(), "resident");
        assert_eq!(
            ProcessPhase::decode(u32::MAX),
            Err(crate::Error::InvalidResponse)
        );
        Ok(())
    }

    #[test]
    fn memory_observations_keep_partial_censuses_independent() {
        let page = 4096;
        let record = hyper_abi::HyperNativeMemoryObservation {
            page_size: page,
            total_bytes: 100 * page,
            managed_bytes: 80 * page,
            free_bytes: 30 * page,
            slab_bytes: 10 * page,
            vmo_bytes: 20 * page,
            guest_loaned_bytes: 15 * page,
            file_cache_bytes: 20 * page,
            file_cache_reclaimable_bytes: 18 * page,
            file_cache_sample_complete: 1,
            ..super::ZERO_MEMORY
        };
        // An unavailable slab census must not discard valid file-cache data.
        assert_eq!(validate_memory_observation(&record), Ok(()));
        for bad in [
            hyper_abi::HyperNativeMemoryObservation {
                guest_loaned_bytes: 21 * page,
                ..record
            },
            hyper_abi::HyperNativeMemoryObservation {
                slab_reclaimable_bytes: page,
                ..record
            },
            hyper_abi::HyperNativeMemoryObservation {
                file_cache_sample_complete: 0,
                ..record
            },
            hyper_abi::HyperNativeMemoryObservation {
                file_cache_sample_complete: 2,
                ..record
            },
            hyper_abi::HyperNativeMemoryObservation {
                file_cache_reclaimable_bytes: 21 * page,
                ..record
            },
            hyper_abi::HyperNativeMemoryObservation {
                free_bytes: 31 * page,
                ..record
            },
            hyper_abi::HyperNativeMemoryObservation {
                managed_bytes: 101 * page,
                ..record
            },
            hyper_abi::HyperNativeMemoryObservation {
                page_size: 0,
                ..record
            },
        ] {
            assert_eq!(
                validate_memory_observation(&bad),
                Err(crate::Error::InvalidResponse)
            );
        }
    }

    #[test]
    fn object_observation_preserves_every_reference_class() -> crate::Result<()> {
        let record = hyper_abi::HyperNativeObjectInspection {
            koid: 7,
            object_kind: hyper_abi::HYPER_NATIVE_OBJECT_VIRTUAL_MACHINE,
            handle_state: hyper_abi::HYPER_NATIVE_OBJECT_HANDLE_STATE_ACTIVE as u32,
            active_handles: 2,
            supported_rights: hyper_abi::HYPER_NATIVE_RIGHT_INSPECT,
            strong_references: 11,
            kernel_service_references: 1,
            vm_device_binding_references: 2,
            scheduler_references: 3,
            operation_references: 4,
            user_authority_references: 5,
            publication_references: 6,
            diagnostic_references: 7,
            retirement_references: 8,
        };

        let observation = decode_object_observation(&record)?;
        assert_eq!(observation.handles, ObjectHandleState::Active(2));
        assert_eq!(observation.references.strong, 11);
        assert_eq!(observation.references.kernel_service, 1);
        assert_eq!(observation.references.vm_device_binding, 2);
        assert_eq!(observation.references.scheduler, 3);
        assert_eq!(observation.references.operation, 4);
        assert_eq!(observation.references.user_authority, 5);
        assert_eq!(observation.references.publication, 6);
        assert_eq!(observation.references.diagnostic, 7);
        assert_eq!(observation.references.retirement, 8);
        Ok(())
    }
}

#[cfg(test)]
mod raw_ops {
    use super::*;

    macro_rules! reject {
        ($($name:ident($inspector:ty, $target:ty)),+ $(,)?) => {
            $(
                pub(super) fn $name(
                    _inspector: HandleRef<'_, $inspector>,
                    _target: HandleRef<'_, $target>,
                ) -> hyper_sys::CallResult {
                    rejected()
                }
            )+
        };
    }

    pub(super) fn scan_processes(
        _inspector: HandleRef<'_, TaskInspectorObject>,
        _cursor: u64,
        _records: &mut [hyper_abi::HyperNativeTaskProcess; PROCESS_PAGE_CAPACITY],
    ) -> hyper_sys::CallResult {
        rejected()
    }

    pub(super) fn scan_threads(
        _inspector: HandleRef<'_, TaskInspectorObject>,
        _cursor: u64,
        _records: &mut [hyper_abi::HyperNativeTaskThread; THREAD_PAGE_CAPACITY],
    ) -> hyper_sys::CallResult {
        rejected()
    }

    pub(super) fn scan_objects(
        _inspector: HandleRef<'_, ObjectInspectorObject>,
        _cursor: u64,
        _records: &mut [hyper_abi::HyperNativeObjectInspection; OBJECT_PAGE_CAPACITY],
    ) -> hyper_sys::CallResult {
        rejected()
    }

    pub(super) fn scan_handles(
        _inspector: HandleRef<'_, ObjectInspectorObject>,
        _process_koid: u64,
        _cursor: u64,
        _records: &mut [hyper_abi::HyperNativeHandleInspection; HANDLE_PAGE_CAPACITY],
    ) -> hyper_sys::CallResult {
        rejected()
    }

    reject!(
        derive_task_process(TaskInspectorObject, ProcessObject),
        derive_task_group(TaskInspectorObject, TaskGroupObject),
        derive_task_domain(TaskInspectorObject, ResourceDomainObject),
        derive_object_process(ObjectInspectorObject, ProcessObject),
        derive_object_group(ObjectInspectorObject, TaskGroupObject),
        derive_object_domain(ObjectInspectorObject, ResourceDomainObject),
    );

    fn rejected() -> hyper_sys::CallResult {
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_NOT_SUPPORTED,
            value0: 0,
            value1: 0,
        }
    }
}
