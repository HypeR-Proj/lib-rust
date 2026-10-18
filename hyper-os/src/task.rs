// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Capability-scoped process construction and lifecycle operations.

use core::num::NonZeroU64;

use crate::handle::{
    AnyObject, FileObject, HandleRef, OwnedHandle, ProcessBuilderObject, ProcessObject,
    ResourceDomainObject, Rights, RightsOffer, TaskFactoryObject, TaskGroupObject, TypedObject,
};
use crate::{Error, Result, Status};

pub use crate::retirement::ProcessRetirement;

const _: () = assert!(hyper_abi::HYPER_NATIVE_PROCESS_NAME_MAX_BYTES <= usize::MAX as u64);
const _: () = assert!(hyper_abi::HYPER_NATIVE_PROCESS_AFFINITY_MAX_WORDS <= usize::MAX as u64);

const MAX_NAME_BYTES: usize = hyper_abi::HYPER_NATIVE_PROCESS_NAME_MAX_BYTES as usize;
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_ENVIRONMENT_BYTES: usize = 4096;
const MAX_AFFINITY_WORDS: usize = hyper_abi::HYPER_NATIVE_PROCESS_AFFINITY_MAX_WORDS as usize;

const BUILDER_RIGHTS: Rights = Rights::TRANSFER
    .union(Rights::INSPECT)
    .union(Rights::WRITE)
    .union(Rights::START)
    .union(Rights::REQUEST_STOP);
const PROCESS_SUPERVISOR_RIGHTS: Rights = Rights::TRANSFER
    .union(Rights::WAIT)
    .union(Rights::INSPECT)
    .union(Rights::REQUEST_STOP);
const CHILD_RESOURCE_DOMAIN_RIGHTS: Rights = Rights::DUPLICATE
    .union(Rights::TRANSFER)
    .union(Rights::INSPECT)
    .union(Rights::CREATE_RESOURCE_DOMAIN)
    .union(Rights::SET_LIMITS)
    .union(Rights::REVOKE)
    .union(Rights::RESOURCE_DOMAIN_SPONSOR);
const CHILD_TASK_GROUP_RIGHTS: Rights = Rights::DUPLICATE
    .union(Rights::WAIT)
    .union(Rights::TRANSFER)
    .union(Rights::INSPECT)
    .union(Rights::REQUEST_STOP)
    .union(Rights::TASK_GROUP_ATTACH_PROCESS);

/// Lifecycle phase reported for a Process object.
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

/// Immutable reason latched when a Process begins termination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessTermination {
    Requested,
    ThreadExited { status: i64 },
    ProcessExited { status: i64 },
    LastThreadExited { status: i64 },
    Fault { class: u32, code: u64 },
    TaskGroupStop { generation: u64 },
}

/// Stable lifecycle information obtained through Process inspect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessInfo {
    pub phase: ProcessPhase,
    pub terminal: Option<ProcessTermination>,
}

/// Yields the calling thread's remaining scheduling opportunity.
///
/// This is a scheduling hint rather than a blocking primitive. Callers that
/// poll an object should keep the poll bounded or use an object wait once the
/// relevant signal can be waited on directly.
pub fn yield_now() -> Result<()> {
    Status::from_raw(raw_ops::yield_thread()).into_result()
}

/// Creates an independently accounted child of `parent`.
///
/// The limits become authoritative in the same transaction that publishes the
/// child, so no temporarily unlimited domain can admit work between creation
/// and policy installation. Every ancestor limit remains independently
/// authoritative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    pub kernel_memory_bytes: u64,
    pub processes: u64,
    pub threads: u64,
    pub handles: u64,
    pub kernel_objects: u64,
    pub committed_pages: u64,
    pub pinned_pages: u64,
    pub guest_pages: u64,
    pub ipc_messages: u64,
    pub ipc_bytes: u64,
    pub ipc_handles: u64,
    pub subscriptions: u64,
    pub timers: u64,
    pub virtual_machines: u64,
    pub virtual_cpus: u64,
    pub device_leases: u64,
    pub dma_mappings: u64,
    pub user_address_spaces: u64,
    pub user_mappings: u64,
}

impl ResourceLimits {
    pub const UNLIMITED: Self = Self {
        kernel_memory_bytes: u64::MAX,
        processes: u64::MAX,
        threads: u64::MAX,
        handles: u64::MAX,
        kernel_objects: u64::MAX,
        committed_pages: u64::MAX,
        pinned_pages: u64::MAX,
        guest_pages: u64::MAX,
        ipc_messages: u64::MAX,
        ipc_bytes: u64::MAX,
        ipc_handles: u64::MAX,
        subscriptions: u64::MAX,
        timers: u64::MAX,
        virtual_machines: u64::MAX,
        virtual_cpus: u64::MAX,
        device_leases: u64::MAX,
        dma_mappings: u64::MAX,
        user_address_spaces: u64::MAX,
        user_mappings: u64::MAX,
    };

    fn abi(self) -> hyper_abi::HyperNativeResourceLimits {
        hyper_abi::HyperNativeResourceLimits {
            kernel_memory_bytes: self.kernel_memory_bytes,
            processes: self.processes,
            threads: self.threads,
            handles: self.handles,
            kernel_objects: self.kernel_objects,
            committed_pages: self.committed_pages,
            pinned_pages: self.pinned_pages,
            guest_pages: self.guest_pages,
            ipc_messages: self.ipc_messages,
            ipc_bytes: self.ipc_bytes,
            ipc_handles: self.ipc_handles,
            subscriptions: self.subscriptions,
            timers: self.timers,
            virtual_machines: self.virtual_machines,
            virtual_cpus: self.virtual_cpus,
            device_leases: self.device_leases,
            dma_mappings: self.dma_mappings,
            user_address_spaces: self.user_address_spaces,
            user_mappings: self.user_mappings,
            reserved: 0,
        }
    }
}

pub fn create_resource_domain(
    parent: HandleRef<'_, ResourceDomainObject>,
    limits: ResourceLimits,
) -> Result<OwnedHandle<ResourceDomainObject>> {
    let limits = limits.abi();
    let parent_raw = parent.raw();
    // SAFETY: the typed parent borrow remains live for the complete call.
    let result = unsafe { hyper_sys::resource_domain_create(parent_raw.get(), &limits) };
    Status::from_raw(result.status).into_result()?;
    adopt_produced_handle::<ResourceDomainObject>(
        result.value0,
        CHILD_RESOURCE_DOMAIN_RIGHTS,
        &[parent_raw],
    )
}

/// Creates an empty process task group charged to `domain`.
///
/// Every returned or duplicated group handle is a shared lifetime owner,
/// independently of its attenuated rights. Closing the last owner
/// asynchronously requests stop for every member of the group.
pub fn create_task_group(
    factory: HandleRef<'_, TaskFactoryObject>,
    domain: HandleRef<'_, ResourceDomainObject>,
) -> Result<OwnedHandle<TaskGroupObject>> {
    let factory_raw = factory.raw();
    let domain_raw = domain.raw();
    // SAFETY: both typed input borrows remain live for the complete call.
    let result = unsafe { hyper_sys::task_group_create(factory_raw.get(), domain_raw.get()) };
    Status::from_raw(result.status).into_result()?;
    adopt_produced_handle::<TaskGroupObject>(
        result.value0,
        CHILD_TASK_GROUP_RIGHTS,
        &[factory_raw, domain_raw],
    )
}

fn adopt_produced_handle<T: TypedObject>(
    raw: u64,
    rights: Rights,
    live_inputs: &[NonZeroU64],
) -> Result<OwnedHandle<T>> {
    // SAFETY: successful creation publishes one new owner unless malformed
    // output aliases one of the explicitly retained input borrows.
    let owner =
        unsafe { crate::handle::adopt_produced_handle_excluding::<AnyObject>(raw, live_inputs)? };
    validate_produced_handle::<T>(owner, rights)
}

/// One mutable or sealed process construction transaction.
///
/// The kernel owns transaction phase and capability transfers. This wrapper
/// stages argv/environment locally and uploads them before sealing or transfer.
/// Received builders may be sealed and started, but cannot append to the sender's
/// local argument list. `start` and `abort` consume the owner when the kernel commits.
pub struct ProcessBuilder {
    handle: OwnedHandle<ProcessBuilderObject>,
    data: core::cell::RefCell<Option<crate::launch_data::LaunchData>>,
}

impl ProcessBuilder {
    /// Creates a builder with explicit executable and loader authorities.
    /// The target needs `READ|EXECUTE|PROTECT|DUPLICATE|TRANSFER`; the loader
    /// needs `READ|EXECUTE`. The child receives a reduced ordinary File and
    /// acquires content protection itself. Builder creation does not freeze
    /// target bytes; only the restricted loader uses a temporary kernel copy.
    pub fn create(
        factory: HandleRef<'_, TaskFactoryObject>,
        group: HandleRef<'_, TaskGroupObject>,
        domain: HandleRef<'_, ResourceDomainObject>,
        executable: HandleRef<'_, FileObject>,
        loader: HandleRef<'_, FileObject>,
    ) -> Result<Self> {
        let live_inputs = [
            factory.raw(),
            group.raw(),
            domain.raw(),
            executable.raw(),
            loader.raw(),
        ];
        let result = raw_ops::create(factory, group, domain, executable, loader);
        Status::from_raw(result.status).into_result()?;
        // SAFETY: successful create publishes one new builder owner unless a
        // malformed output aliases a retained input borrow.
        let owner = unsafe {
            crate::handle::adopt_produced_handle_excluding::<AnyObject>(
                result.value0,
                &live_inputs,
            )?
        };
        let rights = owner.info()?.rights;
        if !rights.contains(BUILDER_RIGHTS)
            || !BUILDER_RIGHTS
                .union(Rights::LOCK_MEMORY)
                .union(Rights::RETAIN_PROCESS)
                .contains(rights)
        {
            return Err(Error::InvalidResponse);
        }
        let handle = owner
            .downcast::<ProcessBuilderObject>()
            .map_err(|failure| failure.error())?;
        Ok(Self {
            handle,
            data: core::cell::RefCell::new(Some(crate::launch_data::LaunchData::new())),
        })
    }

    /// Wraps an already typed owner received through a trusted SDK path.
    #[must_use]
    pub const fn from_handle(handle: OwnedHandle<ProcessBuilderObject>) -> Self {
        Self {
            handle,
            data: core::cell::RefCell::new(None),
        }
    }

    /// Replaces the process and initial-thread name.
    pub fn set_name(&self, name: &str) -> Result<()> {
        if name.is_empty() || name.len() > MAX_NAME_BYTES || name.as_bytes().contains(&0) {
            return Err(Error::InvalidProcessName);
        }
        Status::from_raw(raw_ops::set_name(self.handle.as_handle_ref(), name)).into_result()
    }

    /// Appends one argv entry. Empty entries are valid.
    pub fn add_argument(&self, argument: &str) -> Result<()> {
        if argument.len() > MAX_ARGUMENT_BYTES || argument.as_bytes().contains(&0) {
            return Err(Error::InvalidProcessArgument);
        }
        self.data
            .borrow_mut()
            .as_mut()
            .ok_or(Error::Status(Status::BAD_STATE))?
            .append(argument, false)
    }

    /// Appends one `name=value` environment entry.
    pub fn add_environment(&self, environment: &str) -> Result<()> {
        if environment.len() > MAX_ENVIRONMENT_BYTES || !valid_environment(environment) {
            return Err(Error::InvalidProcessEnvironment);
        }
        self.data
            .borrow_mut()
            .as_mut()
            .ok_or(Error::Status(Status::BAD_STATE))?
            .append(environment, true)
    }

    /// Arms bounded post-exit observation before this child is started.
    ///
    /// Only a factory carrying `RETAIN_PROCESS` grants this authority. The
    /// returned controller belongs to the external supervisor, never the child.
    /// Closing it permits cleanup; observations cannot extend that obligation.
    pub fn retain_on_exit(&self, max_bytes: u64, timeout_ns: u64) -> Result<ProcessRetirement> {
        crate::retirement::retain(self.handle.as_handle_ref(), max_bytes, timeout_ns)
    }

    /// Allows the child to lock its own current mappings in RAM. The factory
    /// used to create this builder must carry `LOCK_MEMORY`. Disabled by default;
    /// ordinary process creation cannot manufacture this authority.
    pub fn set_memory_lock_allowed(&self, enabled: bool) -> Result<()> {
        Status::from_raw(raw_ops::set_memory_lock(
            self.handle.as_handle_ref(),
            enabled,
        ))
        .into_result()
    }

    /// Replaces the CPU affinity bitmap.
    pub fn set_affinity(&self, words: &[u64]) -> Result<()> {
        if words.is_empty() || words.len() > MAX_AFFINITY_WORDS {
            return Err(Error::InvalidProcessAffinity);
        }
        Status::from_raw(raw_ops::set_affinity(self.handle.as_handle_ref(), words)).into_result()
    }

    /// Moves one capability into the builder on success.
    pub fn add_handle_move<T: TypedObject>(
        &self,
        source: OwnedHandle<T>,
        purpose: u32,
        offer: RightsOffer,
    ) -> core::result::Result<(), AddHandleFailure<T>> {
        if purpose == 0 || T::KIND == ProcessBuilderObject::KIND {
            return Err(AddHandleFailure {
                error: Error::InvalidCapabilityDisposition,
                handle: source,
            });
        }
        if let Err(error) = validate_source(source.as_handle_ref(), offer, Rights::TRANSFER) {
            return Err(AddHandleFailure {
                error,
                handle: source,
            });
        }
        let status = Status::from_raw(raw_ops::add_handle(
            self.handle.as_handle_ref(),
            source.as_handle_ref().raw(),
            purpose,
            T::KIND.as_raw(),
            offer,
            hyper_abi::HYPER_NATIVE_CAPABILITY_DISPOSITION_MOVE as u32,
        ));
        if status != Status::OK {
            return Err(AddHandleFailure {
                error: Error::Status(status),
                handle: source,
            });
        }
        let _ = source.into_raw();
        Ok(())
    }

    /// Duplicates one capability into the builder while retaining its source.
    pub fn add_handle_duplicate<T: TypedObject>(
        &self,
        source: HandleRef<'_, T>,
        purpose: u32,
        offer: RightsOffer,
    ) -> Result<()> {
        if purpose == 0 || T::KIND == ProcessBuilderObject::KIND {
            return Err(Error::InvalidCapabilityDisposition);
        }
        validate_source(source, offer, Rights::TRANSFER.union(Rights::DUPLICATE))?;
        Status::from_raw(raw_ops::add_handle(
            self.handle.as_handle_ref(),
            source.raw(),
            purpose,
            T::KIND.as_raw(),
            offer,
            hyper_abi::HYPER_NATIVE_CAPABILITY_DISPOSITION_DUPLICATE as u32,
        ))
        .into_result()
    }

    /// Irreversibly seals the builder against further mutation.
    pub fn seal(&self) -> Result<()> {
        self.flush_data()?;
        Status::from_raw(raw_ops::seal(self.handle.as_handle_ref())).into_result()?;
        self.data.borrow_mut().take();
        Ok(())
    }

    /// Starts the sealed process and returns only supervisor authority.
    ///
    /// A rejected kernel operation returns the builder in [`StartFailure`].
    /// After commit, waits for runtime readiness. A loader failure stops and
    /// joins the child; it is a committed failure, as is a malformed successful
    /// response. Neither returns the consumed builder for retry.
    pub fn start(self) -> core::result::Result<OwnedHandle<ProcessObject>, StartFailure> {
        let result = raw_ops::start(self.handle.as_handle_ref());
        let status = Status::from_raw(result.status);
        if status != Status::OK {
            return Err(StartFailure::Rejected {
                error: Error::Status(status),
                builder: self,
            });
        }
        let _ = self.handle.into_raw();
        // SAFETY: the successful consume-builder call transfers both distinct
        // result owners; the input owner was disarmed before adoption.
        let (process, channel) = unsafe {
            crate::handle::adopt_produced_handle_pair::<AnyObject, AnyObject>([
                result.value0,
                result.value1,
            ])
        }
        .map_err(StartFailure::Committed)?;
        let process = validate_produced_handle::<ProcessObject>(process, PROCESS_SUPERVISOR_RIGHTS)
            .map_err(StartFailure::Committed)?;
        let channel = validate_produced_handle::<crate::handle::ByteChannelObject>(
            channel,
            Rights::READ.union(Rights::WAIT),
        )
        .map_err(StartFailure::Committed)?;
        Status::from_raw(raw_ops::wait_launch(
            process.as_handle_ref().raw().get(),
            channel.as_handle_ref().raw().get(),
        ))
        .into_result()
        .map_err(StartFailure::Committed)?;
        Ok(process)
    }

    /// Aborts this builder and discards every capability it owns.
    pub fn abort(self) -> core::result::Result<(), BuilderFailure> {
        let status = Status::from_raw(raw_ops::abort(self.handle.as_handle_ref()));
        if status == Status::OK {
            let _ = self.handle.into_raw();
            Ok(())
        } else {
            Err(BuilderFailure {
                error: Error::Status(status),
                builder: self,
            })
        }
    }

    /// Uploads local arguments before transferring the typed builder owner.
    /// A receiver may seal/start it; appending to the sender's argument list is
    /// intentionally unsupported because that list is SDK-local state.
    pub fn into_handle(
        self,
    ) -> core::result::Result<OwnedHandle<ProcessBuilderObject>, BuilderFailure> {
        if let Err(error) = self.flush_data() {
            return Err(BuilderFailure {
                error,
                builder: self,
            });
        }
        Ok(self.handle)
    }

    fn flush_data(&self) -> Result<()> {
        let data = self.data.borrow();
        if let Some(data) = data.as_ref() {
            let bytes = data.encode()?;
            Status::from_raw(raw_ops::set_data(self.handle.as_handle_ref(), &bytes))
                .into_result()?;
        }
        Ok(())
    }
}

/// Borrowed Process supervisor authority.
pub struct ProcessSupervisor<'owner> {
    handle: HandleRef<'owner, ProcessObject>,
}

impl ProcessSupervisor<'_> {
    /// Creates a transferable wait-only view of this same Process identity.
    /// The observer cannot inspect, stop, or derive another observer.
    pub fn observe(&self) -> Result<OwnedHandle<ProcessObject>> {
        let raw = self.handle.raw();
        // SAFETY: the typed Process borrow remains live throughout derivation.
        let result = unsafe { hyper_sys::process_derive_observer(raw.get()) };
        Status::from_raw(result.status).into_result()?;
        adopt_produced_handle::<ProcessObject>(
            result.value0,
            Rights::WAIT.union(Rights::TRANSFER),
            &[raw],
        )
    }

    /// Requests asynchronous termination of the supervised Process.
    pub fn request_stop(&self) -> Result<()> {
        Status::from_raw(raw_ops::request_process_stop(self.handle)).into_result()
    }

    /// Waits until the Process terminates. Exit status is not part of this ABI.
    pub fn wait_terminated(&self, deadline: u64) -> Result<()> {
        let expected = hyper_abi::HYPER_NATIVE_SIGNAL_PROCESS_TERMINATED;
        let result = raw_ops::wait_process(self.handle, expected, deadline);
        Status::from_raw(result.status).into_result()?;
        if result.value0 & expected == expected {
            Ok(())
        } else {
            Err(Error::InvalidResponse)
        }
    }

    /// Retrieves the Process lifecycle and reason-specific terminal details.
    pub fn info(&self) -> Result<ProcessInfo> {
        decode_process_info(raw_ops::process_info(self.handle)?)
    }
}

fn decode_process_info(record: hyper_abi::HyperNativeProcessInfo) -> Result<ProcessInfo> {
    if record.reserved != 0 {
        return Err(Error::InvalidResponse);
    }
    let phase = match u64::from(record.phase) {
        hyper_abi::HYPER_NATIVE_PROCESS_PHASE_PREPARED => ProcessPhase::Prepared,
        hyper_abi::HYPER_NATIVE_PROCESS_PHASE_CREATED => ProcessPhase::Created,
        hyper_abi::HYPER_NATIVE_PROCESS_PHASE_RUNNING => ProcessPhase::Running,
        hyper_abi::HYPER_NATIVE_PROCESS_PHASE_STOPPING => ProcessPhase::Stopping,
        hyper_abi::HYPER_NATIVE_PROCESS_PHASE_STOPPED => ProcessPhase::Stopped,
        hyper_abi::HYPER_NATIVE_PROCESS_PHASE_RETIRING => ProcessPhase::Retiring,
        hyper_abi::HYPER_NATIVE_PROCESS_PHASE_RETIRED => ProcessPhase::Retired,
        _ => return Err(Error::InvalidResponse),
    };
    let terminal = match u64::from(record.terminal_reason) {
        hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_NONE
            if record.detail0 == 0 && record.detail1 == 0 =>
        {
            None
        }
        hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_REQUESTED
            if record.detail0 == 0 && record.detail1 == 0 =>
        {
            Some(ProcessTermination::Requested)
        }
        hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_THREAD_EXITED if record.detail1 == 0 => {
            Some(ProcessTermination::ThreadExited {
                status: record.detail0 as i64,
            })
        }
        hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_PROCESS_EXITED if record.detail1 == 0 => {
            Some(ProcessTermination::ProcessExited {
                status: record.detail0 as i64,
            })
        }
        hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_LAST_THREAD_EXITED if record.detail1 == 0 => {
            Some(ProcessTermination::LastThreadExited {
                status: record.detail0 as i64,
            })
        }
        hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_FAULT if record.detail0 <= u32::MAX.into() => {
            Some(ProcessTermination::Fault {
                class: record.detail0 as u32,
                code: record.detail1,
            })
        }
        hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_TASK_GROUP_STOP if record.detail1 == 0 => {
            Some(ProcessTermination::TaskGroupStop {
                generation: record.detail0,
            })
        }
        _ => return Err(Error::InvalidResponse),
    };
    Ok(ProcessInfo { phase, terminal })
}

impl OwnedHandle<ProcessObject> {
    /// Borrows this Process as supervisor authority.
    #[must_use]
    pub fn as_process_supervisor(&self) -> ProcessSupervisor<'_> {
        ProcessSupervisor {
            handle: self.as_handle_ref(),
        }
    }
}

/// Borrowed control over a flat process task group.
pub struct TaskGroupSupervisor<'owner> {
    handle: HandleRef<'owner, TaskGroupObject>,
}

impl TaskGroupSupervisor<'_> {
    /// Closes membership admission and requests asynchronous member stop.
    pub fn request_stop(&self) -> Result<()> {
        // SAFETY: the typed borrow keeps the group capability live.
        Status::from_raw(unsafe { hyper_sys::task_group_request_stop(self.handle.raw().get()) })
            .into_result()
    }

    /// Waits until all members and pending constructors have retired. This does
    /// not cover children that were placed in a different task group.
    pub fn wait_terminated(&self, deadline: u64) -> Result<()> {
        let expected = hyper_abi::HYPER_NATIVE_SIGNAL_TASK_GROUP_TERMINATED;
        // SAFETY: the typed group borrow remains live for the complete wait.
        let result =
            unsafe { hyper_sys::object_wait_one(self.handle.raw().get(), expected, deadline) };
        Status::from_raw(result.status).into_result()?;
        if result.value0 & expected == expected {
            Ok(())
        } else {
            Err(Error::InvalidResponse)
        }
    }
}

impl OwnedHandle<TaskGroupObject> {
    /// Borrows this group for scoped lifecycle control.
    pub fn as_task_group(&self) -> TaskGroupSupervisor<'_> {
        self.as_handle_ref().as_task_group()
    }
}

impl<'owner> HandleRef<'owner, TaskGroupObject> {
    /// Borrows this group for scoped lifecycle control.
    pub fn as_task_group(self) -> TaskGroupSupervisor<'owner> {
        TaskGroupSupervisor { handle: self }
    }
}

/// Rejected builder capability insertion with its unchanged MOVE source.
pub struct AddHandleFailure<T: TypedObject> {
    error: Error,
    handle: OwnedHandle<T>,
}

impl<T: TypedObject> AddHandleFailure<T> {
    #[must_use]
    pub const fn error(&self) -> Error {
        self.error
    }

    #[must_use]
    pub fn into_parts(self) -> (Error, OwnedHandle<T>) {
        (self.error, self.handle)
    }
}

/// Rejected consuming builder operation with the unchanged builder owner.
pub struct BuilderFailure {
    error: Error,
    builder: ProcessBuilder,
}

impl BuilderFailure {
    #[must_use]
    pub const fn error(&self) -> Error {
        self.error
    }

    #[must_use]
    pub fn into_parts(self) -> (Error, ProcessBuilder) {
        (self.error, self.builder)
    }
}

/// Start failure distinguishes rejection from malformed post-commit output.
pub enum StartFailure {
    Rejected {
        error: Error,
        builder: ProcessBuilder,
    },
    Committed(Error),
}

impl StartFailure {
    #[must_use]
    pub const fn error(&self) -> Error {
        match self {
            Self::Rejected { error, .. } | Self::Committed(error) => *error,
        }
    }

    /// Recovers the builder only when the kernel rejected the transaction.
    #[must_use]
    pub fn into_builder(self) -> Option<ProcessBuilder> {
        match self {
            Self::Rejected { builder, .. } => Some(builder),
            Self::Committed(_) => None,
        }
    }
}

fn validate_source<T: TypedObject>(
    source: HandleRef<'_, T>,
    offer: RightsOffer,
    required: Rights,
) -> Result<()> {
    let info = source.info()?;
    if info.kind != T::KIND {
        return Err(Error::UnexpectedObjectKind {
            expected: T::KIND.as_raw(),
            actual: info.kind.as_raw(),
        });
    }
    if !info.rights.contains(required) {
        return Err(Error::Status(Status::ACCESS_DENIED));
    }
    if let RightsOffer::Exact(rights) = offer
        && !info.rights.contains(rights)
    {
        return Err(Error::Status(Status::ACCESS_DENIED));
    }
    Ok(())
}

fn validate_produced_handle<T: TypedObject>(
    owner: OwnedHandle<AnyObject>,
    expected_rights: Rights,
) -> Result<OwnedHandle<T>> {
    let info = owner.info()?;
    if info.rights != expected_rights {
        return Err(Error::InvalidResponse);
    }
    owner.downcast::<T>().map_err(|failure| failure.error())
}

fn valid_environment(environment: &str) -> bool {
    if environment.as_bytes().contains(&0) {
        return false;
    }
    let Some(separator) = environment.find('=') else {
        return false;
    };
    separator != 0 && !environment[..separator].contains('=')
}

#[cfg(not(test))]
mod raw_ops {
    use core::num::NonZeroU64;

    use super::{
        FileObject, HandleRef, MAX_AFFINITY_WORDS, ProcessBuilderObject, ResourceDomainObject,
        RightsOffer, TaskFactoryObject, TaskGroupObject,
    };

    pub(super) fn create(
        factory: HandleRef<'_, TaskFactoryObject>,
        group: HandleRef<'_, TaskGroupObject>,
        domain: HandleRef<'_, ResourceDomainObject>,
        executable: HandleRef<'_, FileObject>,
        loader: HandleRef<'_, FileObject>,
    ) -> hyper_sys::CallResult {
        // SAFETY: all typed borrows remain live for this non-retaining call.
        unsafe {
            hyper_sys::process_builder_create(
                factory.raw().get(),
                group.raw().get(),
                domain.raw().get(),
                executable.raw().get(),
                loader.raw().get(),
            )
        }
    }

    macro_rules! string_operation {
        ($name:ident, $call:path) => {
            pub(super) fn $name(
                builder: HandleRef<'_, ProcessBuilderObject>,
                value: &str,
            ) -> hyper_abi::HyperNativeStatus {
                // SAFETY: the typed borrow and UTF-8 buffer remain live.
                unsafe { $call(builder.raw().get(), value.as_ptr(), value.len()) }
            }
        };
    }

    string_operation!(set_name, hyper_sys::process_builder_set_name);
    pub(super) fn set_data(
        builder: HandleRef<'_, ProcessBuilderObject>,
        bytes: &[u8],
    ) -> hyper_abi::HyperNativeStatus {
        // SAFETY: the live typed handle and borrowed bytes outlive this call.
        unsafe {
            hyper_sys::process_builder_set_data(builder.raw().get(), bytes.as_ptr(), bytes.len())
        }
    }
    pub(super) fn wait_launch(process: u64, channel: u64) -> hyper_abi::HyperNativeStatus {
        unsafe extern "C" {
            fn hyper_launch_wait(process: u64, channel: u64) -> i64;
        }
        // SAFETY: the caller retains validated process/channel owners until return.
        unsafe { hyper_launch_wait(process, channel) }
    }

    pub(super) fn set_memory_lock(
        builder: HandleRef<'_, ProcessBuilderObject>,
        enabled: bool,
    ) -> hyper_abi::HyperNativeStatus {
        // SAFETY: The typed builder remains borrowed through this call.
        unsafe { hyper_sys::process_builder_set_memory_lock(builder.raw().get(), enabled) }
    }

    pub(super) fn set_affinity(
        builder: HandleRef<'_, ProcessBuilderObject>,
        words: &[u64],
    ) -> hyper_abi::HyperNativeStatus {
        let mut little_endian = [0_u64; MAX_AFFINITY_WORDS];
        for (encoded, word) in little_endian.iter_mut().zip(words) {
            *encoded = word.to_le();
        }
        // SAFETY: the typed borrow and aligned encoded prefix remain live.
        unsafe {
            hyper_sys::process_builder_set_affinity(
                builder.raw().get(),
                little_endian.as_ptr(),
                words.len(),
            )
        }
    }

    pub(super) fn add_handle(
        builder: HandleRef<'_, ProcessBuilderObject>,
        source: NonZeroU64,
        purpose: u32,
        expected_kind: u32,
        offer: RightsOffer,
        operation: u32,
    ) -> hyper_abi::HyperNativeStatus {
        let rights = match offer {
            RightsOffer::SameRights => hyper_abi::HYPER_NATIVE_CAPABILITY_DISPOSITION_SAME_RIGHTS,
            RightsOffer::Exact(rights) => rights.bits(),
        };
        // SAFETY: the caller retains both owners until the result and applies
        // the operation-dependent ownership transition.
        unsafe {
            hyper_sys::process_builder_add_handle(
                builder.raw().get(),
                source.get(),
                purpose,
                expected_kind,
                rights,
                operation,
            )
        }
    }

    pub(super) fn seal(
        builder: HandleRef<'_, ProcessBuilderObject>,
    ) -> hyper_abi::HyperNativeStatus {
        // SAFETY: the typed builder remains live for the call.
        unsafe { hyper_sys::process_builder_seal(builder.raw().get()) }
    }

    pub(super) fn start(builder: HandleRef<'_, ProcessBuilderObject>) -> hyper_sys::CallResult {
        // SAFETY: the caller owns the consume-on-success transition.
        unsafe { hyper_sys::process_builder_start(builder.raw().get()) }
    }

    pub(super) fn abort(
        builder: HandleRef<'_, ProcessBuilderObject>,
    ) -> hyper_abi::HyperNativeStatus {
        // SAFETY: the caller owns the consume-on-success transition.
        unsafe { hyper_sys::process_builder_abort(builder.raw().get()) }
    }

    pub(super) fn wait_process(
        process: HandleRef<'_, super::ProcessObject>,
        signals: u64,
        deadline: u64,
    ) -> hyper_sys::CallResult {
        // SAFETY: the typed borrow keeps the waitable Process live.
        unsafe { hyper_sys::object_wait_one(process.raw().get(), signals, deadline) }
    }

    pub(super) fn request_process_stop(
        process: HandleRef<'_, super::ProcessObject>,
    ) -> hyper_abi::HyperNativeStatus {
        // SAFETY: the typed borrow keeps the Process authority live.
        unsafe { hyper_sys::process_request_stop(process.raw().get()) }
    }

    pub(super) fn process_info(
        process: HandleRef<'_, super::ProcessObject>,
    ) -> crate::Result<hyper_abi::HyperNativeProcessInfo> {
        let mut record = hyper_abi::HyperNativeProcessInfo {
            phase: 0,
            terminal_reason: 0,
            detail0: 0,
            detail1: 0,
            reserved: 0,
        };
        // SAFETY: the typed Process borrow remains live and `record` is
        // writable for the complete fixed-width ABI output.
        let result = unsafe { hyper_sys::process_get_info(process.raw().get(), &mut record) };
        let _supported_size =
            crate::validate_info_result(result, hyper_abi::HYPER_NATIVE_PROCESS_INFO_MIN_SIZE)?;
        Ok(record)
    }

    pub(super) fn yield_thread() -> hyper_abi::HyperNativeStatus {
        // SAFETY: this safe SDK function is callable only from a Native thread.
        unsafe { hyper_sys::thread_yield() }
    }
}

#[cfg(test)]
mod raw_ops {
    use core::num::NonZeroU64;

    use super::{
        FileObject, HandleRef, ProcessBuilderObject, ResourceDomainObject, RightsOffer,
        TaskFactoryObject, TaskGroupObject,
    };

    pub(super) fn create(
        _factory: HandleRef<'_, TaskFactoryObject>,
        _group: HandleRef<'_, TaskGroupObject>,
        _domain: HandleRef<'_, ResourceDomainObject>,
        _executable: HandleRef<'_, FileObject>,
        _loader: HandleRef<'_, FileObject>,
    ) -> hyper_sys::CallResult {
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_OK,
            value0: hyper_abi::HYPER_NATIVE_OBJECT_PROCESS_BUILDER.into(),
            value1: 0,
        }
    }

    pub(super) fn set_name(
        _builder: HandleRef<'_, ProcessBuilderObject>,
        value: &str,
    ) -> hyper_abi::HyperNativeStatus {
        if value == "reject" {
            hyper_abi::HYPER_NATIVE_STATUS_BAD_STATE
        } else {
            hyper_abi::HYPER_NATIVE_STATUS_OK
        }
    }

    pub(super) fn set_data(
        _builder: HandleRef<'_, ProcessBuilderObject>,
        _bytes: &[u8],
    ) -> hyper_abi::HyperNativeStatus {
        0
    }
    pub(super) fn wait_launch(_process: u64, _channel: u64) -> hyper_abi::HyperNativeStatus {
        0
    }

    pub(super) fn set_memory_lock(
        _builder: HandleRef<'_, ProcessBuilderObject>,
        _enabled: bool,
    ) -> hyper_abi::HyperNativeStatus {
        0
    }

    pub(super) fn set_affinity(
        _builder: HandleRef<'_, ProcessBuilderObject>,
        _words: &[u64],
    ) -> hyper_abi::HyperNativeStatus {
        hyper_abi::HYPER_NATIVE_STATUS_OK
    }

    pub(super) fn add_handle(
        _builder: HandleRef<'_, ProcessBuilderObject>,
        _source: NonZeroU64,
        purpose: u32,
        _expected_kind: u32,
        _offer: RightsOffer,
        _operation: u32,
    ) -> hyper_abi::HyperNativeStatus {
        if purpose == 99 {
            hyper_abi::HYPER_NATIVE_STATUS_BAD_STATE
        } else {
            hyper_abi::HYPER_NATIVE_STATUS_OK
        }
    }

    pub(super) fn seal(
        _builder: HandleRef<'_, ProcessBuilderObject>,
    ) -> hyper_abi::HyperNativeStatus {
        hyper_abi::HYPER_NATIVE_STATUS_OK
    }

    pub(super) fn start(_builder: HandleRef<'_, ProcessBuilderObject>) -> hyper_sys::CallResult {
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_OK,
            value0: hyper_abi::HYPER_NATIVE_OBJECT_PROCESS.into(),
            value1: u64::from(hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL) + 0x10000,
        }
    }

    pub(super) fn abort(
        _builder: HandleRef<'_, ProcessBuilderObject>,
    ) -> hyper_abi::HyperNativeStatus {
        hyper_abi::HYPER_NATIVE_STATUS_OK
    }

    pub(super) fn wait_process(
        _process: HandleRef<'_, super::ProcessObject>,
        signals: u64,
        _deadline: u64,
    ) -> hyper_sys::CallResult {
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_OK,
            value0: signals,
            value1: 0,
        }
    }

    pub(super) fn request_process_stop(
        _process: HandleRef<'_, super::ProcessObject>,
    ) -> hyper_abi::HyperNativeStatus {
        hyper_abi::HYPER_NATIVE_STATUS_OK
    }

    pub(super) fn process_info(
        _process: HandleRef<'_, super::ProcessObject>,
    ) -> crate::Result<hyper_abi::HyperNativeProcessInfo> {
        Ok(hyper_abi::HyperNativeProcessInfo {
            phase: hyper_abi::HYPER_NATIVE_PROCESS_PHASE_STOPPED as u32,
            terminal_reason: hyper_abi::HYPER_NATIVE_PROCESS_TERMINAL_LAST_THREAD_EXITED as u32,
            detail0: (-7_i64) as u64,
            detail1: 0,
            reserved: 0,
        })
    }

    pub(super) fn yield_thread() -> hyper_abi::HyperNativeStatus {
        hyper_abi::HYPER_NATIVE_STATUS_OK
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use super::{ProcessBuilder, ProcessPhase, ProcessTermination, yield_now};
    use crate::handle::{
        EventObject, FileObject, OwnedHandle, ResourceDomainObject, Rights, RightsOffer,
        TaskFactoryObject, TaskGroupObject,
    };
    use crate::{Error, Status};

    fn owner<T: crate::handle::ObjectType>(kind: u32) -> crate::Result<OwnedHandle<T>> {
        let raw = NonZeroU64::new(kind.into()).ok_or(Error::InvalidResponse)?;
        // SAFETY: every test invokes this helper once per distinct object kind.
        Ok(unsafe { OwnedHandle::from_raw_owned(raw) })
    }

    fn builder() -> crate::Result<ProcessBuilder> {
        let factory = owner::<TaskFactoryObject>(hyper_abi::HYPER_NATIVE_OBJECT_TASK_FACTORY)?;
        let group = owner::<TaskGroupObject>(hyper_abi::HYPER_NATIVE_OBJECT_TASK_GROUP)?;
        let domain = owner::<ResourceDomainObject>(hyper_abi::HYPER_NATIVE_OBJECT_RESOURCE_DOMAIN)?;
        let executable = owner::<FileObject>(hyper_abi::HYPER_NATIVE_OBJECT_FILE)?;
        ProcessBuilder::create(
            factory.as_handle_ref(),
            group.as_handle_ref(),
            domain.as_handle_ref(),
            executable.as_handle_ref(),
            executable.as_handle_ref(),
        )
    }

    #[test]
    fn validates_staged_strings_and_affinity() -> crate::Result<()> {
        let builder = builder()?;
        assert!(matches!(
            builder.set_name(""),
            Err(Error::InvalidProcessName)
        ));
        builder.set_name("init")?;
        builder.add_argument("")?;
        assert!(matches!(
            builder.add_environment("=bad"),
            Err(Error::InvalidProcessEnvironment)
        ));
        builder.add_environment("PATH=/bin")?;
        assert!(matches!(
            builder.set_affinity(&[]),
            Err(Error::InvalidProcessAffinity)
        ));
        builder.set_affinity(&[1])?;
        Ok(())
    }

    #[test]
    fn yield_reports_the_kernel_status() -> crate::Result<()> {
        yield_now()
    }

    #[test]
    fn rejected_move_returns_owner_and_success_consumes_it() -> crate::Result<()> {
        let builder = builder()?;
        let source = owner::<EventObject>(hyper_abi::HYPER_NATIVE_OBJECT_EVENT)?;
        let failure = match builder.add_handle_move(source, 99, RightsOffer::SameRights) {
            Ok(()) => return Err(Error::InvalidResponse),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), Error::Status(Status::BAD_STATE));
        let (_, source) = failure.into_parts();
        builder
            .add_handle_move(source, 1, RightsOffer::Exact(Rights::TRANSFER))
            .map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn start_returns_supervisor_process_owner() -> crate::Result<()> {
        let builder = builder()?;
        builder.set_name("init")?;
        builder.add_argument("init")?;
        builder.seal()?;
        let process = builder.start().map_err(|failure| failure.error())?;
        assert_eq!(process.info()?.rights, super::PROCESS_SUPERVISOR_RIGHTS);
        process.as_process_supervisor().request_stop()?;
        process
            .as_process_supervisor()
            .wait_terminated(hyper_abi::HYPER_NATIVE_DEADLINE_INFINITE)?;
        let info = process.as_process_supervisor().info()?;
        assert_eq!(info.phase, ProcessPhase::Stopped);
        assert_eq!(
            info.terminal,
            Some(ProcessTermination::LastThreadExited { status: -7 })
        );
        Ok(())
    }
}

/// Returns this process's observation-only kernel object identifier.
pub fn current_process_id() -> crate::Result<u64> {
    // SAFETY: hyper-os APIs execute only in a Native process with its SDK.
    let result = unsafe { hyper_sys::process_get_current_id() };
    crate::Status::from_raw(result.status).into_result()?;
    if result.value0 == 0 || result.value1 != 0 {
        return Err(crate::Error::InvalidResponse);
    }
    Ok(result.value0)
}
