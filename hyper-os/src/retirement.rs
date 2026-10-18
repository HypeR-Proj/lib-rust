// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-owned, bounded observation after process execution has stopped.
//!
//! A view never keeps an endpoint alive or grants access to the original VMAR,
//! VMO or device. Releasing its controller revokes every derived view. Missing
//! pages are reported as unavailable; reading a scene never asks a filesystem
//! to populate it. There is no application self-registration or kernel callback.

use crate::handle::{
    AnyObject, CrashViewObject, HandleRef, OwnedHandle, ProcessBuilderObject,
    ProcessRetirementObject, Rights, TypedObject,
};
use crate::{Error, Result, Status};

pub use hyper_abi::{
    HyperNativeCrashHandle as CrashHandle, HyperNativeCrashMapping as CrashMapping,
    HyperNativeCrashThread as CrashThread,
};

/// State of one supervisor's diagnostic retention obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionPhase {
    Prepared,
    Running,
    Stopping,
    Ready,
    Released,
}

/// Independently sampled lifecycle and bounded scene summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessRetirementInfo {
    pub phase: RetentionPhase,
    pub flags: u32,
    pub release_reason: u32,
    pub process_koid: u64,
    pub deadline_ns: u64,
    pub retained_bytes: u64,
    pub memory_limit: u64,
    pub terminal_reason: u32,
    pub fault_class: u32,
    pub exit_status: i64,
    pub fault_pc: u64,
    pub fault_address: u64,
    pub fault_syndrome: u64,
    pub thread_count: u32,
    pub mapping_count: u32,
    pub handle_count: u32,
}

impl ProcessRetirementInfo {
    #[must_use]
    pub const fn ready(&self) -> bool {
        matches!(self.phase, RetentionPhase::Ready)
    }

    #[must_use]
    pub const fn released(&self) -> bool {
        matches!(self.phase, RetentionPhase::Released)
    }
}

/// Linear permission to retain and explicitly release a child's stopped scene.
///
/// A controller may be transferred to another supervisor. Dropping its final
/// active owner releases retention; ordinary Process observers cannot extend
/// it. Release does not bypass CPU, translation or DMA retirement.
pub struct ProcessRetirement(OwnedHandle<ProcessRetirementObject>);

impl ProcessRetirement {
    #[must_use]
    pub const fn from_handle(handle: OwnedHandle<ProcessRetirementObject>) -> Self {
        Self(handle)
    }

    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<ProcessRetirementObject> {
        self.0
    }

    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, ProcessRetirementObject> {
        self.0.as_handle_ref()
    }

    pub fn info(&self) -> Result<ProcessRetirementInfo> {
        let mut record = empty_info();
        // SAFETY: The controller and initialized output remain live for the call.
        let result = unsafe {
            hyper_sys::process_retirement_get_info(self.0.as_handle_ref().raw().get(), &mut record)
        };
        decode_info(result, record)
    }

    /// Waits until a bounded scene is ready or retention has already ended.
    /// A released observation is returned normally so supervisors can retire
    /// a child even when a deadline or lost authority discarded its scene.
    pub fn wait_ready(&self, deadline: u64) -> Result<ProcessRetirementInfo> {
        use crate::wait::{ObjectSignals, WaitItem, wait_many};
        wait_many(
            &[WaitItem::new(
                self.as_handle_ref(),
                ObjectSignals::<ProcessRetirementObject>::READY
                    .union(ObjectSignals::<ProcessRetirementObject>::RELEASED),
            )],
            deadline,
        )?;
        self.info()
    }

    /// Derives a revocable read-only view after the scene becomes ready.
    pub fn open_view(&self) -> Result<CrashView> {
        let raw = self.0.as_handle_ref().raw();
        // SAFETY: The typed controller is borrowed and successful output is adopted once.
        let result = unsafe { hyper_sys::process_retirement_open_view(raw.get()) };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: Success transfers one new view and may not alias the input.
        let handle = unsafe {
            crate::handle::adopt_produced_handle_excluding::<AnyObject>(result.value0, &[raw])?
        };
        if result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(CrashView(validate_handle(
            handle,
            Rights::DUPLICATE
                .union(Rights::TRANSFER)
                .union(Rights::INSPECT)
                .union(Rights::READ),
        )?))
    }

    /// Irreversibly permits cleanup, including when called before the child exits.
    /// This operation is idempotent and leaves the controller queryable.
    pub fn release(&self) -> Result<()> {
        // SAFETY: The controller remains borrowed for this operation.
        let result =
            unsafe { hyper_sys::process_retirement_release(self.0.as_handle_ref().raw().get()) };
        Status::from_raw(result.status).into_result()
    }
}

/// Read-only, revocable evidence; this handle cannot extend scene retention.
pub struct CrashView(OwnedHandle<CrashViewObject>);

impl CrashView {
    #[must_use]
    pub const fn from_handle(handle: OwnedHandle<CrashViewObject>) -> Self {
        Self(handle)
    }

    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<CrashViewObject> {
        self.0
    }

    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, CrashViewObject> {
        self.0.as_handle_ref()
    }

    pub fn info(&self) -> Result<ProcessRetirementInfo> {
        let mut record = empty_info();
        // SAFETY: The view and initialized output remain live for the call.
        let result = unsafe {
            hyper_sys::crash_view_get_info(self.0.as_handle_ref().raw().get(), &mut record)
        };
        decode_info(result, record)
    }

    /// Copies 1–65536 bytes from retained private pages without target page-in.
    /// Holes and excluded mappings are errors; a short read ends at a retained
    /// range boundary. REVOKED means the controller released the entire scene.
    pub fn read_memory(&self, address: u64, output: &mut [u8]) -> Result<usize> {
        if output.is_empty() || output.len() > hyper_abi::HYPER_NATIVE_CRASH_READ_MAX_BYTES as usize
        {
            return Err(Error::Status(Status::INVALID_ARGUMENT));
        }
        // SAFETY: The typed view and writable slice remain live throughout the copy.
        let result = unsafe {
            hyper_sys::crash_view_read(
                self.0.as_handle_ref().raw().get(),
                address,
                output.as_mut_ptr(),
                output.len(),
            )
        };
        Status::from_raw(result.status).into_result()?;
        let length = usize::try_from(result.value0).map_err(|_| Error::InvalidResponse)?;
        if result.value1 != 0 || length > output.len() {
            return Err(Error::InvalidResponse);
        }
        Ok(length)
    }
}

macro_rules! scene_record {
    ($method:ident, $record:ty, $syscall:path) => {
        impl CrashView {
            /// Copies one indexed record. Start at zero; a zero next index ends
            /// enumeration, and `NOT_FOUND` means the requested record is absent.
            pub fn $method(&self, index: u64) -> Result<($record, u64)> {
                // SAFETY: This ABI record consists exclusively of integers and
                // byte arrays, all valid when zero-initialized.
                let mut record: $record = unsafe { core::mem::zeroed() };
                let result =
                    // SAFETY: A live typed view and one writable record are borrowed.
                    unsafe { $syscall(self.0.as_handle_ref().raw().get(), index, &mut record) };
                Status::from_raw(result.status).into_result()?;
                let expected = core::mem::size_of::<$record>() as u64;
                if result.value0 < expected
                    || result.value0 > hyper_abi::HYPER_NATIVE_EXTENSIBLE_RECORD_MAX_BYTES
                    || u64::from(record.size) != result.value0
                    || (result.value1 != 0 && result.value1 <= index)
                {
                    return Err(Error::InvalidResponse);
                }
                Ok((record, result.value1))
            }
        }
    };
}

scene_record!(thread, CrashThread, hyper_sys::crash_view_thread);
scene_record!(mapping, CrashMapping, hyper_sys::crash_view_mapping);
scene_record!(handle, CrashHandle, hyper_sys::crash_view_handle);

pub(crate) fn retain(
    builder: HandleRef<'_, ProcessBuilderObject>,
    max_bytes: u64,
    timeout_ns: u64,
) -> Result<ProcessRetirement> {
    let raw = builder.raw();
    // SAFETY: The builder remains borrowed; success transfers one controller.
    let result = unsafe { hyper_sys::process_builder_retain(raw.get(), max_bytes, timeout_ns) };
    Status::from_raw(result.status).into_result()?;
    // SAFETY: Successful output is adopted once and may not alias the builder.
    let handle = unsafe {
        crate::handle::adopt_produced_handle_excluding::<AnyObject>(result.value0, &[raw])?
    };
    if result.value1 != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(ProcessRetirement(validate_handle(
        handle,
        Rights::TRANSFER
            .union(Rights::WAIT)
            .union(Rights::INSPECT)
            .union(Rights::INSPECT_DETAILS)
            .union(Rights::RETIRE),
    )?))
}

fn validate_handle<T: TypedObject>(
    handle: OwnedHandle<AnyObject>,
    rights: Rights,
) -> Result<OwnedHandle<T>> {
    if handle.info()?.rights != rights {
        return Err(Error::InvalidResponse);
    }
    handle.downcast::<T>().map_err(|failure| failure.error())
}

fn empty_info() -> hyper_abi::HyperNativeProcessRetirementInfo {
    // SAFETY: The wire record contains only integer fields, with zero valid for all.
    unsafe { core::mem::zeroed() }
}

fn decode_info(
    result: hyper_sys::CallResult,
    r: hyper_abi::HyperNativeProcessRetirementInfo,
) -> Result<ProcessRetirementInfo> {
    let size = crate::validate_info_result(
        result,
        core::mem::size_of::<hyper_abi::HyperNativeProcessRetirementInfo>(),
    )?;
    if r.size as usize != size || r.reserved != 0 {
        return Err(Error::InvalidResponse);
    }
    let phase = match u64::from(r.phase) {
        hyper_abi::HYPER_NATIVE_PROCESS_RETIREMENT_PREPARED => RetentionPhase::Prepared,
        hyper_abi::HYPER_NATIVE_PROCESS_RETIREMENT_RUNNING => RetentionPhase::Running,
        hyper_abi::HYPER_NATIVE_PROCESS_RETIREMENT_STOPPING => RetentionPhase::Stopping,
        hyper_abi::HYPER_NATIVE_PROCESS_RETIREMENT_READY => RetentionPhase::Ready,
        hyper_abi::HYPER_NATIVE_PROCESS_RETIREMENT_RELEASED => RetentionPhase::Released,
        _ => return Err(Error::InvalidResponse),
    };
    Ok(ProcessRetirementInfo {
        phase,
        flags: r.flags,
        release_reason: r.release_reason,
        process_koid: r.process_koid,
        deadline_ns: r.deadline_ns,
        retained_bytes: r.retained_bytes,
        memory_limit: r.memory_limit,
        terminal_reason: r.terminal_reason,
        fault_class: r.fault_class,
        exit_status: r.exit_status,
        fault_pc: r.fault_pc,
        fault_address: r.fault_address,
        fault_syndrome: r.fault_syndrome,
        thread_count: r.thread_count,
        mapping_count: r.mapping_count,
        handle_count: r.handle_count,
    })
}
