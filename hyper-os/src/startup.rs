// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Validated, linearly claimed process-startup capabilities.

use core::ffi::{CStr, c_char};
use core::marker::PhantomData;
use core::num::NonZeroU64;
use core::ptr::NonNull;

use crate::console::Console;
use crate::fs::Directory;
use crate::handle::{
    AnyObject, ConsoleObject, DirectoryObject, ExecutableAuthorityObject, FileObject, HandleRef,
    ObjectType, OwnedHandle, ResourceDomainObject, TaskFactoryObject, TaskGroupObject, TypedObject,
    VmarObject, VmoObject,
};
use crate::{Error, Result};

/// SDK convention for a loader file explicitly delegated to a child launcher.
/// This role is opaque to the kernel and grants no ambient path access.
pub const CHILD_LOADER: StartupPurpose<FileObject> = StartupPurpose::new(0x8004_0003);

/// Immutable unconsumed boot arguments supplied to a boot-stage successor.
/// This does not grant ambient configuration or device access.
pub const BOOT_COMMAND_LINE: StartupPurpose<VmoObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_BOOT_COMMAND_LINE as u32);

/// Prepares remaining boot arguments for a successor's startup table.
///
/// The returned immutable VMO has READ, INSPECT and TRANSFER rights. Move it
/// under [`BOOT_COMMAND_LINE`], attenuating to READ | INSPECT for the receiver.
/// No writable source handle survives this call, including its error paths.
pub fn create_boot_command_line(text: &str) -> Result<OwnedHandle<VmoObject>> {
    let (payload, length) = boot_command_line_payload(text)?;
    let source = crate::memory::WritableVmo::create(crate::memory::PAGE_SIZE)?;
    source.write_all_at(0, &payload[..length])?;
    let snapshot = crate::memory::SnapshotVmo::from_vmo(source.as_handle_ref())?;
    snapshot.as_handle_ref().duplicate(
        crate::Rights::READ
            .union(crate::Rights::INSPECT)
            .union(crate::Rights::TRANSFER),
    )
}

const _: () = assert!(hyper_abi::HYPER_NATIVE_STARTUP_MAX_HANDLES <= usize::MAX as u64);
const MAX_STARTUP_HANDLES: usize = hyper_abi::HYPER_NATIVE_STARTUP_MAX_HANDLES as usize;
const CLAIM_WORD_BITS: usize = u64::BITS as usize;
const CLAIM_WORDS: usize = MAX_STARTUP_HANDLES.div_ceil(CLAIM_WORD_BITS);

/// Typed name of one capability supplied at process startup.
pub struct StartupPurpose<T: ObjectType> {
    value: u32,
    _type: PhantomData<fn() -> T>,
}

impl<T: ObjectType> Clone for StartupPurpose<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ObjectType> Copy for StartupPurpose<T> {}

impl<T: ObjectType> StartupPurpose<T> {
    /// Creates a typed purpose declared by the Native ABI or a service SDK.
    ///
    /// The kernel-reported object kind is still checked when the handle is
    /// borrowed or taken, so an incorrect marker cannot forge a typed handle.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self {
            value,
            _type: PhantomData,
        }
    }

    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.value
    }
}

pub const RESOURCE_DOMAIN: StartupPurpose<ResourceDomainObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_RESOURCE_DOMAIN as u32);
pub const TASK_GROUP: StartupPurpose<TaskGroupObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_TASK_GROUP as u32);
pub const TASK_FACTORY: StartupPurpose<TaskFactoryObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_TASK_FACTORY as u32);
pub const EXECUTABLE_AUTHORITY: StartupPurpose<ExecutableAuthorityObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_EXECUTABLE_AUTHORITY as u32);
pub const ROOT_VMAR: StartupPurpose<VmarObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_ROOT_VMAR as u32);
pub const CONSOLE: StartupPurpose<ConsoleObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_CONSOLE as u32);
pub const ROOT_DIRECTORY: StartupPurpose<DirectoryObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_ROOT_DIRECTORY as u32);
pub const TASK_INSPECTOR: StartupPurpose<crate::handle::TaskInspectorObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_TASK_INSPECTOR as u32);
pub const OBJECT_INSPECTOR: StartupPurpose<crate::handle::ObjectInspectorObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_OBJECT_INSPECTOR as u32);
pub const MEMORY_INSPECTOR: StartupPurpose<crate::handle::MemoryInspectorObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_MEMORY_INSPECTOR as u32);
pub const CPU_INSPECTOR: StartupPurpose<crate::handle::CpuInspectorObject> =
    StartupPurpose::new(hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_CPU_INSPECTOR as u32);
pub const VIRTUAL_MACHINE_CREATION_AUTHORITY: StartupPurpose<
    crate::handle::VirtualMachineCreationAuthorityObject,
> = StartupPurpose::new(
    hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_VIRTUAL_MACHINE_CREATION_AUTHORITY as u32,
);
pub const DYNAMIC_LIBRARY_DIRECTORY: StartupPurpose<DirectoryObject> = StartupPurpose::new(
    hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_DYNAMIC_LIBRARY_DIRECTORY as u32,
);

pub const DEVICE_ASSIGNMENT_AUTHORITY: StartupPurpose<
    crate::handle::DeviceAssignmentAuthorityObject,
> = StartupPurpose::new(
    hyper_abi::HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_DEVICE_ASSIGNMENT_AUTHORITY as u32,
);

/// Exclusive safe view of the process-startup record owned by the runtime.
///
/// Every handle begins under this value's logical ownership. [`Self::take`]
/// moves that ownership out exactly once; dropping `Startup` closes every
/// unclaimed handle. Temporary operation wrappers borrow it and therefore
/// cannot overlap a later take of the same startup state.
pub struct Startup<'runtime> {
    arguments: Option<NonNull<*const c_char>>,
    argument_count: usize,
    records: Option<NonNull<hyper_abi::HyperNativeStartupHandle>>,
    count: usize,
    claimed: [u64; CLAIM_WORDS],
    _runtime: PhantomData<&'runtime [hyper_abi::HyperNativeStartupHandle]>,
}

impl<'runtime> Startup<'runtime> {
    /// Constructs the unique safe startup owner at the language-runtime edge.
    ///
    /// # Safety
    ///
    /// `raw` must point to a live `RawStartup` produced by the matching Native
    /// C runtime. Its handle records must remain immutable and initialized for
    /// `'runtime`, and no other owner may close or transfer their values. This
    /// call assumes ownership of every distinct nonzero handle record even if
    /// later record validation fails.
    pub unsafe fn from_raw(raw: *const hyper_sys::RawStartup) -> Result<Self> {
        let raw = NonNull::new(raw.cast_mut()).ok_or(Error::InvalidStartup)?;
        // SAFETY: the caller guarantees a live, initialized RawStartup.
        let startup = unsafe { raw.as_ref() };
        if startup.handle_count > MAX_STARTUP_HANDLES {
            return Err(Error::InvalidStartup);
        }
        let records = if startup.handle_count == 0 {
            None
        } else {
            Some(NonNull::new(startup.handles.cast_mut()).ok_or(Error::InvalidStartup)?)
        };
        let candidate = Self {
            arguments: NonNull::new(startup.arguments.cast_mut()),
            argument_count: startup.argument_count,
            records,
            count: startup.handle_count,
            claimed: [0; CLAIM_WORDS],
            _runtime: PhantomData,
        };
        candidate.validate_records()?;
        Ok(candidate)
    }

    /// Returns the number of validated process arguments.
    #[must_use]
    pub const fn argument_count(&self) -> usize {
        self.argument_count
    }

    /// Borrows one UTF-8 argument from the immutable startup stack.
    pub fn argument(&self, index: usize) -> Result<&str> {
        if index >= self.argument_count {
            return Err(Error::InvalidStartup);
        }
        let arguments = self.arguments.ok_or(Error::InvalidStartup)?;
        // SAFETY: the matching C runtime validated the pointer array and a
        // bounded NUL terminator for every entry before constructing RawStartup.
        let pointer = unsafe { arguments.as_ptr().add(index).read() };
        if pointer.is_null() {
            return Err(Error::InvalidStartup);
        }
        // SAFETY: the runtime's bounded validation establishes a live C string
        // within the immutable startup stack for this runtime lifetime.
        let string = unsafe { CStr::from_ptr(pointer) };
        string.to_str().map_err(|_| Error::InvalidStartup)
    }

    /// Consumes the optional boot-argument capability and copies its text.
    ///
    /// The kernel supplies remaining arguments to its initial process; boot
    /// stages may pass their own remainder to a successor. An absent capability
    /// is distinct from a malformed present one. The handle is closed on both
    /// success and failure. Parameter interpretation remains the caller's policy.
    pub fn take_boot_command_line(&mut self) -> Result<Option<alloc::string::String>> {
        let Some(handle) = self.take_optional(BOOT_COMMAND_LINE)? else {
            return Ok(None);
        };
        read_boot_command_line(|offset, bytes| {
            // SAFETY: the VMO remains owned throughout this synchronous read;
            // `bytes` is uniquely borrowed initialized output storage. The
            // kernel validates the source range and READ authority.
            crate::Status::from_raw(unsafe {
                hyper_sys::vmo_read(
                    handle.as_handle_ref().raw().get(),
                    offset,
                    bytes.as_mut_ptr(),
                    bytes.len(),
                )
            })
            .into_result()
        })
        .map(Some)
    }

    /// Moves one typed startup capability out of this owner exactly once.
    pub fn take<T: TypedObject>(&mut self, purpose: StartupPurpose<T>) -> Result<OwnedHandle<T>> {
        let (index, raw) = self.find_unclaimed(purpose.as_raw())?;
        validate_kind::<T>(raw)?;
        self.mark_claimed(index)?;
        // SAFETY: startup validation proved values unique, and the claim bit
        // moves this exact process handle out of Startup only once.
        Ok(unsafe { OwnedHandle::from_raw_owned(raw) })
    }

    /// Moves an optional typed startup capability out exactly once.
    pub fn take_optional<T: TypedObject>(
        &mut self,
        purpose: StartupPurpose<T>,
    ) -> Result<Option<OwnedHandle<T>>> {
        let Some((index, raw)) = self.find_optional_unclaimed(purpose.as_raw())? else {
            return Ok(None);
        };
        validate_kind::<T>(raw)?;
        self.mark_claimed(index)?;
        // SAFETY: the validated record is unique and now claimed exactly once.
        Ok(Some(unsafe { OwnedHandle::from_raw_owned(raw) }))
    }

    /// Borrows one typed startup capability without moving its ownership.
    pub fn borrow<T: TypedObject>(&self, purpose: StartupPurpose<T>) -> Result<HandleRef<'_, T>> {
        let (_, raw) = self.find_unclaimed(purpose.as_raw())?;
        validate_kind::<T>(raw)?;
        // SAFETY: this borrow is tied to `self`, which remains the unique
        // logical owner of every unclaimed startup handle.
        Ok(unsafe { HandleRef::from_raw_borrowed(raw) })
    }

    /// Borrows the Console capability assigned to this process.
    pub fn console(&self) -> Result<Console<'_>> {
        Ok(Console::from_handle(self.borrow(CONSOLE)?))
    }

    /// Moves the process's `ResourceDomain` authority out exactly once.
    pub fn take_resource_domain(&mut self) -> Result<OwnedHandle<ResourceDomainObject>> {
        self.take(RESOURCE_DOMAIN)
    }

    /// Moves the process's `TaskGroup` authority out exactly once.
    ///
    /// The handle remains a shared lifetime owner even when its operational
    /// rights are attenuated. Closing the last group handle asynchronously
    /// requests stop for all group members.
    pub fn take_task_group(&mut self) -> Result<OwnedHandle<TaskGroupObject>> {
        self.take(TASK_GROUP)
    }

    /// Moves the process's `TaskFactory` authority out exactly once.
    pub fn take_task_factory(&mut self) -> Result<OwnedHandle<TaskFactoryObject>> {
        self.take(TASK_FACTORY)
    }

    /// Moves the process's Console capability out exactly once.
    pub fn take_console(&mut self) -> Result<OwnedHandle<ConsoleObject>> {
        self.take(CONSOLE)
    }

    /// Moves the initial root-directory authority out exactly once.
    pub fn take_root_directory(&mut self) -> Result<Directory> {
        self.take(ROOT_DIRECTORY).map(Directory::from_handle)
    }

    fn validate_records(&self) -> Result<()> {
        for index in 0..self.count {
            let record = self.record(index)?;
            if record.purpose == 0 || record.flags != 0 || record.handle == 0 {
                return Err(Error::InvalidStartup);
            }
            for previous in 0..index {
                let prior = self.record(previous)?;
                if prior.purpose == record.purpose || prior.handle == record.handle {
                    return Err(Error::InvalidStartup);
                }
            }
        }
        Ok(())
    }

    fn find_unclaimed(&self, purpose: u32) -> Result<(usize, NonZeroU64)> {
        self.find_optional_unclaimed(purpose)?
            .ok_or(Error::InvalidStartup)
    }

    fn find_optional_unclaimed(&self, purpose: u32) -> Result<Option<(usize, NonZeroU64)>> {
        if purpose == 0 {
            return Err(Error::InvalidStartup);
        }
        for index in 0..self.count {
            let record = self.record(index)?;
            if record.purpose == purpose {
                if self.is_claimed(index)? {
                    return Err(Error::InvalidStartup);
                }
                let raw = NonZeroU64::new(record.handle).ok_or(Error::InvalidStartup)?;
                return Ok(Some((index, raw)));
            }
        }
        Ok(None)
    }

    fn record(&self, index: usize) -> Result<hyper_abi::HyperNativeStartupHandle> {
        if index >= self.count {
            return Err(Error::InvalidStartup);
        }
        let records = self.records.ok_or(Error::InvalidStartup)?;
        // SAFETY: construction validates a live array of `count` immutable
        // records, and the explicit bound above keeps `index` within it.
        Ok(unsafe { records.as_ptr().add(index).read() })
    }

    fn is_claimed(&self, index: usize) -> Result<bool> {
        let word = index / CLAIM_WORD_BITS;
        let bit = index % CLAIM_WORD_BITS;
        self.claimed
            .get(word)
            .map(|value| value & (1_u64 << bit) != 0)
            .ok_or(Error::InvalidStartup)
    }

    fn mark_claimed(&mut self, index: usize) -> Result<()> {
        let word = index / CLAIM_WORD_BITS;
        let bit = index % CLAIM_WORD_BITS;
        let value = self.claimed.get_mut(word).ok_or(Error::InvalidStartup)?;
        let mask = 1_u64 << bit;
        if *value & mask != 0 {
            return Err(Error::InvalidStartup);
        }
        *value |= mask;
        Ok(())
    }
}

impl Drop for Startup<'_> {
    fn drop(&mut self) {
        for index in 0..self.count {
            if self.is_claimed(index) != Ok(false) {
                continue;
            }
            let Ok(record) = self.record(index) else {
                continue;
            };
            let Some(raw) = NonZeroU64::new(record.handle) else {
                continue;
            };
            if self.raw_appeared_before(index, raw) {
                continue;
            }
            // SAFETY: unclaimed validated startup records remain uniquely
            // owned by Startup. De-duplication also makes rejection cleanup
            // safe when validation discovered repeated malformed records.
            drop(unsafe { OwnedHandle::<AnyObject>::from_raw_owned(raw) });
        }
    }
}

impl Startup<'_> {
    fn raw_appeared_before(&self, index: usize, raw: NonZeroU64) -> bool {
        for previous in 0..index {
            if self
                .record(previous)
                .is_ok_and(|record| record.handle == raw.get())
            {
                return true;
            }
        }
        false
    }
}

fn validate_kind<T: TypedObject>(raw: NonZeroU64) -> Result<()> {
    // SAFETY: this short-lived borrow cannot escape validation and its caller
    // owns the startup record throughout the metadata query.
    let handle = unsafe { HandleRef::<T>::from_raw_borrowed(raw) };
    let info = handle.info()?;
    if info.kind == T::KIND {
        Ok(())
    } else {
        Err(Error::UnexpectedObjectKind {
            expected: T::KIND.as_raw(),
            actual: info.kind.as_raw(),
        })
    }
}

const BOOT_ARGUMENT_MAX: usize = hyper_abi::HYPER_NATIVE_BOOT_COMMAND_LINE_MAX_BYTES as usize;
const _: () = assert!(8 + BOOT_ARGUMENT_MAX <= crate::memory::PAGE_SIZE as usize);

fn boot_command_line_payload(text: &str) -> Result<([u8; 8 + BOOT_ARGUMENT_MAX], usize)> {
    if text.len() > BOOT_ARGUMENT_MAX || text.as_bytes().contains(&0) {
        return Err(Error::InvalidStartup);
    }
    let mut payload = [0; 8 + BOOT_ARGUMENT_MAX];
    payload[..8].copy_from_slice(&(text.len() as u64).to_le_bytes());
    payload[8..8 + text.len()].copy_from_slice(text.as_bytes());
    Ok((payload, 8 + text.len()))
}

fn read_boot_command_line(
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<alloc::string::String> {
    let mut length = [0; 8];
    read(0, &mut length)?;
    let length = usize::try_from(u64::from_le_bytes(length)).map_err(|_| Error::InvalidStartup)?;
    if length > BOOT_ARGUMENT_MAX {
        return Err(Error::InvalidStartup);
    }
    let mut bytes = [0; BOOT_ARGUMENT_MAX];
    if length != 0 {
        read(8, &mut bytes[..length])?;
    }
    let text = core::str::from_utf8(&bytes[..length]).map_err(|_| Error::InvalidStartup)?;
    if text.as_bytes().contains(&0) {
        return Err(Error::InvalidStartup);
    }
    let mut result = alloc::string::String::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| Error::Status(crate::Status::NO_MEMORY))?;
    result.push_str(text);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{ROOT_DIRECTORY, Startup, StartupPurpose};
    use crate::Error;
    use crate::handle::ByteChannelObject;

    const SERVICE_ENDPOINT: StartupPurpose<ByteChannelObject> = StartupPurpose::new(0x4859_0100);

    #[test]
    fn boot_argument_payload_validates_and_roundtrips() -> Result<(), Error> {
        for text in [
            alloc::string::String::from("bad\0argument"),
            "x".repeat(hyper_abi::HYPER_NATIVE_BOOT_COMMAND_LINE_MAX_BYTES as usize + 1),
        ] {
            assert!(matches!(
                super::boot_command_line_payload(&text),
                Err(Error::InvalidStartup)
            ));
        }
        for text in [
            "",
            "key=one key=two unicode=λ",
            &"x".repeat(super::BOOT_ARGUMENT_MAX),
        ] {
            let (payload, length) = super::boot_command_line_payload(text)?;
            assert_eq!(length, text.len() + 8);
            let decoded = super::read_boot_command_line(|offset, output| {
                let source = payload
                    .get(offset as usize..offset as usize + output.len())
                    .ok_or(Error::InvalidStartup)?;
                output.copy_from_slice(source);
                Ok(())
            })?;
            assert_eq!(decoded, text);
        }
        Ok(())
    }

    #[test]
    fn boot_command_line_is_bounded_utf8_without_nul() -> Result<(), Error> {
        fn decode(bytes: &[u8], length: u64) -> Result<alloc::string::String, Error> {
            super::read_boot_command_line(|offset, output| {
                if offset == 0 {
                    output.copy_from_slice(&length.to_le_bytes());
                } else {
                    let source = bytes.get(..output.len()).ok_or(Error::InvalidStartup)?;
                    output.copy_from_slice(source);
                }
                Ok(())
            })
        }
        let text = b"earlycon hyper.boot-profile=recovery";
        assert_eq!(decode(text, text.len() as u64)?.as_bytes(), text);
        assert_eq!(decode(&[], 0)?, "");
        assert!(matches!(decode(&[0xff], 1), Err(Error::InvalidStartup)));
        assert!(matches!(decode(b"a\0b", 3), Err(Error::InvalidStartup)));
        assert!(matches!(decode(b"x", 2), Err(Error::InvalidStartup)));
        assert!(matches!(decode(&[], u64::MAX), Err(Error::InvalidStartup)));
        let max = hyper_abi::HYPER_NATIVE_BOOT_COMMAND_LINE_MAX_BYTES as usize;
        let bytes = alloc::vec![b'x'; max];
        assert_eq!(decode(&bytes, max as u64)?.len(), max);
        assert!(matches!(
            decode(&bytes, max as u64 + 1),
            Err(Error::InvalidStartup)
        ));
        Ok(())
    }

    fn raw_startup(handles: &[hyper_abi::HyperNativeStartupHandle]) -> hyper_sys::RawStartup {
        hyper_sys::RawStartup {
            argument_count: 0,
            arguments: core::ptr::null(),
            environment_count: 0,
            environment: core::ptr::null(),
            auxiliary_count: 0,
            auxiliary: core::ptr::null(),
            handle_count: handles.len(),
            handles: handles.as_ptr(),
        }
    }

    #[test]
    fn duplicate_purposes_and_handle_values_are_rejected() {
        let duplicate_purpose = [
            hyper_abi::HyperNativeStartupHandle {
                purpose: 1,
                flags: 0,
                handle: 1,
            },
            hyper_abi::HyperNativeStartupHandle {
                purpose: 1,
                flags: 0,
                handle: 2,
            },
        ];
        let raw = raw_startup(&duplicate_purpose);
        // SAFETY: the local record array remains initialized for the call.
        let result = unsafe { Startup::from_raw(&raw) };
        assert!(matches!(result, Err(Error::InvalidStartup)));

        let duplicate_handle = [
            hyper_abi::HyperNativeStartupHandle {
                purpose: 1,
                flags: 0,
                handle: 2,
            },
            hyper_abi::HyperNativeStartupHandle {
                purpose: 2,
                flags: 0,
                handle: 2,
            },
        ];
        let raw = raw_startup(&duplicate_handle);
        // SAFETY: the local record array remains initialized for the call.
        let result = unsafe { Startup::from_raw(&raw) };
        assert!(matches!(result, Err(Error::InvalidStartup)));
    }

    #[test]
    fn take_claims_one_typed_startup_handle_once() -> Result<(), Error> {
        let handles = [hyper_abi::HyperNativeStartupHandle {
            purpose: SERVICE_ENDPOINT.as_raw(),
            flags: 0,
            handle: hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL.into(),
        }];
        let raw = raw_startup(&handles);
        // SAFETY: `raw` and its immutable local handle array outlive Startup.
        let mut startup = unsafe { Startup::from_raw(&raw)? };
        let owned = startup.take(SERVICE_ENDPOINT)?;
        assert_eq!(
            owned.info()?.kind.as_raw(),
            hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL
        );
        assert!(matches!(
            startup.take(SERVICE_ENDPOINT),
            Err(Error::InvalidStartup)
        ));
        Ok(())
    }

    #[test]
    fn take_root_directory_moves_the_typed_owner_once() -> Result<(), Error> {
        let handles = [hyper_abi::HyperNativeStartupHandle {
            purpose: ROOT_DIRECTORY.as_raw(),
            flags: 0,
            handle: hyper_abi::HYPER_NATIVE_OBJECT_DIRECTORY.into(),
        }];
        let raw = raw_startup(&handles);
        // SAFETY: `raw` and its immutable local handle array outlive Startup.
        let mut startup = unsafe { Startup::from_raw(&raw)? };
        let root_directory = startup.take_root_directory()?;
        assert_eq!(
            root_directory.into_handle().info()?.kind.as_raw(),
            hyper_abi::HYPER_NATIVE_OBJECT_DIRECTORY
        );
        assert!(matches!(
            startup.take_root_directory(),
            Err(Error::InvalidStartup)
        ));
        Ok(())
    }
}
