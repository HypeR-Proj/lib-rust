// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Shared file mappings with explicit raw-memory access and durability fences.

use super::PAGE_SIZE;
use crate::fs::{File, SyncScope};
use crate::handle::{HandleRef, OwnedHandle, VmarObject};
use crate::{Error, Result, Status};

/// Existing complete file pages to map into the calling process.
#[derive(Clone, Copy, Debug)]
pub struct SharedFileMappingOptions {
    pub file_offset: u64,
    pub length: u64,
    pub writable: bool,
}

/// Owns one child VMAR and its coherent shared-file mapping.
///
/// Other mappings and ordinary file I/O may modify these bytes. This owner
/// deliberately exposes no safe Rust slices. Closing the source File preserves
/// the mapping; unmapping is not a durability fence. Use [`Self::sync`] before
/// unmapping when persistence must be confirmed. Drop attempts cleanup once;
/// use [`Self::try_close`] to retain cleanup authority after a failed unmap.
pub struct SharedFileMapping {
    region: Option<OwnedHandle<VmarObject>>,
    address: usize,
    length: usize,
    writable: bool,
    mapped: bool,
}

impl File {
    /// Reserves a free child VMAR and maps existing complete file pages.
    ///
    /// The kernel requires `parent` to belong to the current process. The
    /// returned owner exposes only raw pointers: every memory access still
    /// requires the caller to establish lifetime and synchronization safety.
    /// See [`Self::map_shared_at`] for eligibility and fixed-extent semantics.
    pub fn map_shared(
        &self,
        parent: HandleRef<'_, VmarObject>,
        options: SharedFileMappingOptions,
    ) -> Result<SharedFileMapping> {
        // Validate the file range before reserving an automatically chosen VA.
        let (_, length) = validate_mapping(PAGE_SIZE, options)?;
        self.map_shared_inner(parent, 0, length, options, 0)
    }

    /// Maps shared file bytes at an exact unused address.
    ///
    /// The File needs READ and, for writable authority, WRITE. Only complete
    /// existing pages on an eligible writeback provider are supported. Mapping
    /// prevents file-size changes until the last extent lease retires. It does
    /// not imply residency, executable authority or ABI03 atomic-wait support.
    /// Explicit residency locks and address-keyed atomic wait/wake on this
    /// backing are currently unsupported; use independent coordination memory.
    /// Hardware faults which cannot be serviced retain the fatal-fault policy.
    ///
    /// # Safety
    /// `parent` must belong to the calling process. The caller owns the unused
    /// destination range and must not independently unmap, protect or replace
    /// it for the returned owner's lifetime. Access through returned pointers
    /// must obey Rust aliasing and cross-thread/process synchronization rules;
    /// this mapping does not make unsynchronized data races valid Rust.
    pub unsafe fn map_shared_at(
        &self,
        parent: HandleRef<'_, VmarObject>,
        address: u64,
        options: SharedFileMappingOptions,
    ) -> Result<SharedFileMapping> {
        let (address, length) = validate_mapping(address, options)?;
        self.map_shared_inner(
            parent,
            address as u64,
            length,
            options,
            hyper_abi::HYPER_NATIVE_VMAR_ALLOCATE_EXACT,
        )
    }

    fn map_shared_inner(
        &self,
        parent: HandleRef<'_, VmarObject>,
        address: u64,
        length: usize,
        options: SharedFileMappingOptions,
        flags: u64,
    ) -> Result<SharedFileMapping> {
        // SAFETY: zero hint allocates unused space. EXACT callers establish
        // their address ownership in map_shared_at; kernel validates parent.
        let result =
            unsafe { hyper_sys::vmar_allocate(parent.raw().get(), address, options.length, flags) };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: successful allocation transfers one fresh VMAR owner.
        let region = unsafe {
            crate::handle::adopt_produced_handle_excluding::<VmarObject>(
                result.value0,
                &[parent.raw(), self.as_handle_ref().raw()],
            )?
        };
        let mut owner = SharedFileMapping {
            region: Some(region),
            address: 0,
            length,
            writable: options.writable,
            mapped: false,
        };
        let mapped_address = usize::try_from(result.value1).map_err(|_| Error::InvalidResponse)?;
        if mapped_address == 0
            || !(mapped_address as u64).is_multiple_of(PAGE_SIZE)
            || mapped_address.checked_add(length).is_none()
            || (flags != 0 && result.value1 != address)
        {
            return Err(Error::InvalidResponse);
        }
        owner.address = mapped_address;
        let record = hyper_abi::HyperNativeSharedFileMapping {
            file_offset: options.file_offset,
            address: mapped_address as u64,
            length: options.length,
            permissions: (hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_READ
                | if options.writable {
                    hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_WRITE
                } else {
                    0
                }) as u32,
            options: 0,
            reserved0: 0,
            reserved1: 0,
        };
        let region = owner.region.as_ref().ok_or(Error::InvalidResponse)?;
        // SAFETY: the owned child covers the destination; the File and request
        // stay borrowed throughout the non-retaining invocation.
        Status::from_raw(unsafe {
            hyper_sys::vmar_map_file_shared(
                region.as_handle_ref().raw().get(),
                self.as_handle_ref().raw().get(),
                &record,
                core::mem::size_of_val(&record),
            )
        })
        .into_result()?;
        owner.mapped = true;
        Ok(owner)
    }
}

fn validate_mapping(address: u64, options: SharedFileMappingOptions) -> Result<(usize, usize)> {
    if address == 0
        || !address.is_multiple_of(PAGE_SIZE)
        || !options.file_offset.is_multiple_of(PAGE_SIZE)
        || options.length == 0
        || !options.length.is_multiple_of(PAGE_SIZE)
        || address.checked_add(options.length).is_none()
        || options.file_offset.checked_add(options.length).is_none()
    {
        return Err(Error::InvalidMemoryRange);
    }
    let address = usize::try_from(address).map_err(|_| Error::InvalidMemoryRange)?;
    let length = usize::try_from(options.length).map_err(|_| Error::InvalidMemoryRange)?;
    if length > isize::MAX as usize {
        return Err(Error::InvalidMemoryRange);
    }
    Ok((address, length))
}

impl SharedFileMapping {
    /// Borrows the child VMAR for explicit Native operations. Independently
    /// replacing, unmapping or protecting it invalidates outstanding raw-pointer
    /// access assumptions; the caller must honor `map_shared_at` ownership rules.
    pub fn as_handle_ref(&self) -> Result<HandleRef<'_, VmarObject>> {
        // A publicly accessible owner always retains its child. Failed close
        // moves it into SharedFileMappingCloseError, which exposes no mapping.
        self.region
            .as_ref()
            .map(OwnedHandle::as_handle_ref)
            .ok_or(Error::InvalidResponse)
    }

    /// Raw shared bytes. Dereferencing requires independent synchronization and
    /// must not outlive this mapping or a successful explicit close.
    #[must_use]
    pub const fn as_ptr(&self) -> *const u8 {
        self.address as *const u8
    }

    /// Raw writable bytes, subject to the same sharing and lifetime constraints
    /// as [`Self::as_ptr`]. A mutable pointer does not grant exclusive access.
    pub fn as_mut_ptr(&self) -> Result<*mut u8> {
        if !self.writable {
            return Err(Error::Status(Status::ACCESS_DENIED));
        }
        Ok(self.address as *mut u8)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Synchronizes the whole mapping using its retained file authority.
    /// The source File must have carried WRITE when the mapping was created;
    /// a READ-only source cannot synchronize, even if other aliases are writable.
    /// `Volume` is not a supported range scope. File DATA/ALL may issue a
    /// stronger whole-file fence, but do not unconditionally checkpoint.
    pub fn sync(&self, scope: SyncScope) -> Result<()> {
        self.sync_range(0, self.length, scope)
    }

    /// Synchronizes complete mapped pages. Writes ordered before the finite
    /// synchronization boundary are included; later writes are not promised.
    /// Success is not an atomic snapshot of unsynchronized writers.
    pub fn sync_range(&self, offset: usize, length: usize, scope: SyncScope) -> Result<()> {
        let scope = sync_scope(scope)?;
        if length == 0
            || !(offset as u64).is_multiple_of(PAGE_SIZE)
            || !(length as u64).is_multiple_of(PAGE_SIZE)
            || offset
                .checked_add(length)
                .is_none_or(|end| end > self.length)
        {
            return Err(Error::InvalidMemoryRange);
        }
        let record = hyper_abi::HyperNativeSharedFileSync {
            address: self
                .address
                .checked_add(offset)
                .ok_or(Error::InvalidMemoryRange)? as u64,
            length: length as u64,
            scope,
            options: 0,
            reserved0: 0,
            reserved1: 0,
        };
        let region = self.region.as_ref().ok_or(Error::InvalidResponse)?;
        // SAFETY: Self retains the mapped region and readable request record.
        Status::from_raw(unsafe {
            hyper_sys::vmar_sync_file_range(
                region.as_handle_ref().raw().get(),
                &record,
                core::mem::size_of_val(&record),
            )
        })
        .into_result()
    }

    pub fn try_close(mut self) -> core::result::Result<(), SharedFileMappingCloseError> {
        match self.close_inner() {
            Ok(()) => Ok(()),
            Err(error) => Err(SharedFileMappingCloseError {
                error,
                mapping: self,
            }),
        }
    }

    fn close_inner(&mut self) -> Result<()> {
        let Some(region) = self.region.as_ref() else {
            return Ok(());
        };
        let raw = region.as_handle_ref().raw().get();
        if self.mapped {
            // SAFETY: the owner controls its exact range; callers must not keep
            // using raw addresses after close. Success acknowledges retirement.
            Status::from_raw(unsafe {
                hyper_sys::vmar_unmap(raw, self.address as u64, self.length as u64)
            })
            .into_result()?;
            self.mapped = false;
        }
        // SAFETY: only this owned, now-empty child is destroyed. Failure keeps
        // cleanup authority; success consumes the handle exactly once.
        Status::from_raw(unsafe { hyper_sys::vmar_destroy(raw) }).into_result()?;
        if let Some(region) = self.region.take() {
            let _ = region.into_raw();
        }
        Ok(())
    }
}

fn sync_scope(scope: SyncScope) -> Result<u32> {
    match scope {
        SyncScope::Data => Ok(hyper_abi::HYPER_NATIVE_FILE_SYNC_DATA as u32),
        SyncScope::Full => Ok(hyper_abi::HYPER_NATIVE_FILE_SYNC_ALL as u32),
        SyncScope::Volume => Err(Error::Status(Status::INVALID_ARGUMENT)),
    }
}

/// A failed explicit cleanup retains only retry authority, not raw byte access.
#[must_use = "retry close or accept best-effort cleanup on drop"]
pub struct SharedFileMappingCloseError {
    error: Error,
    mapping: SharedFileMapping,
}

impl SharedFileMappingCloseError {
    #[must_use]
    pub const fn error(&self) -> Error {
        self.error
    }

    pub fn retry(self) -> core::result::Result<(), Self> {
        self.mapping.try_close()
    }
}

impl core::fmt::Debug for SharedFileMappingCloseError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SharedFileMappingCloseError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl Drop for SharedFileMapping {
    fn drop(&mut self) {
        // A blocking reservation on another thread can reject teardown. Never
        // spin in Drop and prevent that operation from making progress.
        let _ = self.close_inner();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_rejects_overflow_and_partial_pages_before_reserving_a_region() {
        let valid = SharedFileMappingOptions {
            file_offset: 0,
            length: PAGE_SIZE,
            writable: true,
        };
        assert_eq!(
            validate_mapping(PAGE_SIZE, valid),
            Ok((PAGE_SIZE as usize, PAGE_SIZE as usize))
        );
        for (address, options) in [
            (0, valid),
            (PAGE_SIZE + 1, valid),
            (
                PAGE_SIZE,
                SharedFileMappingOptions {
                    file_offset: 1,
                    ..valid
                },
            ),
            (PAGE_SIZE, SharedFileMappingOptions { length: 0, ..valid }),
            (
                PAGE_SIZE,
                SharedFileMappingOptions {
                    length: PAGE_SIZE + 1,
                    ..valid
                },
            ),
            (u64::MAX - PAGE_SIZE + 1, valid),
            (
                PAGE_SIZE,
                SharedFileMappingOptions {
                    file_offset: u64::MAX - PAGE_SIZE + 1,
                    ..valid
                },
            ),
        ] {
            assert_eq!(
                validate_mapping(address, options),
                Err(Error::InvalidMemoryRange)
            );
        }
    }

    #[test]
    fn range_fences_do_not_accept_volume_scope() {
        assert_eq!(sync_scope(SyncScope::Data), Ok(0));
        assert_eq!(sync_scope(SyncScope::Full), Ok(1));
        assert_eq!(
            sync_scope(SyncScope::Volume),
            Err(Error::Status(Status::INVALID_ARGUMENT))
        );
    }
}
