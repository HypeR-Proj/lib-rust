// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Private address-space mappings with explicit copy policy.

use super::{PAGE_SIZE, SnapshotVmo};
use crate::fs::{File, FileProtection};
use crate::handle::{AnyObject, FileProtectionObject, HandleRef, OwnedHandle, VmarObject};
use crate::{Error, Result, Status};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateMappingMode {
    CopyOnWrite,
    Eager,
}

/// Bytes outside the selected source interval are initialized to zero.
#[derive(Clone, Copy, Debug)]
pub struct PrivateMappingOptions {
    pub source_offset: u64,
    pub source_length: u64,
    pub data_offset: u64,
    pub size: u64,
    pub writable: bool,
    pub mode: PrivateMappingMode,
}

/// Owns an exact child VMAR and its private mapping.
///
/// Use [`Self::try_close`] when reclamation must be confirmed. Drop attempts
/// cleanup once; if the kernel rejects it, the process retains the mapping or
/// region until process teardown. Drop never waits indefinitely for another
/// thread's outstanding memory reservation.
pub struct PrivateMapping {
    region: Option<OwnedHandle<VmarObject>>,
    address: usize,
    size: usize,
    writable: bool,
    mapped: bool,
}

impl SnapshotVmo {
    /// Maps a fresh private view into the calling process.
    ///
    /// # Safety
    /// `parent` must belong to the calling process. The caller must own the
    /// destination address range and must not independently unmap, protect,
    /// remap, or expose aliases to it for the returned mapping's lifetime.
    pub unsafe fn map_private_at(
        &self,
        parent: HandleRef<'_, VmarObject>,
        address: u64,
        options: PrivateMappingOptions,
    ) -> Result<PrivateMapping> {
        // SAFETY: the caller owns the destination range and all input owners
        // remain borrowed throughout preparation and mapping publication.
        unsafe {
            map_source(
                self.as_handle_ref().erase(),
                self.byte_size(),
                None,
                parent,
                address,
                options,
            )
        }
    }
}

impl FileProtection {
    /// Maps protected file bytes privately. Clean pages can be reclaimed and
    /// faulted back; modified COW pages remain private to this process.
    ///
    /// The File needs READ, and this guard must belong to that same file.
    /// `Eager` reserves all pages in the calling process and prevents pressure
    /// eviction. Filesystem providers use it to avoid paging into themselves.
    /// The kernel
    /// retains protection independently until unmap or owner-process teardown.
    /// Creating the mapping can report allocation or quota errors. A later
    /// hardware fault that cannot be refilled after bounded reclaim retries
    /// terminates the process; it cannot return an error from a memory access.
    ///
    /// # Safety
    /// `parent` must belong to the calling process. The caller owns the unused
    /// destination range and must not independently unmap, remap, protect or
    /// expose aliases for the returned mapping's lifetime.
    pub unsafe fn map_private_at(
        &self,
        file: &File,
        parent: HandleRef<'_, VmarObject>,
        address: u64,
        options: PrivateMappingOptions,
    ) -> Result<PrivateMapping> {
        // SAFETY: the caller owns the range; File, token and VMAR stay borrowed.
        unsafe {
            map_source(
                file.as_handle_ref().erase(),
                self.byte_size(),
                Some(self.as_handle_ref()),
                parent,
                address,
                options,
            )
        }
    }
}

unsafe fn map_source(
    source: HandleRef<'_, AnyObject>,
    byte_size: u64,
    protection: Option<HandleRef<'_, FileProtectionObject>>,
    parent: HandleRef<'_, VmarObject>,
    address: u64,
    options: PrivateMappingOptions,
) -> Result<PrivateMapping> {
    let data_end = options
        .data_offset
        .checked_add(options.source_length)
        .ok_or(Error::OffsetOverflow)?;
    if address == 0
        || !address.is_multiple_of(PAGE_SIZE)
        || options.size == 0
        || !options.size.is_multiple_of(PAGE_SIZE)
        || !options.source_offset.is_multiple_of(PAGE_SIZE)
        || options.data_offset >= PAGE_SIZE
        || data_end > options.size
        || (options.source_length != 0
            && options
                .source_offset
                .checked_add(data_end)
                .ok_or(Error::OffsetOverflow)?
                > byte_size)
        || address.checked_add(options.size).is_none()
    {
        return Err(Error::InvalidMemoryRange);
    }
    let base = usize::try_from(address).map_err(|_| Error::InvalidMemoryRange)?;
    let size = usize::try_from(options.size).map_err(|_| Error::InvalidMemoryRange)?;
    if size > isize::MAX as usize {
        return Err(Error::InvalidMemoryRange);
    }
    // SAFETY: the caller supplies an unused current-process range.
    let result = unsafe {
        hyper_sys::vmar_allocate(
            parent.raw().get(),
            address,
            options.size,
            hyper_abi::HYPER_NATIVE_VMAR_ALLOCATE_EXACT,
        )
    };
    Status::from_raw(result.status).into_result()?;
    // SAFETY: vmar_allocate's successful result transfers a VMAR handle,
    // so no fallible kind query is needed after reserving the child region.
    // Adoption still rejects zero and aliases of the live input handles.
    let region = unsafe {
        crate::handle::adopt_produced_handle_excluding::<VmarObject>(
            result.value0,
            &[parent.raw(), source.raw()],
        )?
    };
    let mut mapping = PrivateMapping {
        region: Some(region),
        address: base,
        size,
        writable: options.writable,
        mapped: false,
    };
    let permissions = hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_READ
        | if options.writable {
            hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_WRITE
        } else {
            0
        };
    let record = hyper_abi::HyperNativePrivateMapping {
        source_offset: options.source_offset,
        source_length: options.source_length,
        address,
        size: options.size,
        data_offset: options.data_offset,
        permissions: permissions as u32,
        mode: match options.mode {
            PrivateMappingMode::CopyOnWrite => {
                hyper_abi::HYPER_NATIVE_PRIVATE_MAPPING_COPY_ON_WRITE as u32
            }
            PrivateMappingMode::Eager => hyper_abi::HYPER_NATIVE_PRIVATE_MAPPING_EAGER as u32,
        },
    };
    let Some(region) = mapping.region.as_ref() else {
        return Err(Error::InvalidResponse);
    };
    // SAFETY: the private region, immutable source, and request are live.
    Status::from_raw(unsafe {
        match protection {
            Some(protection) => hyper_sys::vmar_map_file(
                region.as_handle_ref().raw().get(),
                source.raw().get(),
                protection.raw().get(),
                &record,
                core::mem::size_of_val(&record),
            ),
            None => hyper_sys::vmar_map_private(
                region.as_handle_ref().raw().get(),
                source.raw().get(),
                &record,
                core::mem::size_of_val(&record),
            ),
        }
    })
    .into_result()?;
    mapping.mapped = true;
    Ok(mapping)
}

impl PrivateMapping {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: construction grants exclusive view ownership in this process;
        // no other mapping can write its private bytes. Self retains the VMAR.
        unsafe { core::slice::from_raw_parts(self.address as *const u8, self.size) }
    }

    pub fn as_mut_slice(&mut self) -> Result<&mut [u8]> {
        if !self.writable {
            return Err(Error::InvalidMemoryRange);
        }
        // SAFETY: mutable Self borrow excludes all slices from this view and
        // construction established writable, uniquely controlled virtual bytes.
        Ok(unsafe { core::slice::from_raw_parts_mut(self.address as *mut u8, self.size) })
    }
}

/// A failed explicit close which retains cleanup authority for retry.
///
/// Closing may have unmapped the bytes before region destruction failed. This
/// owner therefore exposes only the error and another close attempt, never
/// slices or a conversion back into an accessible mapping.
#[must_use = "retry close or explicitly accept best-effort cleanup on drop"]
pub struct PrivateMappingCloseError {
    error: Error,
    mapping: PrivateMapping,
}

impl PrivateMappingCloseError {
    #[must_use]
    pub const fn error(&self) -> Error {
        self.error
    }

    pub fn retry(self) -> core::result::Result<(), Self> {
        self.mapping.try_close()
    }
}

impl core::fmt::Debug for PrivateMappingCloseError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PrivateMappingCloseError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl PrivateMapping {
    /// Unmaps the bytes and destroys the child region, retaining cleanup
    /// authority in the error if either operation is rejected.
    pub fn try_close(mut self) -> core::result::Result<(), PrivateMappingCloseError> {
        match self.close_inner() {
            Ok(()) => Ok(()),
            Err(error) => Err(PrivateMappingCloseError {
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
            // SAFETY: close owns Self, so no borrowed slices survive. Success
            // acknowledges translations before releasing physical owners.
            Status::from_raw(unsafe {
                hyper_sys::vmar_unmap(raw, self.address as u64, self.size as u64)
            })
            .into_result()?;
            // A later retry must destroy only the now-empty child region.
            self.mapped = false;
        }
        // SAFETY: this owned child is empty. Rejection preserves its handle;
        // success consumes the handle, so disarm its Rust owner exactly once.
        Status::from_raw(unsafe { hyper_sys::vmar_destroy(raw) }).into_result()?;
        if let Some(region) = self.region.take() {
            let _ = region.into_raw();
        }
        Ok(())
    }
}

impl Drop for PrivateMapping {
    fn drop(&mut self) {
        // Busy may reflect a blocking operation on another thread. Retrying
        // indefinitely from Drop could deadlock that thread's completion.
        let _ = self.close_inner();
    }
}
