// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Safe ownership and bounded transfer operations for Native VMOs.

use crate::handle::{AnyObject, HandleRef, OwnedHandle, Rights, VmoObject};

mod private;
mod residency;
pub use residency::{lock_current_memory, lock_memory, unlock_current_memory, unlock_memory};
mod shared;
use crate::{Error, Result, Status};
pub use private::{
    PrivateMapping, PrivateMappingCloseError, PrivateMappingMode, PrivateMappingOptions,
};
pub use shared::SharedReadMapping;

const WRITABLE_RIGHTS: Rights = Rights::DUPLICATE
    .union(Rights::TRANSFER)
    .union(Rights::INSPECT)
    .union(Rights::READ)
    .union(Rights::WRITE)
    .union(Rights::MAP);
const _: () = assert!(hyper_abi::HYPER_NATIVE_VMO_MAX_TRANSFER_BYTES <= usize::MAX as u64);
pub const PAGE_SIZE: u64 = hyper_abi::HYPER_NATIVE_PAGE_SIZE;
pub const MAX_TRANSFER_BYTES: usize = hyper_abi::HYPER_NATIVE_VMO_MAX_TRANSFER_BYTES as usize;

/// Exclusive process-local owner of one writable virtual memory object.
pub struct WritableVmo {
    handle: OwnedHandle<VmoObject>,
    size: u64,
}

impl WritableVmo {
    /// Eager DMA backing. Size must be a power of two from one page to 128 MiB.
    /// The entire physical extent remains allocated until all derived page
    /// owners retire; ordinary applications should use sparse `create`.
    pub fn create_contiguous(size: u64) -> Result<Self> {
        if size < PAGE_SIZE
            || !size.is_power_of_two()
            || size > hyper_abi::HYPER_NATIVE_VMO_MAX_CONTIGUOUS_SIZE_BYTES
        {
            return Err(Error::InvalidMemoryRange);
        }
        // SAFETY: successful creation publishes one unique output owner.
        let result = unsafe { hyper_sys::vmo_create_contiguous(size) };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: this no-input creation call transfers its nonzero result.
        let owner = unsafe {
            crate::handle::adopt_produced_handle_excluding::<AnyObject>(result.value0, &[])?
        };
        let info = owner.info()?;
        if info.rights != WRITABLE_RIGHTS {
            return Err(Error::InvalidResponse);
        }
        let handle = owner
            .downcast::<VmoObject>()
            .map_err(|failure| failure.error())?;
        Ok(Self { handle, size })
    }

    /// Creates a page-aligned sparse VMO.
    pub fn create(size: u64) -> Result<Self> {
        if size == 0 || !size.is_multiple_of(PAGE_SIZE) {
            return Err(Error::InvalidMemoryRange);
        }
        // SAFETY: successful creation publishes one unique output owner.
        let result = unsafe { hyper_sys::vmo_create(size) };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: this no-input creation call transfers its nonzero result.
        let owner = unsafe {
            crate::handle::adopt_produced_handle_excluding::<AnyObject>(result.value0, &[])?
        };
        let info = owner.info()?;
        if info.rights != WRITABLE_RIGHTS {
            return Err(Error::InvalidResponse);
        }
        let handle = owner
            .downcast::<VmoObject>()
            .map_err(|failure| failure.error())?;
        Ok(Self { handle, size })
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, VmoObject> {
        self.handle.as_handle_ref()
    }

    /// Copies one complete byte range into the VMO using ABI-bounded calls.
    pub fn write_all_at(&self, offset: u64, bytes: &[u8]) -> Result<()> {
        self.validate_range(offset, bytes.len())?;
        let mut completed = 0usize;
        while completed < bytes.len() {
            let end = completed
                .saturating_add(MAX_TRANSFER_BYTES)
                .min(bytes.len());
            let chunk = bytes.get(completed..end).ok_or(Error::InvalidResponse)?;
            let chunk_offset = offset
                .checked_add(u64::try_from(completed).map_err(|_| Error::OffsetOverflow)?)
                .ok_or(Error::OffsetOverflow)?;
            // SAFETY: the handle is borrowed and `chunk` remains readable for
            // the complete non-retaining syscall.
            Status::from_raw(unsafe {
                hyper_sys::vmo_write(
                    self.handle.as_handle_ref().raw().get(),
                    chunk_offset,
                    chunk.as_ptr(),
                    chunk.len(),
                )
            })
            .into_result()?;
            completed = end;
        }
        Ok(())
    }

    /// Reads one complete byte range from the VMO using ABI-bounded calls.
    pub fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        self.validate_range(offset, bytes.len())?;
        let mut completed = 0usize;
        while completed < bytes.len() {
            let end = completed
                .saturating_add(MAX_TRANSFER_BYTES)
                .min(bytes.len());
            let chunk = bytes
                .get_mut(completed..end)
                .ok_or(Error::InvalidResponse)?;
            let chunk_offset = offset
                .checked_add(u64::try_from(completed).map_err(|_| Error::OffsetOverflow)?)
                .ok_or(Error::OffsetOverflow)?;
            // SAFETY: the handle is borrowed and `chunk` remains writable for
            // the complete non-retaining syscall.
            Status::from_raw(unsafe {
                hyper_sys::vmo_read(
                    self.handle.as_handle_ref().raw().get(),
                    chunk_offset,
                    chunk.as_mut_ptr(),
                    chunk.len(),
                )
            })
            .into_result()?;
            completed = end;
        }
        Ok(())
    }

    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<VmoObject> {
        self.handle
    }

    fn validate_range(&self, offset: u64, length: usize) -> Result<()> {
        let length = u64::try_from(length).map_err(|_| Error::OffsetOverflow)?;
        let end = offset.checked_add(length).ok_or(Error::OffsetOverflow)?;
        if end > self.size {
            Err(Error::InvalidMemoryRange)
        } else {
            Ok(())
        }
    }
}

/// Immutable bytes captured from one VMO.
/// A private mapping may be writable without granting write access to this source.
pub struct SnapshotVmo {
    handle: OwnedHandle<VmoObject>,
    byte_size: u64,
}

impl SnapshotVmo {
    pub fn from_vmo(source: HandleRef<'_, VmoObject>) -> Result<Self> {
        // SAFETY: source is borrowed; successful creation transfers one owner.
        let result = unsafe { hyper_sys::vmo_create_snapshot(source.raw().get()) };
        Self::adopt(result, source.raw())
    }

    fn adopt(result: hyper_sys::CallResult, source: core::num::NonZeroU64) -> Result<Self> {
        Status::from_raw(result.status).into_result()?;
        // SAFETY: success transfers one handle, excluding the still-live input.
        let owner = unsafe {
            crate::handle::adopt_produced_handle_excluding::<AnyObject>(result.value0, &[source])?
        };
        let expected = Rights::DUPLICATE
            .union(Rights::TRANSFER)
            .union(Rights::INSPECT)
            .union(Rights::READ)
            .union(Rights::MAP);
        if owner.info()?.rights != expected {
            return Err(Error::InvalidResponse);
        }
        let handle = owner
            .downcast::<VmoObject>()
            .map_err(|failure| failure.error())?;
        Ok(Self {
            handle,
            byte_size: result.value1,
        })
    }

    #[must_use]
    pub const fn byte_size(&self) -> u64 {
        self.byte_size
    }

    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, VmoObject> {
        self.handle.as_handle_ref()
    }

    pub fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        let length = u64::try_from(bytes.len()).map_err(|_| Error::OffsetOverflow)?;
        if offset.checked_add(length).ok_or(Error::OffsetOverflow)? > self.byte_size {
            return Err(Error::InvalidMemoryRange);
        }
        let mut completed = 0;
        while completed < bytes.len() {
            let end = completed
                .saturating_add(MAX_TRANSFER_BYTES)
                .min(bytes.len());
            let chunk = &mut bytes[completed..end];
            // SAFETY: the destination is uniquely borrowed for the syscall and
            // the source handle/range remains owned by this immutable snapshot.
            Status::from_raw(unsafe {
                hyper_sys::vmo_read(
                    self.handle.as_handle_ref().raw().get(),
                    offset + completed as u64,
                    chunk.as_mut_ptr(),
                    chunk.len(),
                )
            })
            .into_result()?;
            completed = end;
        }
        Ok(())
    }
}
