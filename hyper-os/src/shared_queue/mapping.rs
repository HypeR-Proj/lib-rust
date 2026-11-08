// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Fixed-width atomic access to a queue's privately owned mapping.

use crate::handle::{HandleRef, OwnedHandle, VmarObject, VmoObject};
use crate::{Error, Result, Status};
use core::sync::atomic::{AtomicU64, Ordering};

pub(super) struct AtomicWords {
    region: Option<OwnedHandle<VmarObject>>,
    address: usize,
    size: usize,
    writable: bool,
    mapped: bool,
}

impl AtomicWords {
    /// Maps locally validated geometry, without consulting shared metadata.
    ///
    /// # Safety
    /// `root` must belong to the calling process. No other authority may unmap,
    /// protect or replace the private child for this owner's lifetime. The VMO
    /// must have been populated before publishing either endpoint. Concurrent
    /// accesses to these bytes, through every alias, must use aligned atomic
    /// u64 words at the same offsets, never ordinary or mixed-width accesses.
    pub(super) unsafe fn map(
        root: HandleRef<'_, VmarObject>,
        vmo: HandleRef<'_, VmoObject>,
        size: usize,
        writable: bool,
    ) -> Result<Self> {
        let size_u64 = u64::try_from(size).map_err(|_| Error::InvalidMemoryRange)?;
        if size == 0
            || size > isize::MAX as usize
            || !size_u64.is_multiple_of(crate::memory::PAGE_SIZE)
        {
            return Err(Error::InvalidMemoryRange);
        }
        // SAFETY: the caller supplies a current-process root; a zero hint
        // reserves a new child instead of replacing an existing mapping.
        let result = unsafe { hyper_sys::vmar_allocate(root.raw().get(), 0, size_u64, 0) };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: allocation transfers a fresh region, never either input.
        let region = unsafe {
            crate::handle::adopt_produced_handle_excluding::<VmarObject>(
                result.value0,
                &[root.raw(), vmo.raw()],
            )?
        };
        let mut mapping = Self {
            region: Some(region),
            address: 0,
            size,
            writable,
            mapped: false,
        };
        let address = usize::try_from(result.value1).map_err(|_| Error::InvalidResponse)?;
        if address == 0
            || !result.value1.is_multiple_of(crate::memory::PAGE_SIZE)
            || address.checked_add(size).is_none()
        {
            return Err(Error::InvalidResponse);
        }
        mapping.address = address;
        let region = mapping.region.as_ref().ok_or(Error::InvalidResponse)?;
        let permissions = hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_READ
            | if writable {
                hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_WRITE
            } else {
                0
            };
        // SAFETY: the private child covers the complete range. Native vmar_map
        // accepts RAM-backed VMOs, not MMIO, and installs coherent Normal memory;
        // it also checks source size and the requested read/write authority.
        Status::from_raw(unsafe {
            hyper_sys::vmar_map(
                region.as_handle_ref().raw().get(),
                vmo.raw().get(),
                0,
                address as u64,
                size_u64,
                permissions,
            )
        })
        .into_result()?;
        mapping.mapped = true;
        Ok(mapping)
    }

    pub(super) fn load(&self, index: usize, ordering: Ordering) -> Result<u64> {
        if !matches!(
            ordering,
            Ordering::Relaxed | Ordering::Acquire | Ordering::SeqCst
        ) {
            return Err(Error::Status(Status::INVALID_ARGUMENT));
        }
        let address = self.word_address(index)?;
        // SAFETY: checked geometry and the retained child keep this aligned
        // word mapped. Construction requires consistent-width atomic access
        // through every alias; no reference to shared payload escapes.
        Ok(unsafe { &*core::ptr::with_exposed_provenance::<AtomicU64>(address) }.load(ordering))
    }

    pub(super) fn store(&self, index: usize, value: u64, ordering: Ordering) -> Result<()> {
        if !self.writable {
            return Err(Error::Status(Status::ACCESS_DENIED));
        }
        if !matches!(
            ordering,
            Ordering::Relaxed | Ordering::Release | Ordering::SeqCst
        ) {
            return Err(Error::Status(Status::INVALID_ARGUMENT));
        }
        let address = self.word_address(index)?;
        // SAFETY: the same bounds and aliasing proof as load applies; this
        // instance additionally owns a writable mapping of the word.
        unsafe { &*core::ptr::with_exposed_provenance::<AtomicU64>(address) }
            .store(value, ordering);
        Ok(())
    }

    fn word_address(&self, index: usize) -> Result<usize> {
        if index >= self.size / core::mem::size_of::<AtomicU64>() {
            return Err(Error::InvalidMemoryRange);
        }
        // Both operations fit because map checked address + size, and index
        // names a complete word strictly inside that range.
        Ok(self.address + index * core::mem::size_of::<AtomicU64>())
    }
}

impl Drop for AtomicWords {
    fn drop(&mut self) {
        let Some(region) = self.region.take() else {
            return;
        };
        let raw = region.as_handle_ref().raw().get();
        if self.mapped {
            // SAFETY: no references escape this owner. Successful unmap retires
            // translations before releasing the mapping's retained backing.
            if Status::from_raw(unsafe {
                hyper_sys::vmar_unmap(raw, self.address as u64, self.size as u64)
            })
            .into_result()
            .is_err()
            {
                // The process retains a failed cleanup until teardown. Closing
                // this capability cannot free backing beneath a live mapping.
                return;
            }
        }
        // SAFETY: the private region is empty after unmap or failed creation.
        if Status::from_raw(unsafe { hyper_sys::vmar_destroy(raw) })
            .into_result()
            .is_ok()
        {
            // Destruction consumes the capability on success.
            let _ = region.into_raw();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_access_checks_bounds_permissions_and_ordering() -> Result<()> {
        let backing = [AtomicU64::new(5), AtomicU64::new(9)];
        // Host backing remains live throughout the owner, without a VMAR.
        let mut mapping = core::mem::ManuallyDrop::new(AtomicWords {
            region: None,
            address: backing.as_ptr().expose_provenance(),
            size: core::mem::size_of_val(&backing),
            writable: true,
            mapped: false,
        });
        assert_eq!(mapping.load(0, Ordering::Acquire)?, 5);
        mapping.store(1, 17, Ordering::Release)?;
        assert_eq!(backing[1].load(Ordering::Acquire), 17);
        assert_eq!(
            mapping.load(2, Ordering::Relaxed),
            Err(Error::InvalidMemoryRange)
        );
        assert_eq!(
            mapping.store(usize::MAX, 1, Ordering::SeqCst),
            Err(Error::InvalidMemoryRange)
        );
        assert_eq!(
            mapping.load(0, Ordering::Release),
            Err(Error::Status(Status::INVALID_ARGUMENT))
        );
        assert_eq!(
            mapping.store(0, 1, Ordering::Acquire),
            Err(Error::Status(Status::INVALID_ARGUMENT))
        );
        mapping.writable = false;
        assert_eq!(
            mapping.store(0, 1, Ordering::SeqCst),
            Err(Error::Status(Status::ACCESS_DENIED))
        );
        assert_eq!(mapping.load(0, Ordering::SeqCst)?, 5);
        Ok(())
    }
}
