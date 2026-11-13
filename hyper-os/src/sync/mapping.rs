// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Retained mappings for shared mutex control words, never ordinary payload refs.

use core::sync::atomic::AtomicU64;

use super::{SharedMutex, SyncDomain, native::NativeWord, protocol};
use crate::handle::{HandleRef, OwnedHandle, VmarObject, VmoObject};
use crate::{Error, Result, Status};

/// Private child mapping of aligned shared u64 control words. VMOs and the
/// domain are borrowed for its entire lifetime. Dropping it only removes this
/// local view; it never destroys/reinitializes a shared mutex instance.
pub struct SharedMutexRegion<'owner> {
    domain: &'owner SyncDomain,
    vmo: HandleRef<'owner, VmoObject>,
    vmo_offset: u64,
    region: Option<OwnedHandle<VmarObject>>,
    address: usize,
    size: usize,
    mapped: bool,
}

impl<'owner> SharedMutexRegion<'owner> {
    /// Maps a page-aligned range of ordinary RAM as mutex control words.
    /// The range must already have been bound through `SyncDomain::bind`.
    /// Individual word attribution and wait/wake authority are checked by
    /// `mutex`; mapping does not require administrative configure authority.
    ///
    /// # Safety
    /// `root` belongs to the calling process. No other authority may unmap,
    /// protect or replace the private child while it is retained here. Every
    /// alias accessing these bytes uses aligned u64 atomics exclusively. Control
    /// words follow this mutex protocol and start zero in fresh memory, or refer
    /// to an already initialized live instance in the same domain. External
    /// code must not reset/reuse an instance until all owners, recovery guards,
    /// waiters and potential users have reached externally coordinated quiescence.
    pub unsafe fn map(
        domain: &'owner SyncDomain,
        root: HandleRef<'_, VmarObject>,
        vmo: HandleRef<'owner, VmoObject>,
        vmo_offset: u64,
        size: u64,
    ) -> Result<Self> {
        let size_u64 = size;
        let size = usize::try_from(size).map_err(|_| Error::InvalidMemoryRange)?;
        if size == 0
            || size > isize::MAX as usize
            || !size_u64.is_multiple_of(crate::memory::PAGE_SIZE)
            || !vmo_offset.is_multiple_of(crate::memory::PAGE_SIZE)
            || vmo_offset.checked_add(size_u64).is_none()
        {
            return Err(Error::InvalidMemoryRange);
        }
        // SAFETY: the supplied current-process root creates a fresh child.
        let result = unsafe { hyper_sys::vmar_allocate(root.raw().get(), 0, size_u64, 0) };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: successful creation transfers one fresh VMAR owner.
        let region = unsafe {
            crate::handle::adopt_produced_handle_excluding::<VmarObject>(
                result.value0,
                &[root.raw(), vmo.raw(), domain.as_handle_ref().raw()],
            )?
        };
        let mut mapping = Self {
            domain,
            vmo,
            vmo_offset,
            region: Some(region),
            address: 0,
            size,
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
        // SAFETY: this fresh child retains the full read/write RAM mapping. The
        // caller's alias protocol permits AtomicU64 access, not mixed widths.
        Status::from_raw(unsafe {
            hyper_sys::vmar_map(
                region.as_handle_ref().raw().get(),
                vmo.raw().get(),
                vmo_offset,
                address as u64,
                size_u64,
                hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_READ
                    | hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_WRITE,
            )
        })
        .into_result()?;
        mapping.mapped = true;
        Ok(mapping)
    }

    /// Opens one initialized control word by u64 index, validating fixed backing
    /// attribution and wait/wake authority before enabling syscall-free locking.
    /// This creates no kernel object and never writes or initializes shared state.
    pub fn mutex(&self, index: usize) -> Result<SharedMutex<'_>> {
        if index >= self.size / core::mem::size_of::<AtomicU64>() {
            return Err(Error::InvalidMemoryRange);
        }
        let displacement = index * core::mem::size_of::<AtomicU64>();
        let backend = NativeWord {
            domain: self.domain,
            vmo: self.vmo,
            offset: self.vmo_offset + displacement as u64,
        };
        // Count zero validates the exact namespace and authority without waking.
        super::native::validate_word(&backend)?;
        // SAFETY: map's lifetime and alias contract retain this aligned, complete
        // AtomicU64. The reference stays private and cannot outlive this mapping.
        let word = unsafe {
            &*core::ptr::with_exposed_provenance::<AtomicU64>(self.address + displacement)
        };
        Ok(SharedMutex {
            core: protocol::Mutex { word, backend },
        })
    }
}

impl Drop for SharedMutexRegion<'_> {
    fn drop(&mut self) {
        let Some(region) = self.region.take() else {
            return;
        };
        let raw = region.as_handle_ref().raw().get();
        if self.mapped {
            // SAFETY: all mutex views and guards borrow this mapping and have
            // ended. Kernel unmap retires translation before releasing backing.
            if Status::from_raw(unsafe {
                hyper_sys::vmar_unmap(raw, self.address as u64, self.size as u64)
            })
            .into_result()
            .is_err()
            {
                // The process retains any failed cleanup until teardown.
                return;
            }
        }
        // SAFETY: the child is empty after successful unmap or failed map.
        if Status::from_raw(unsafe { hyper_sys::vmar_destroy(raw) })
            .into_result()
            .is_ok()
        {
            let _ = region.into_raw();
        }
    }
}
