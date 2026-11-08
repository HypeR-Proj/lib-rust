// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Aligned u32 atomics in a process-owned shared VMO mapping.

use crate::handle::{HandleRef, OwnedHandle, VmarObject, VmoObject};
use crate::{Error, Result, Status};
use core::sync::atomic::{AtomicU32, Ordering};

/// Owned shared atomic words without exposed ordinary Rust references.
/// Drop unmaps the private child; failed cleanup remains owned by the process
/// until teardown. All participating aliases must obey the constructor contract.
pub struct SharedAtomicU32Mapping {
    region: Option<OwnedHandle<VmarObject>>,
    address: usize,
    size: usize,
    mapped: bool,
}

impl SharedAtomicU32Mapping {
    /// Reserves a private child VMAR and maps the first `size` bytes read/write.
    /// Size must be nonzero and page aligned. Indexes in load/store count u32
    /// words, not bytes. The mapping retains backing if the input handle closes.
    ///
    /// # Safety
    /// `root` must belong to the calling process. No other authority may unmap,
    /// protect or replace the private child for this owner's lifetime. The VMO
    /// must be ordinary writable RAM with READ|WRITE|MAP authority. Concurrent
    /// accesses to these bytes, through every alias, must use aligned atomic
    /// u32 words at the same offsets, never ordinary or mixed-width accesses.
    pub unsafe fn map(
        root: HandleRef<'_, VmarObject>,
        vmo: HandleRef<'_, VmoObject>,
        size: u64,
    ) -> Result<Self> {
        let size_u64 = size;
        let size = usize::try_from(size).map_err(|_| Error::InvalidMemoryRange)?;
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
            | hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_WRITE;
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

    /// Loads one word with `Relaxed`, `Acquire` or `SeqCst` ordering.
    pub fn load(&self, index: usize, ordering: Ordering) -> Result<u32> {
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
        Ok(unsafe { &*core::ptr::with_exposed_provenance::<AtomicU32>(address) }.load(ordering))
    }

    /// Stores one word with `Relaxed`, `Release` or `SeqCst` ordering.
    pub fn store(&self, index: usize, value: u32, ordering: Ordering) -> Result<()> {
        if !matches!(
            ordering,
            Ordering::Relaxed | Ordering::Release | Ordering::SeqCst
        ) {
            return Err(Error::Status(Status::INVALID_ARGUMENT));
        }
        let address = self.word_address(index)?;
        // SAFETY: the same bounds and aliasing proof as load applies; this
        // instance additionally owns a writable mapping of the word.
        unsafe { &*core::ptr::with_exposed_provenance::<AtomicU32>(address) }
            .store(value, ordering);
        Ok(())
    }

    /// Atomically replaces a word only if it equals `current`.
    /// The inner result is the previous value: `Ok` on replacement, `Err` on
    /// mismatch. Ordering follows `AtomicU32::compare_exchange`; failure permits
    /// only `Relaxed`, `Acquire` or `SeqCst`. Invalid orders return
    /// `INVALID_ARGUMENT` instead of panicking.
    pub fn compare_exchange(
        &self,
        index: usize,
        current: u32,
        new: u32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<core::result::Result<u32, u32>> {
        if !matches!(
            success,
            Ordering::Relaxed
                | Ordering::Acquire
                | Ordering::Release
                | Ordering::AcqRel
                | Ordering::SeqCst
        ) || !matches!(
            failure,
            Ordering::Relaxed | Ordering::Acquire | Ordering::SeqCst
        ) {
            return Err(Error::Status(Status::INVALID_ARGUMENT));
        }
        let address = self.word_address(index)?;
        // SAFETY: the constructor's atomic-width and mapping-lifetime contract
        // retains this aligned writable word; no reference escapes the call.
        Ok(
            unsafe { &*core::ptr::with_exposed_provenance::<AtomicU32>(address) }
                .compare_exchange(current, new, success, failure),
        )
    }

    /// Observes the mapping base; this does not grant a right to dereference it.
    #[must_use]
    pub const fn base_address(&self) -> usize {
        self.address
    }

    fn word_address(&self, index: usize) -> Result<usize> {
        if index >= self.size / core::mem::size_of::<AtomicU32>() {
            return Err(Error::InvalidMemoryRange);
        }
        // Both operations fit because map checked address + size, and index
        // names a complete word strictly inside that range.
        Ok(self.address + index * core::mem::size_of::<AtomicU32>())
    }
}

impl Drop for SharedAtomicU32Mapping {
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
    fn aligned_word_access_rejects_bad_index_and_memory_order() -> Result<()> {
        let backing = [AtomicU32::new(7), AtomicU32::new(9)];
        // No kernel mapping exists: host backing outlives this synthetic owner.
        let mapping = core::mem::ManuallyDrop::new(SharedAtomicU32Mapping {
            region: None,
            address: backing.as_ptr().expose_provenance(),
            size: core::mem::size_of_val(&backing),
            mapped: false,
        });
        assert_eq!(mapping.base_address(), backing.as_ptr().addr());
        assert_eq!(mapping.load(1, Ordering::Acquire)?, 9);
        mapping.store(0, u32::MAX, Ordering::Release)?;
        assert_eq!(backing[0].load(Ordering::Acquire), u32::MAX);
        assert_eq!(
            mapping.load(2, Ordering::Relaxed),
            Err(Error::InvalidMemoryRange)
        );
        assert_eq!(
            mapping.store(usize::MAX, 0, Ordering::SeqCst),
            Err(Error::InvalidMemoryRange)
        );
        assert_eq!(
            mapping.load(0, Ordering::Release),
            Err(Error::Status(Status::INVALID_ARGUMENT))
        );
        assert_eq!(
            mapping.store(0, 0, Ordering::Acquire),
            Err(Error::Status(Status::INVALID_ARGUMENT))
        );
        assert_eq!(
            mapping.compare_exchange(1, 9, 11, Ordering::AcqRel, Ordering::Acquire)?,
            Ok(9)
        );
        assert_eq!(
            mapping.compare_exchange(1, 9, 13, Ordering::Release, Ordering::Relaxed)?,
            Err(11)
        );
        assert_eq!(
            mapping.compare_exchange(1, 11, 13, Ordering::Relaxed, Ordering::SeqCst)?,
            Ok(11)
        );
        for invalid in [Ordering::Release, Ordering::AcqRel] {
            assert_eq!(
                mapping.compare_exchange(1, 13, 0, Ordering::SeqCst, invalid),
                Err(Error::Status(Status::INVALID_ARGUMENT))
            );
        }
        assert_eq!(mapping.load(1, Ordering::Relaxed)?, 13);
        assert_eq!(
            mapping.compare_exchange(usize::MAX, 0, 1, Ordering::SeqCst, Ordering::SeqCst),
            Err(Error::InvalidMemoryRange)
        );
        Ok(())
    }
}
