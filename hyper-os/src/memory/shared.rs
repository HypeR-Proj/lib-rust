// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Copy-only access to memory that another execution context can modify.

use super::WritableVmo;
use crate::handle::{HandleRef, OwnedHandle, VmarObject};
use crate::{Error, Result, Status};
use core::sync::atomic::{AtomicU8, Ordering};

/// Owns a read-only view without exposing ordinary references to shared bytes.
///
/// Atomic byte loads permit a remote writer to race a copy safely. They do not
/// make a multi-byte record consistent: callers still validate protocol replies
/// and metadata checksums before trusting the resulting private buffer.
pub struct SharedReadMapping {
    region: Option<OwnedHandle<VmarObject>>,
    address: usize,
    size: usize,
    mapped: bool,
}

impl WritableVmo {
    /// Reserve an unused child VMAR and map the whole VMO read-only.
    /// Backing remains pinned by the mapping even if the source handle closes.
    ///
    /// # Safety
    /// `root` must belong to the calling process. The caller must not unmap,
    /// protect or replace the reserved child through another VMAR capability
    /// for the returned owner's lifetime.
    pub unsafe fn map_shared_read(
        &self,
        root: HandleRef<'_, VmarObject>,
    ) -> Result<SharedReadMapping> {
        let size = usize::try_from(self.size()).map_err(|_| Error::InvalidMemoryRange)?;
        if size > isize::MAX as usize {
            return Err(Error::InvalidMemoryRange);
        }
        // SAFETY: root is current-process authority by the caller's contract;
        // zero hint reserves a free interval rather than replacing a mapping.
        let result = unsafe { hyper_sys::vmar_allocate(root.raw().get(), 0, self.size(), 0) };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: success transfers one fresh child region, excluding inputs.
        let region = unsafe {
            crate::handle::adopt_produced_handle_excluding::<VmarObject>(
                result.value0,
                &[root.raw(), self.as_handle_ref().raw()],
            )?
        };
        let mut mapping = SharedReadMapping {
            region: Some(region),
            address: 0,
            size,
            mapped: false,
        };
        let address = usize::try_from(result.value1).map_err(|_| Error::InvalidResponse)?;
        if address == 0 || address.checked_add(size).is_none() {
            return Err(Error::InvalidResponse);
        }
        mapping.address = address;
        let region = mapping.region.as_ref().ok_or(Error::InvalidResponse)?;
        // SAFETY: the private child and source cover the exact whole-page range.
        Status::from_raw(unsafe {
            hyper_sys::vmar_map(
                region.as_handle_ref().raw().get(),
                self.as_handle_ref().raw().get(),
                0,
                address as u64,
                self.size(),
                hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_READ,
            )
        })
        .into_result()?;
        mapping.mapped = true;
        Ok(mapping)
    }
}

impl SharedReadMapping {
    /// Copy a bounded range into private memory. No reference to shared bytes
    /// survives a load, including when a faulty peer changes them concurrently.
    pub fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<()> {
        let offset = usize::try_from(offset).map_err(|_| Error::InvalidMemoryRange)?;
        if offset
            .checked_add(output.len())
            .is_none_or(|end| end > self.size)
        {
            return Err(Error::InvalidMemoryRange);
        }
        for (index, byte) in output.iter_mut().enumerate() {
            let address = self.address + offset + index;
            // SAFETY: construction and the private region owner keep each byte
            // mapped. AtomicU8 has byte alignment and no invalid bit patterns;
            // no ordinary shared reference is created for remote-writable data.
            *byte = unsafe { &*core::ptr::with_exposed_provenance::<AtomicU8>(address) }
                .load(Ordering::Relaxed);
        }
        Ok(())
    }
}

impl Drop for SharedReadMapping {
    fn drop(&mut self) {
        let Some(region) = self.region.take() else {
            return;
        };
        let raw = region.as_handle_ref().raw().get();
        if self.mapped {
            // SAFETY: no byte references escape this owner. Unmap completes
            // translation retirement before releasing the mapping's backing.
            if Status::from_raw(unsafe {
                hyper_sys::vmar_unmap(raw, self.address as u64, self.size as u64)
            })
            .into_result()
            .is_err()
            {
                // A failed unmap remains owned by the process until teardown.
                return;
            }
        }
        // SAFETY: this private region is empty after unmap or failed creation.
        if Status::from_raw(unsafe { hyper_sys::vmar_destroy(raw) })
            .into_result()
            .is_ok()
        {
            // Successful VMAR destruction consumes its handle.
            let _ = region.into_raw();
        }
    }
}

#[cfg(test)]
#[path = "../../tests/memory/shared.rs"]
mod tests;
