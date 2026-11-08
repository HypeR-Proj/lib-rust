// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Read/execute mappings retain immutable backing independently of VMO handles.

use super::ExecutableVmo;
use crate::handle::{HandleRef, OwnedHandle, VmarObject};
use crate::{Error, Result, Status};

/// Owns one private child VMAR with read/execute permissions only.
/// Drop unmaps it; failed cleanup stays owned by the process until teardown.
pub struct ExecutableMapping {
    region: Option<OwnedHandle<VmarObject>>,
    address: usize,
    size: usize,
    mapped: bool,
}

impl ExecutableVmo {
    /// Maps the whole published image into a fresh private child VMAR.
    /// Publication has already synchronized instruction caches. The returned
    /// owner exposes an address, not a safe callable function pointer.
    ///
    /// # Safety
    /// `root` must belong to this process. No other VMAR authority may unmap,
    /// protect or replace the child while this owner lives. Any execution must
    /// end before dropping the mapping; callers must independently establish
    /// machine-code validity, calling convention and memory-access safety.
    pub unsafe fn map(&self, root: HandleRef<'_, VmarObject>) -> Result<ExecutableMapping> {
        let size = usize::try_from(self.byte_size()).map_err(|_| Error::InvalidMemoryRange)?;
        if size > isize::MAX as usize {
            return Err(Error::InvalidMemoryRange);
        }
        // SAFETY: current-process root and mapping lifetime are the caller's contract.
        let result = unsafe { hyper_sys::vmar_allocate(root.raw().get(), 0, self.byte_size(), 0) };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: allocation returns a fresh region distinct from both inputs.
        let region = unsafe {
            crate::handle::adopt_produced_handle_excluding::<VmarObject>(
                result.value0,
                &[root.raw(), self.as_handle_ref().raw()],
            )?
        };
        let mut mapping = ExecutableMapping {
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
        // SAFETY: the whole-page immutable source and private child cover this
        // exact range; the mapping never requests WRITE or exposes mutable data.
        Status::from_raw(unsafe {
            hyper_sys::vmar_map(
                region.as_handle_ref().raw().get(),
                self.as_handle_ref().raw().get(),
                0,
                result.value1,
                self.byte_size(),
                hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_READ
                    | hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_EXECUTE,
            )
        })
        .into_result()?;
        mapping.mapped = true;
        Ok(mapping)
    }
}
impl ExecutableMapping {
    /// The base address is an observation, not a safe function pointer.
    #[must_use]
    pub const fn base_address(&self) -> usize {
        self.address
    }
    #[must_use]
    pub const fn byte_size(&self) -> usize {
        self.size
    }
}
impl Drop for ExecutableMapping {
    fn drop(&mut self) {
        let Some(region) = self.region.take() else {
            return;
        };
        let raw = region.as_handle_ref().raw().get();
        if self.mapped {
            // SAFETY: the constructor contract excludes concurrent execution
            // during destruction. Successful unmap retires all translations.
            if Status::from_raw(unsafe {
                hyper_sys::vmar_unmap(raw, self.address as u64, self.size as u64)
            })
            .into_result()
            .is_err()
            {
                return;
            }
        }
        // SAFETY: this child is empty after unmap or a failed initial mapping.
        if Status::from_raw(unsafe { hyper_sys::vmar_destroy(raw) })
            .into_result()
            .is_ok()
        {
            let _ = region.into_raw();
        }
    }
}
