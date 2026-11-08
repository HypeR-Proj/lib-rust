// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Explicit VMO-relative shared waits, independent of address-space mappings.

use super::WritableVmo;
use crate::handle::{HandleRef, VmoObject};
use crate::{Error, Result, Status};

impl HandleRef<'_, VmoObject> {
    /// Sleeps only while the shared u32 equals `expected`, using an absolute
    /// monotonic deadline. Mismatch returns success immediately. Success is a
    /// hint: reload the condition and use application-defined atomic ordering.
    ///
    /// Requires READ|WRITE on an ordinary writable RAM VMO, but no MAP right.
    /// Offset is four-byte aligned and must fit inside the VMO. Waits through
    /// different processes and virtual addresses share the same object+offset
    /// identity. Closing a handle or unmapping does not cancel an admitted wait.
    /// Snapshots, ordinary VMO byte access and hardware leases cannot overlap
    /// its writable admission. Existing hardware ownership reports BUSY.
    ///
    /// # Safety
    /// Every concurrent access to this word, through every alias in every
    /// process, must use aligned `AtomicU32` operations of the same width for
    /// the entire call. Non-atomic and overlapping mixed-width accesses violate
    /// this contract. The kernel retains backing independently of mappings.
    pub unsafe fn wait_u32(self, offset: u64, expected: u32, deadline: u64) -> Result<()> {
        validate_offset(offset)?;
        // SAFETY: the caller establishes cross-alias atomic access and this
        // borrowed handle remains live through the non-retaining invocation.
        Status::from_raw(unsafe { raw_ops::wait(self.raw().get(), offset, expected, deadline) })
            .into_result()
    }

    /// Wakes up to `count` shared waiters and returns the actual wake count.
    /// Requires WRITE only; it neither reads nor populates the word. Zero count
    /// is a validated no-op. Bounds, variant and alignment still apply; a wake
    /// can return zero during hardware ownership because it acquires no lease.
    pub fn wake_u32(self, offset: u64, count: u32) -> Result<u32> {
        validate_offset(offset)?;
        decode_wake(raw_ops::wake(self.raw().get(), offset, count), count)
    }
}

impl WritableVmo {
    /// See [`HandleRef::wait_u32`] for shared identity, rights and wake semantics.
    ///
    /// # Safety
    /// All concurrent aliases of the selected word must use matching aligned
    /// `AtomicU32` accesses for this call's lifetime, as for [`HandleRef::wait_u32`].
    pub unsafe fn wait_u32(&self, offset: u64, expected: u32, deadline: u64) -> Result<()> {
        self.validate_range(offset, 4)?;
        // SAFETY: the caller supplies the shared atomic-aliasing contract.
        unsafe { self.as_handle_ref().wait_u32(offset, expected, deadline) }
    }

    /// Wakes shared waiters without reading the VMO. See [`HandleRef::wake_u32`].
    pub fn wake_u32(&self, offset: u64, count: u32) -> Result<u32> {
        self.validate_range(offset, 4)?;
        self.as_handle_ref().wake_u32(offset, count)
    }
}

fn validate_offset(offset: u64) -> Result<()> {
    if !offset.is_multiple_of(4) || offset.checked_add(4).is_none() {
        Err(Error::InvalidMemoryRange)
    } else {
        Ok(())
    }
}

fn decode_wake(result: hyper_sys::CallResult, maximum: u32) -> Result<u32> {
    Status::from_raw(result.status).into_result()?;
    if result.value1 != 0 || result.value0 > u64::from(maximum) {
        return Err(Error::InvalidResponse);
    }
    u32::try_from(result.value0).map_err(|_| Error::InvalidResponse)
}

#[cfg(not(test))]
mod raw_ops {
    pub(super) unsafe fn wait(
        handle: u64,
        offset: u64,
        expected: u32,
        deadline: u64,
    ) -> hyper_abi::HyperNativeStatus {
        // SAFETY: the caller upholds the raw shared atomic-access contract.
        unsafe { hyper_sys::vmo_wait_u32(handle, offset, expected, deadline, 0) }
    }
    pub(super) fn wake(handle: u64, offset: u64, count: u32) -> hyper_sys::CallResult {
        // SAFETY: the typed borrowed handle remains live, and no pointer is read.
        unsafe { hyper_sys::vmo_wake_u32(handle, offset, count, 0) }
    }
}

#[cfg(test)]
#[path = "../../tests/memory/atomic_wait.rs"]
mod tests;
#[cfg(test)]
use tests::raw_ops;
