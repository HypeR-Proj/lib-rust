// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Explicit process memory residency; independent of DMA pinning and unmapping.
use super::PAGE_SIZE;
use crate::{
    Error, Result, Status,
    handle::{HandleRef, VmarObject},
};

/// Populate all current mappings covered by this VMAR and prevent reclamation.
/// Requires `LOCK_MEMORY`. Guard holes and future mappings are excluded. Repeating
/// the call is idempotent; quota is charged to the calling resource domain.
/// Shared clean file pages remain reusable through the common file cache.
pub fn lock_current_memory(vmar: HandleRef<'_, VmarObject>) -> Result<()> {
    set(
        vmar,
        0,
        0,
        hyper_abi::HYPER_NATIVE_VMAR_MEMORY_CURRENT,
        true,
    )
}

/// Release all current residency locks covered by this VMAR. Other mappings'
/// locks on the same backing remain in effect. Unmapping also releases locks.
pub fn unlock_current_memory(vmar: HandleRef<'_, VmarObject>) -> Result<()> {
    set(
        vmar,
        0,
        0,
        hyper_abi::HYPER_NATIVE_VMAR_MEMORY_CURRENT,
        false,
    )
}

/// Populate and lock a nonempty, page-aligned mapped interval. This does not
/// forbid unmap, protect, or private writes, and promises no fixed DMA address.
pub fn lock_memory(vmar: HandleRef<'_, VmarObject>, address: u64, size: u64) -> Result<()> {
    range(vmar, address, size, true)
}

/// Unlock a page-aligned interval; remaining locks and mappings stay intact.
pub fn unlock_memory(vmar: HandleRef<'_, VmarObject>, address: u64, size: u64) -> Result<()> {
    range(vmar, address, size, false)
}

fn range(vmar: HandleRef<'_, VmarObject>, address: u64, size: u64, lock: bool) -> Result<()> {
    if size == 0
        || !size.is_multiple_of(PAGE_SIZE)
        || !address.is_multiple_of(PAGE_SIZE)
        || address.checked_add(size).is_none()
    {
        return Err(Error::InvalidMemoryRange);
    }
    set(vmar, address, size, 0, lock)
}

fn set(
    vmar: HandleRef<'_, VmarObject>,
    address: u64,
    size: u64,
    flags: u64,
    lock: bool,
) -> Result<()> {
    // SAFETY: The typed borrow remains live and the kernel validates ownership.
    let status = unsafe {
        if lock {
            hyper_sys::vmar_lock_memory(vmar.raw().get(), address, size, flags)
        } else {
            hyper_sys::vmar_unlock_memory(vmar.raw().get(), address, size, flags)
        }
    };
    Status::from_raw(status).into_result()
}
