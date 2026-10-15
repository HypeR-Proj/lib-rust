// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Read-only allocator diagnostics. Calls neither reclaim nor flush memory.
//! Records and their atomic fields are sampled independently; a sequence is
//! not a globally atomic snapshot. Counts from overlapping views are not additive.
use super::MemoryInspector;
use crate::{Error, Result, Status};
use hyper_abi as abi;

pub const BUDDY_ORDERS: u32 = abi::HYPER_NATIVE_MEMORY_STATISTICS_BUDDY_ORDER_COUNT as u32;
pub const PAGE_OWNERS: u32 = abi::HYPER_NATIVE_MEMORY_STATISTICS_OWNER_COUNT as u32;
pub const HEAP_CLASSES: u32 = abi::HYPER_NATIVE_MEMORY_STATISTICS_HEAP_CLASS_COUNT as u32;
pub use abi::HyperNativeMemoryBuddyStatistics as BuddyStatistics;
pub use abi::HyperNativeMemoryFileCacheStatistics as FileCacheStatistics;
pub use abi::HyperNativeMemoryHeapClassStatistics as HeapClassStatistics;
pub use abi::HyperNativeMemoryHeapStatistics as HeapStatistics;
pub use abi::HyperNativeMemoryOwnerStatistics as OwnerStatistics;

// Only local invocations can choose a record type. All records contain u64
// fields only; explicit initialization avoids padding/validity assumptions.
macro_rules! read_record {
    ($self:ident, $ty:ident, $topic:ident, $index:expr, [$($field:ident),+]) => {{
        let mut record = $ty { $($field: 0),+ };
        // SAFETY: The layout is fixed by the local typed call; initialized
        // writable storage and the inspector borrow survive the syscall.
        let result = unsafe { hyper_sys::memory_inspector_read_statistics(
            $self.handle.as_handle_ref().raw().get(), abi::$topic as u32, $index,
            (&mut record as *mut $ty).cast(), core::mem::size_of::<$ty>()) };
        crate::validate_info_result(result, core::mem::size_of::<$ty>())?;
        record
    }};
}

impl MemoryInspector {
    /// Heap occupancy, allocation traffic and per-CPU cache traffic.
    pub fn heap_statistics(&self) -> Result<HeapStatistics> {
        let record = read_record!(
            self,
            HeapStatistics,
            HYPER_NATIVE_MEMORY_STATISTICS_HEAP,
            0,
            [
                captured_at_ns,
                live_objects,
                live_slab_objects,
                live_large_objects,
                requested_bytes,
                peak_objects,
                peak_requested_bytes,
                allocations,
                failures,
                cached_objects,
                cache_hits,
                cache_misses,
                cache_refills,
                cache_drains,
                pressure_reclaims,
                reclaimed_objects,
                cache_cpus,
                profiling_enabled,
                page_allocations,
                page_failures,
                page_deallocations,
                peak_allocated_pages
            ]
        );
        if record.profiling_enabled > 1 {
            return Err(Error::InvalidResponse);
        }
        Ok(record)
    }
    /// Free block count at one buddy order; bytes = `blocks * page_size * 2^order`.
    pub fn buddy_statistics(&self, index: u32) -> Result<BuddyStatistics> {
        if index >= BUDDY_ORDERS {
            return Err(Error::Status(Status::INVALID_ARGUMENT));
        }
        let record = read_record!(
            self,
            BuddyStatistics,
            HYPER_NATIVE_MEMORY_STATISTICS_BUDDY,
            index,
            [captured_at_ns, order, free_blocks]
        );
        if record.order != index as u64 {
            return Err(Error::InvalidResponse);
        }
        Ok(record)
    }
    /// One owner: kernel, page tables, guest, user, file cache (indices 0..4).
    pub fn owner_statistics(&self, index: u32) -> Result<OwnerStatistics> {
        if index >= PAGE_OWNERS {
            return Err(Error::Status(Status::INVALID_ARGUMENT));
        }
        let record = read_record!(
            self,
            OwnerStatistics,
            HYPER_NATIVE_MEMORY_STATISTICS_OWNER,
            index,
            [
                captured_at_ns,
                resident_pages,
                peak_pages,
                allocations,
                failures,
                deallocations
            ]
        );
        Ok(record)
    }
    /// File payload, index occupancy and metadata residency; these views overlap.
    pub fn file_cache_statistics(&self) -> Result<FileCacheStatistics> {
        let record = read_record!(
            self,
            FileCacheStatistics,
            HYPER_NATIVE_MEMORY_STATISTICS_FILE_CACHE,
            0,
            [
                captured_at_ns,
                payload_pages,
                metadata_slab_pages,
                metadata_large_pages,
                index_capacity,
                clean_entries,
                loading_entries,
                live_payloads,
                metadata_budget_pages,
                table_present,
                admission_enabled,
                admission_paused,
                maintenance_pending,
                maintenance_running,
                growth_requested
            ]
        );
        if [
            record.table_present,
            record.admission_enabled,
            record.admission_paused,
            record.maintenance_pending,
            record.maintenance_running,
            record.growth_requested,
        ]
        .iter()
        .any(|value| *value > 1)
        {
            return Err(Error::InvalidResponse);
        }
        Ok(record)
    }
    /// One heap pool/size bucket. Returns `NOT_SUPPORTED` if profiling is disabled.
    pub fn heap_class_statistics(&self, index: u32) -> Result<HeapClassStatistics> {
        if index >= HEAP_CLASSES {
            return Err(Error::Status(Status::INVALID_ARGUMENT));
        }
        let record = read_record!(
            self,
            HeapClassStatistics,
            HYPER_NATIVE_MEMORY_STATISTICS_HEAP_CLASS,
            index,
            [
                captured_at_ns,
                pool,
                object_size,
                pages,
                capacity,
                reserved,
                cached,
                live,
                requested_bytes,
                allocations,
                deallocations
            ]
        );
        if record.pool != u64::from(index / 9)
            || record.object_size != if index % 9 == 8 { 0 } else { 16 << (index % 9) }
        {
            return Err(Error::InvalidResponse);
        }
        Ok(record)
    }
}
