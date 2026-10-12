// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Virtual memory objects and address-space mappings.

use crate::ffi::ffi_native_call6;
use crate::{CallResult, abi};

/// Creates one zero-filled writable VMO.
///
/// # Safety
///
/// On `OK`, the caller assumes exclusive ownership of the VMO in `value0`.
#[inline]
pub unsafe fn vmo_create(size: u64) -> CallResult {
    // SAFETY: ownership of the successful raw result transfers to the caller.
    unsafe { ffi_native_call6(abi::HYPER_NATIVE_SYS_VMO_CREATE, size, 0, 0, 0, 0, 0) }
}

/// Reads bytes from a VMO.
///
/// # Safety
///
/// `vmo` must remain live with read rights and `output` must be writable for
/// `length` bytes.
#[inline]
pub unsafe fn vmo_read(
    vmo: abi::HyperNativeHandle,
    offset: u64,
    output: *mut u8,
    length: usize,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the raw handle and output range.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VMO_READ,
            vmo,
            offset,
            output.addr() as u64,
            length as u64,
            0,
            0,
        )
        .status
    }
}

/// Writes bytes into a writable VMO.
///
/// # Safety
///
/// `vmo` must remain live with write rights and `input` must be readable for
/// `length` bytes.
#[inline]
pub unsafe fn vmo_write(
    vmo: abi::HyperNativeHandle,
    offset: u64,
    input: *const u8,
    length: usize,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the raw handle and input range.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VMO_WRITE,
            vmo,
            offset,
            input.addr() as u64,
            length as u64,
            0,
            0,
        )
        .status
    }
}

/// Allocates a child VMAR. Options zero treats address as a low-end hint;
/// address zero selects the lowest free range. `VMAR_ALLOCATE_EXACT` forbids
/// relocation, including for address zero. Success returns its base in value1.
///
/// # Safety
///
/// `parent` must remain live with map rights. On `OK`, the caller assumes
/// exclusive ownership of the child VMAR in `value0`.
#[inline]
pub unsafe fn vmar_allocate(
    parent: abi::HyperNativeHandle,
    address: u64,
    size: u64,
    options: u64,
) -> CallResult {
    // SAFETY: the caller establishes the parent and result ownership contract.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VMAR_ALLOCATE,
            parent,
            address,
            size,
            options,
            0,
            0,
        )
    }
}

/// Maps a VMO into an exact VMAR range.
///
/// # Safety
///
/// Both handles must remain live with map rights and all offsets, ranges, and
/// permissions must satisfy the Native VMAR contract.
#[inline]
pub unsafe fn vmar_map(
    vmar: abi::HyperNativeHandle,
    vmo: abi::HyperNativeHandle,
    object_offset: u64,
    address: u64,
    size: u64,
    permissions: u64,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes both handles and the complete map range.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VMAR_MAP,
            vmar,
            vmo,
            object_offset,
            address,
            size,
            permissions,
        )
        .status
    }
}

/// Changes permissions on a mapped VMAR range.
///
/// # Safety
///
/// `vmar` must remain live with map rights and the range must be fully owned
/// by it.
#[inline]
pub unsafe fn vmar_protect(
    vmar: abi::HyperNativeHandle,
    address: u64,
    size: u64,
    permissions: u64,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the authority and exact range contract.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VMAR_PROTECT,
            vmar,
            address,
            size,
            permissions,
            0,
            0,
        )
        .status
    }
}

/// Removes mappings from a VMAR range.
///
/// # Safety
///
/// `vmar` must remain live with map rights and the range must be fully owned
/// by it.
#[inline]
pub unsafe fn vmar_unmap(
    vmar: abi::HyperNativeHandle,
    address: u64,
    size: u64,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the authority and exact range contract.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VMAR_UNMAP,
            vmar,
            address,
            size,
            0,
            0,
            0,
        )
        .status
    }
}

/// Destroys and consumes one empty child VMAR.
///
/// # Safety
///
/// The caller must exclusively own `vmar`. `OK` consumes it; every failure
/// preserves ownership.
#[inline]
pub unsafe fn vmar_destroy(vmar: abi::HyperNativeHandle) -> abi::HyperNativeStatus {
    // SAFETY: the caller owns the consume-on-success transition.
    unsafe { ffi_native_call6(abi::HYPER_NATIVE_SYS_VMAR_DESTROY, vmar, 0, 0, 0, 0, 0).status }
}

/// Creates an immutable snapshot of borrowed VMO bytes.
///
/// # Safety
/// `vmo` must name a live readable VMO; the caller adopts the produced handle.
pub unsafe fn vmo_create_snapshot(vmo: abi::HyperNativeHandle) -> CallResult {
    // SAFETY: the caller supplies a live borrowed VMO and adopts the result.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VMO_CREATE_SNAPSHOT,
            vmo,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Installs a private mapping of immutable snapshot bytes.
///
/// # Safety
/// Handles and the input record must be live for this call. The caller must
/// own the destination virtual range and uphold Rust aliasing for its mappings.
pub unsafe fn vmar_map_private(
    vmar: abi::HyperNativeHandle,
    snapshot: abi::HyperNativeHandle,
    mapping: *const abi::HyperNativePrivateMapping,
    mapping_size: usize,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller supplies live handles, request bytes, and destination ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VMAR_MAP_PRIVATE,
            vmar,
            snapshot,
            mapping as usize as u64,
            mapping_size as u64,
            0,
            0,
        )
        .status
    }
}

/// Creates an eagerly allocated physically contiguous writable VMO.
///
/// # Safety
/// Adopt a successfully returned handle exactly once.
#[inline]
pub unsafe fn vmo_create_contiguous(size: u64) -> CallResult {
    // SAFETY: Scalar request; no borrowed memory or input capability.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VMO_CREATE_CONTIGUOUS,
            size,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Executes the Native `vmo_get_dma_extent` operation.
///
/// # Safety
/// Retain all input handles and provide valid readable/writable pointer ranges
/// as specified by the Native ABI for the complete non-retaining call.
#[inline]
pub unsafe fn vmo_get_dma_extent(
    authority: u64,
    vmo: u64,
    offset: u64,
    length: u64,
    output: *mut abi::HyperNativeDmaExtent,
    size: usize,
) -> CallResult {
    // SAFETY: The caller establishes the ABI handle and memory contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VMO_GET_DMA_EXTENT,
            authority,
            vmo,
            offset,
            length,
            output as u64,
            size as u64,
        )
    }
}

/// Maps a protected file range privately into a VMAR of the current process.
///
/// Only `COPY_ON_WRITE` mode is supported. The mapping retains an independent
/// protection reference while allowing clean resident pages to be reclaimed.
///
/// # Safety
/// The File requires READ, plus EXECUTE for executable mappings. The live
/// protection token must cover that same file; it and the VMAR require MAP.
/// `mapping` must remain readable
/// for `mapping_size` bytes; the caller owns the destination address range.
pub unsafe fn vmar_map_file(
    vmar: abi::HyperNativeHandle,
    file: abi::HyperNativeHandle,
    protection: abi::HyperNativeHandle,
    mapping: *const abi::HyperNativePrivateMapping,
    mapping_size: usize,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller retains all capabilities and the request record.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VMAR_MAP_FILE,
            vmar,
            file,
            protection,
            mapping as u64,
            mapping_size as u64,
            0,
        )
        .status
    }
}
