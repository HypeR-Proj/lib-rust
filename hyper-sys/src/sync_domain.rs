// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Raw shared synchronization domain operations.

use crate::{CallResult, abi, ffi};

/// Creates a synchronization domain using the current object factory.
///
/// # Safety
/// The caller must adopt the unique handle returned on success.
pub unsafe fn sync_domain_create(options: u64) -> CallResult {
    // SAFETY: the caller assumes the returned capability; reserved inputs are zero.
    unsafe {
        ffi::ffi_native_invoke6(
            ffi::ffi_native_object_factory(),
            abi::HYPER_NATIVE_OP_SYNC_DOMAIN_CREATE,
            options,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Permanently attributes a writable RAM range to a domain.
///
/// # Safety
/// Both handles must remain live and `binding` readable for `size` bytes.
pub unsafe fn sync_domain_bind(
    domain: u64,
    binding: *const abi::HyperNativeSyncDomainBinding,
    size: usize,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller retains the request and its borrowed capabilities.
    unsafe {
        ffi::ffi_native_invoke6(
            domain,
            abi::HYPER_NATIVE_OP_SYNC_DOMAIN_BIND,
            binding as u64,
            size as u64,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Joins the calling Thread, idempotently, until its actual exit.
///
/// # Safety
/// `domain` must remain a live synchronization domain capability.
pub unsafe fn sync_domain_join(domain: u64, options: u64) -> CallResult {
    // SAFETY: the caller retains the domain during the invocation.
    unsafe {
        ffi::ffi_native_invoke6(
            domain,
            abi::HYPER_NATIVE_OP_SYNC_DOMAIN_JOIN,
            options,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Observes a domain-local participant without granting Thread authority.
///
/// # Safety
/// `domain` must remain live during this operation.
pub unsafe fn sync_domain_owner_query(domain: u64, owner: u64, options: u64) -> CallResult {
    // SAFETY: the caller retains the domain; owner is an observation value.
    unsafe {
        ffi::ffi_native_invoke6(
            domain,
            abi::HYPER_NATIVE_OP_SYNC_DOMAIN_OWNER_QUERY,
            owner,
            options,
            0,
            0,
            0,
            0,
        )
    }
}

/// Waits on a shared word, domain death events and optional cancellation.
///
/// # Safety
/// `wait` must remain readable for `size` bytes; all named handles must remain
/// live. Concurrent shared-word access must use aligned, consistent-width u64
/// atomics. A successful result does not grant mutex ownership.
pub unsafe fn sync_domain_wait_u64(
    domain: u64,
    wait: *const abi::HyperNativeSyncDomainWait,
    size: usize,
) -> CallResult {
    // SAFETY: the caller maintains the request and shared-word access contract.
    unsafe {
        ffi::ffi_native_invoke6(
            domain,
            abi::HYPER_NATIVE_OP_SYNC_DOMAIN_WAIT_U64,
            wait as u64,
            size as u64,
            0,
            0,
            0,
            0,
        )
    }
}

/// Notifies up to `count` exact shared-word waiters, without reading payload.
///
/// # Safety
/// Domain and VMO handles must remain live throughout the operation.
pub unsafe fn sync_domain_wake_u64(
    domain: u64,
    vmo: u64,
    offset: u64,
    count: u32,
    options: u64,
) -> CallResult {
    // SAFETY: the caller retains both capabilities; kernel validates geometry.
    unsafe {
        ffi::ffi_native_invoke6(
            domain,
            abi::HYPER_NATIVE_OP_SYNC_DOMAIN_WAKE_U64,
            vmo,
            offset,
            u64::from(count),
            options,
            0,
            0,
        )
    }
}
