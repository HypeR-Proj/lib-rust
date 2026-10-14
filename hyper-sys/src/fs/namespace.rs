// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Namespace topology calls requiring explicit root-administration authority.

use crate::ffi::ffi_native_call6;
use crate::{CallResult, abi};

/// Attach a fresh in-memory filesystem at a capability-relative path.
///
/// # Safety
/// Retain the root capability and readable path for the complete call.
pub unsafe fn filesystem_mount_ramfs(directory: u64, path: *const u8, length: usize) -> CallResult {
    // SAFETY: The caller retains the borrowed capability and path range.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_FILESYSTEM_MOUNT_RAMFS,
            directory,
            path as u64,
            length as u64,
            0,
            0,
            0,
        )
    }
}

/// Atomically replace the namespace root and move the requested mount edges.
///
/// # Safety
/// Retain the root capability, request, move records and every referenced path
/// for the complete call. All pointers name initialized readable memory.
pub unsafe fn filesystem_switch_root(
    directory: u64,
    request: *const abi::HyperNativeFilesystemRootSwitch,
) -> CallResult {
    // SAFETY: The caller retains the capability and the complete request graph.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_FILESYSTEM_SWITCH_ROOT,
            directory,
            request as u64,
            0,
            0,
            0,
            0,
        )
    }
}

/// Publish a reversible root switch, returning a linear transition token.
///
/// # Safety
/// Keep the capability and the complete request graph live until return.
pub unsafe fn filesystem_begin_root_switch(
    directory: u64,
    request: *const abi::HyperNativeFilesystemRootSwitch,
) -> CallResult {
    // SAFETY: The caller establishes input lifetimes; output transfers ownership.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_FILESYSTEM_BEGIN_ROOT_SWITCH,
            directory,
            request as u64,
            0,
            0,
            0,
            0,
        )
    }
}

/// Commit or abort a pending root switch. Repeated completion fails.
///
/// # Safety
/// `token` must remain live with WRITE authority until return.
pub unsafe fn filesystem_finish_root_switch(token: u64, commit: bool) -> CallResult {
    // SAFETY: The caller retains the non-retaining input capability.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_FILESYSTEM_FINISH_ROOT_SWITCH,
            token,
            u64::from(commit),
            0,
            0,
            0,
            0,
        )
    }
}
