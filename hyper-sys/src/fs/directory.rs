// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Capability-relative filesystem namespace operations.

use crate::ffi::ffi_native_call6;
use crate::{CallResult, abi};

/// Opens one file relative to a `Directory` capability.
///
/// # Safety
///
/// `directory` must remain live with read rights and every right named by
/// `requested_rights`. `path` must be readable for `path_size` bytes. On `OK`,
/// the caller assumes exclusive ownership of the nonzero `File` handle
/// returned in `value0`.
#[inline]
pub unsafe fn directory_open_file(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_size: usize,
    requested_rights: u64,
) -> CallResult {
    // SAFETY: the caller establishes the handle, input-buffer, and ownership
    // contracts of the raw Native operation.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_OPEN_FILE,
            directory,
            path.addr() as u64,
            path_size as u64,
            requested_rights,
            0,
            0,
        )
    }
}

/// Opens one child directory relative to a `Directory` capability.
///
/// # Safety
///
/// `directory` must remain live with read rights and every requested right.
/// `path` must be readable for `path_size` bytes. On `OK`, the caller assumes
/// exclusive ownership of the nonzero Directory handle in `value0`.
#[inline]
pub unsafe fn directory_open_directory(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_size: usize,
    requested_rights: u64,
) -> CallResult {
    // SAFETY: the caller establishes all raw handle and buffer contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_OPEN_DIRECTORY,
            directory,
            path.addr() as u64,
            path_size as u64,
            requested_rights,
            0,
            0,
        )
    }
}

/// Creates an independent directory stream without acquiring traversal rights.
///
/// # Safety
///
/// `directory` must remain live with READ. On success the caller owns the
/// `DirectoryStream` handle returned in `value0` and must eventually close it.
#[inline]
pub unsafe fn directory_begin_read(directory: abi::HyperNativeHandle) -> CallResult {
    // SAFETY: the caller retains the source authority and adopts the result.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_BEGIN_READ,
            directory,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Reads one fixed-capacity page from an independently owned `DirectoryStream`.
///
/// # Safety
///
/// `stream` must remain live with READ. `records` must identify
/// writable storage for `capacity` directory-entry records for the complete
/// syscall. Callers must pass the exact capacity published by the Native ABI
/// and treat the returned continuation cookie as opaque.
#[inline]
pub unsafe fn directory_read(
    stream: abi::HyperNativeHandle,
    cookie: u64,
    records: *mut abi::HyperNativeDirectoryEntry,
    capacity: usize,
) -> CallResult {
    // SAFETY: the caller establishes the borrowed handle, output-buffer, and
    // exact-capacity contracts of the raw Native operation.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_READ,
            stream,
            cookie,
            records.addr() as u64,
            capacity as u64,
            0,
            0,
        )
    }
}

/// Retrieves immutable attributes for one Directory.
///
/// # Safety
///
/// `directory` must remain live with inspect rights. `info` must be aligned
/// and writable for one complete [`abi::HyperNativeDirectoryInfo`] record.
#[inline]
pub unsafe fn directory_get_info(
    directory: abi::HyperNativeHandle,
    info: *mut abi::HyperNativeDirectoryInfo,
) -> CallResult {
    // SAFETY: the caller establishes both handle and output-pointer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_GET_INFO,
            directory,
            info.addr() as u64,
            core::mem::size_of::<abi::HyperNativeDirectoryInfo>() as u64,
            0,
            0,
            0,
        )
    }
}

/// Creates a file and transfers exclusive ownership of the returned handle.
///
/// # Safety
///
/// Handles must remain live with the operation's required rights. Input
/// pointers must be readable for their stated lengths.
pub unsafe fn directory_create_file(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_size: usize,
    rights: u64,
    mode: u32,
) -> CallResult {
    // SAFETY: the caller establishes the Native handle and buffer contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_CREATE_FILE,
            directory,
            path.addr() as u64,
            path_size as u64,
            rights,
            mode as u64,
            0,
        )
    }
}

/// Invokes Native `directory_create_directory`.
///
/// # Safety
///
/// Handles must remain live with the operation's required rights. Input
/// pointers must be readable for their stated lengths.
pub unsafe fn directory_create_directory(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_size: usize,
    mode: u32,
) -> CallResult {
    // SAFETY: the caller establishes the Native handle and buffer contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_CREATE_DIRECTORY,
            directory,
            path.addr() as u64,
            path_size as u64,
            mode as u64,
            0,
            0,
        )
    }
}

/// Invokes Native `directory_remove`.
///
/// # Safety
///
/// Handles must remain live with the operation's required rights. Input
/// pointers must be readable for their stated lengths.
pub unsafe fn directory_remove(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_size: usize,
    options: u32,
) -> CallResult {
    // SAFETY: the caller establishes the Native handle and buffer contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_REMOVE,
            directory,
            path.addr() as u64,
            path_size as u64,
            options as u64,
            0,
            0,
        )
    }
}

/// Invokes Native `directory_scope_create`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_scope_create(
    root: abi::HyperNativeHandle,
    start: abi::HyperNativeHandle,
    rights: u64,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_SCOPE_CREATE,
            root,
            start,
            rights,
            0,
            0,
            0,
        )
    }
}

/// Invokes Native `directory_get_metadata`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_get_metadata(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_length: usize,
    options: u32,
    output: *mut abi::HyperNativeFileMetadata,
    output_size: usize,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_GET_METADATA,
            directory,
            path as u64,
            path_length as u64,
            options as u64,
            output as u64,
            output_size as u64,
        )
    }
}

/// Invokes Native `directory_get_self_metadata`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_get_self_metadata(
    directory: abi::HyperNativeHandle,
    output: *mut abi::HyperNativeFileMetadata,
    output_size: usize,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_GET_SELF_METADATA,
            directory,
            output as u64,
            output_size as u64,
            0,
            0,
            0,
        )
    }
}

/// Invokes Native `directory_set_metadata`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_set_metadata(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_length: usize,
    options: u32,
    input: *const abi::HyperNativeFileMetadataUpdate,
    input_size: usize,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_SET_METADATA,
            directory,
            path as u64,
            path_length as u64,
            options as u64,
            input as u64,
            input_size as u64,
        )
    }
}

/// Invokes Native `directory_rename`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_rename(
    source: abi::HyperNativeHandle,
    path: *const u8,
    path_length: usize,
    destination: abi::HyperNativeHandle,
    new_path: *const u8,
    new_path_length: usize,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_RENAME,
            source,
            path as u64,
            path_length as u64,
            destination,
            new_path as u64,
            new_path_length as u64,
        )
    }
}

/// Invokes Native `directory_link`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_link(
    source: abi::HyperNativeHandle,
    path: *const u8,
    path_length: usize,
    destination: abi::HyperNativeHandle,
    new_path: *const u8,
    new_path_length: usize,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_LINK,
            source,
            path as u64,
            path_length as u64,
            destination,
            new_path as u64,
            new_path_length as u64,
        )
    }
}

/// Invokes Native `directory_symlink`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_symlink(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_length: usize,
    target: *const u8,
    target_length: usize,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_SYMLINK,
            directory,
            path as u64,
            path_length as u64,
            target as u64,
            target_length as u64,
            0,
        )
    }
}

/// Invokes Native `directory_read_link`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_read_link(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_length: usize,
    output: *mut u8,
    capacity: usize,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_READ_LINK,
            directory,
            path as u64,
            path_length as u64,
            output as u64,
            capacity as u64,
            0,
        )
    }
}

/// Invokes Native `directory_canonicalize`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_canonicalize(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_length: usize,
    output: *mut u8,
    capacity: usize,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_CANONICALIZE,
            directory,
            path as u64,
            path_length as u64,
            output as u64,
            capacity as u64,
            0,
        )
    }
}

/// Invokes Native `directory_remove_if`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_remove_if(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_length: usize,
    options: u32,
    expected_node_id: u64,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_REMOVE_IF,
            directory,
            path as u64,
            path_length as u64,
            options as u64,
            expected_node_id,
            0,
        )
    }
}

/// Invokes Native `directory_open_directory_nofollow`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_open_directory_nofollow(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_length: usize,
    rights: u64,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_OPEN_DIRECTORY_NOFOLLOW,
            directory,
            path as u64,
            path_length as u64,
            rights,
            0,
            0,
        )
    }
}

/// Invokes Native `directory_open_file_with_options`.
///
/// # Safety
/// Borrowed handles must stay live with required rights. Input pointers must
/// reference readable initialized records or the specified byte ranges; output
/// pointers must exclusively reference writable records or byte ranges.
pub unsafe fn directory_open_file_with_options(
    directory: abi::HyperNativeHandle,
    path: *const u8,
    path_length: usize,
    rights: u64,
    options: u32,
    mode: u32,
) -> CallResult {
    // SAFETY: the caller establishes handle lifetime and buffer validity.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DIRECTORY_OPEN_FILE_WITH_OPTIONS,
            directory,
            path as u64,
            path_length as u64,
            rights,
            options as u64,
            mode as u64,
        )
    }
}
