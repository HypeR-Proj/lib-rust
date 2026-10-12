// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! C runtime startup records and borrowed startup-handle lookup.

use crate::abi;
use crate::ffi::ffi_startup_find_handle;
use core::ffi::c_char;

/// One architecture-width auxiliary-vector entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuxiliaryEntry {
    pub key: usize,
    pub value: usize,
}

/// Parsed process-startup view produced by the Native C runtime.
#[repr(C)]
#[derive(Debug)]
pub struct RawStartup {
    pub argument_count: usize,
    pub arguments: *const *const c_char,
    pub environment_count: usize,
    pub environment: *const *const c_char,
    pub auxiliary_count: usize,
    pub auxiliary: *const AuxiliaryEntry,
    pub handle_count: usize,
    pub handles: *const abi::HyperNativeStartupHandle,
}

const _: () = assert!(core::mem::size_of::<AuxiliaryEntry>() == 2 * core::mem::size_of::<usize>());
const _: () = assert!(core::mem::align_of::<AuxiliaryEntry>() == core::mem::align_of::<usize>());
const _: () = assert!(core::mem::size_of::<RawStartup>() == 8 * core::mem::size_of::<usize>());
const _: () = assert!(core::mem::align_of::<RawStartup>() == core::mem::align_of::<usize>());
const _: () = assert!(core::mem::offset_of!(RawStartup, argument_count) == 0);
const _: () =
    assert!(core::mem::offset_of!(RawStartup, arguments) == core::mem::size_of::<usize>());
const _: () =
    assert!(core::mem::offset_of!(RawStartup, handles) == 7 * core::mem::size_of::<usize>());

/// Finds one handle in a C-runtime-validated startup record.
///
/// # Safety
///
/// `startup` must point to a live `RawStartup` produced by the matching Native
/// runtime. `handle` must be valid and writable for one handle value. The
/// returned raw value remains owned by the process handle table.
#[inline]
pub unsafe fn startup_find_handle(
    startup: *const RawStartup,
    purpose: u32,
    handle: *mut abi::HyperNativeHandle,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller supplies both pointer validity contracts.
    unsafe { ffi_startup_find_handle(startup, purpose, handle) }
}
