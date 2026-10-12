// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Adapter to the process heap initialized by the Native C runtime.

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

unsafe extern "C" {
    fn hyper_alloc(size: usize, alignment: usize) -> *mut c_void;
    fn hyper_free(pointer: *mut c_void);
    fn hyper_realloc(pointer: *mut c_void, size: usize, alignment: usize) -> *mut c_void;
}

/// The shared process allocator supplied by `libhyper`.
///
/// CRT initializes it before application entry. Allocation failure returns
/// null; the caller or Rust's allocation-error handler determines OOM policy.
pub struct NativeAllocator;

// SAFETY: libhyper serializes allocation metadata, honors power-of-two
// alignment, preserves realloc contents on failure, and never unwinds.
unsafe impl GlobalAlloc for NativeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc's caller supplies a valid, nonzero layout.
        unsafe { hyper_alloc(layout.size(), layout.align()).cast() }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
        // SAFETY: the caller transfers a live allocation from this allocator.
        unsafe { hyper_free(pointer.cast()) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller owns pointer with this layout and supplies a valid
        // nonzero replacement size; libhyper retains pointer on failure.
        unsafe { hyper_realloc(pointer.cast(), new_size, layout.align()).cast() }
    }
}
