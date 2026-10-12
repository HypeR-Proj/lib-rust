// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Physical console and guest virtual-serial transport.

use crate::ffi::{ffi_console_read, ffi_console_write, ffi_native_call6};
use crate::{CallResult, abi};

/// Creates one unbound buffered virtual serial port.
///
/// # Safety
///
/// The caller must adopt the returned handle exactly once on success.
#[inline]
pub unsafe fn virtual_serial_create() -> CallResult {
    // SAFETY: result ownership is delegated to the caller.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_SERIAL_CREATE,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Registers caller-owned whole pages for virtual serial output.
///
/// # Safety
///
/// Both handles must remain live with WRITE authority (and READ|MAP for the
/// VMO). Do not access its contents during registration. After success use
/// the shared-ring atomic protocol until all kernel producers are quiescent.
#[inline]
pub unsafe fn virtual_serial_register_output(
    serial: abi::HyperNativeHandle,
    buffer: abi::HyperNativeHandle,
) -> abi::HyperNativeStatus {
    // SAFETY: caller retains both handles and suspends buffer access during registration.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_SERIAL_REGISTER_OUTPUT,
            serial,
            buffer,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Acknowledges consumed output and atomically reconciles READABLE.
///
/// # Safety
/// The serial handle must retain READ authority. Complete all reads of the
/// acknowledged prefix before this call; those slots may immediately be reused.
#[inline]
pub unsafe fn virtual_serial_acknowledge_output(
    serial: abi::HyperNativeHandle,
    consumed: u64,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller retains the handle and has completed the prefix reads.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_SERIAL_ACKNOWLEDGE_OUTPUT,
            serial,
            consumed,
            0,
            0,
            0,
            0,
        )
        .status
    }
}

/// Writes guest input to a virtual serial port.
///
/// # Safety
///
/// `bytes` must be readable for `length` bytes and `serial` must remain live.
#[inline]
pub unsafe fn virtual_serial_write(
    serial: abi::HyperNativeHandle,
    bytes: *const u8,
    length: usize,
) -> CallResult {
    // SAFETY: the caller establishes the pointer and handle contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_VIRTUAL_SERIAL_WRITE,
            serial,
            bytes as u64,
            length as u64,
            0,
            0,
            0,
        )
    }
}

/// Reads bytes through one raw Console handle.
///
/// # Safety
///
/// `console` must remain live and identify a Console with read rights. For a
/// nonzero `capacity`, `bytes` must identify writable memory of that extent
/// for the complete syscall.
#[inline]
pub unsafe fn console_read(
    console: abi::HyperNativeHandle,
    bytes: *mut u8,
    capacity: usize,
) -> CallResult {
    // SAFETY: the caller establishes handle and output-buffer validity.
    unsafe { ffi_console_read(console, bytes, capacity) }
}

/// Writes bytes through one raw Console handle.
///
/// # Safety
///
/// `console` must remain live and identify a Console with write rights. For a
/// nonzero `count`, `bytes` must identify readable memory of that extent for
/// the complete syscall.
#[inline]
pub unsafe fn console_write(
    console: abi::HyperNativeHandle,
    bytes: *const u8,
    count: usize,
) -> CallResult {
    // SAFETY: the caller establishes handle and input-buffer validity.
    unsafe { ffi_console_write(console, bytes, count) }
}
