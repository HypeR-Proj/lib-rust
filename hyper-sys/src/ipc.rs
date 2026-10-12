// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Byte-channel and transactional capability-channel transport.

use crate::ffi::{ffi_byte_channel_read, ffi_byte_channel_write, ffi_native_call6};
use crate::{CallResult, abi};

/// Creates one raw `ByteChannel` endpoint pair.
///
/// # Safety
///
/// On `OK`, the caller assumes exclusive ownership of both nonzero handles in
/// `value0` and `value1`. Every failure publishes no handle.
#[inline]
pub unsafe fn byte_channel_create() -> CallResult {
    // SAFETY: the caller accepts ownership of both successful raw results.
    unsafe { ffi_native_call6(abi::HYPER_NATIVE_SYS_BYTE_CHANNEL_CREATE, 0, 0, 0, 0, 0, 0) }
}

/// Sends one handle-free message through a raw `ByteChannel` endpoint.
///
/// # Safety
///
/// `endpoint` must remain live with write rights. For a nonzero `byte_count`,
/// `bytes` must remain readable for that extent during the call.
#[inline]
pub unsafe fn byte_channel_write(
    endpoint: abi::HyperNativeHandle,
    bytes: *const u8,
    byte_count: usize,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes the handle and input-buffer contracts.
    unsafe { ffi_byte_channel_write(endpoint, bytes, byte_count) }
}

/// Receives one handle-free message through a raw `ByteChannel` endpoint.
///
/// # Safety
///
/// `endpoint` must remain live with read rights. For a nonzero
/// `byte_capacity`, `bytes` must remain writable for that extent during the
/// call. Messages carrying handles are reported as too large by this veneer.
#[inline]
pub unsafe fn byte_channel_read(
    endpoint: abi::HyperNativeHandle,
    bytes: *mut u8,
    byte_capacity: usize,
) -> CallResult {
    // SAFETY: the caller establishes the handle and output-buffer contracts.
    unsafe { ffi_byte_channel_read(endpoint, bytes, byte_capacity) }
}

/// Creates one raw `CapabilityChannel` endpoint pair.
///
/// # Safety
///
/// On `OK`, the caller assumes exclusive ownership of both nonzero handles in
/// `value0` and `value1`. Every failure publishes no handle.
#[inline]
pub unsafe fn capability_channel_create() -> CallResult {
    // SAFETY: the caller accepts ownership of both successful raw results.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_CAPABILITY_CHANNEL_CREATE,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Attempts one transactional capability rendezvous.
///
/// # Safety
///
/// `endpoint` must remain live with write rights. The byte and disposition
/// arrays must remain readable for their complete extents. Every disposition
/// must describe an exclusively owned or validly borrowed handle according to
/// its operation. `OK` consumes every MOVE source and creates the corresponding
/// destination owners; every non-`OK` result preserves all source ownership.
#[inline]
pub unsafe fn capability_channel_try_send(
    endpoint: abi::HyperNativeHandle,
    bytes: *const u8,
    byte_count: usize,
    dispositions: *const abi::HyperNativeCapabilityDisposition,
    disposition_count: usize,
) -> abi::HyperNativeStatus {
    // SAFETY: the caller establishes all pointer, handle, and transactional
    // ownership contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_CAPABILITY_CHANNEL_TRY_SEND,
            endpoint,
            0,
            bytes.addr() as u64,
            byte_count as u64,
            dispositions.addr() as u64,
            disposition_count as u64,
        )
        .status
    }
}

/// Receives one transactional capability rendezvous.
///
/// # Safety
///
/// `endpoint` must remain live with read rights. `bytes` and `slots` must be
/// writable for their declared extents; slots must also contain initialized
/// receive requests. On `OK`, the caller owns each nonzero handle installed in
/// the first `value1` slots. On non-`OK`, no output handle is live. A `FAULT`
/// may have partially modified output memory, which the caller must ignore.
#[inline]
pub unsafe fn capability_channel_receive(
    endpoint: abi::HyperNativeHandle,
    deadline: u64,
    bytes: *mut u8,
    byte_capacity: usize,
    slots: *mut abi::HyperNativeCapabilityReceiveSlot,
    slot_count: usize,
) -> CallResult {
    // SAFETY: the caller establishes all pointer, handle, initialization, and
    // successful-result ownership contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_CAPABILITY_CHANNEL_RECEIVE,
            endpoint,
            deadline,
            bytes.addr() as u64,
            byte_capacity as u64,
            slots.addr() as u64,
            slot_count as u64,
        )
    }
}
