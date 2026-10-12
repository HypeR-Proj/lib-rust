// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Guest mailboxes, notifications, mappings, and block backends.

use crate::ffi::ffi_native_call6;
use crate::{CallResult, abi};

/// Executes the Native `guest_mailbox_create` operation.
///
/// # Safety
/// Retain all input handles and provide valid readable/writable pointer ranges
/// as specified by the Native ABI for the complete non-retaining call.
#[inline]
pub unsafe fn guest_mailbox_create(machine: u64, base: u64, irq: u32) -> CallResult {
    // SAFETY: The caller establishes the ABI handle and memory contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_GUEST_MAILBOX_CREATE,
            machine,
            base,
            u64::from(irq),
            0,
            0,
            0,
        )
    }
}

/// Executes the Native `guest_mailbox_send` operation.
///
/// # Safety
/// Retain all input handles and provide valid readable/writable pointer ranges
/// as specified by the Native ABI for the complete non-retaining call.
#[inline]
pub unsafe fn guest_mailbox_send(mailbox: u64, bytes: *const u8, length: usize) -> CallResult {
    // SAFETY: The caller establishes the ABI handle and memory contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_GUEST_MAILBOX_SEND,
            mailbox,
            bytes as u64,
            length as u64,
            0,
            0,
            0,
        )
    }
}

/// Executes the Native `guest_mailbox_receive` operation.
///
/// # Safety
/// Retain all input handles and provide valid readable/writable pointer ranges
/// as specified by the Native ABI for the complete non-retaining call.
#[inline]
pub unsafe fn guest_mailbox_receive(mailbox: u64, bytes: *mut u8, capacity: usize) -> CallResult {
    // SAFETY: The caller establishes the ABI handle and memory contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_GUEST_MAILBOX_RECEIVE,
            mailbox,
            bytes as u64,
            capacity as u64,
            0,
            0,
            0,
        )
    }
}

/// Executes the Native `guest_notification_create` operation.
///
/// # Safety
/// Retain all input handles and provide valid readable/writable pointer ranges
/// as specified by the Native ABI for the complete non-retaining call.
#[inline]
pub unsafe fn guest_notification_create(
    frontend: u64,
    backend: u64,
    frontend_base: u64,
    backend_base: u64,
    frontend_irq: u32,
    backend_irq: u32,
) -> CallResult {
    // SAFETY: The caller establishes the ABI handle and memory contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_GUEST_NOTIFICATION_CREATE,
            frontend,
            backend,
            frontend_base,
            backend_base,
            u64::from(frontend_irq),
            u64::from(backend_irq),
        )
    }
}

/// Executes the Native `guest_notification_control` operation.
///
/// # Safety
/// Retain all input handles and provide valid readable/writable pointer ranges
/// as specified by the Native ABI for the complete non-retaining call.
#[inline]
pub unsafe fn guest_notification_control(notification: u64, operation: u32) -> CallResult {
    // SAFETY: The caller establishes the ABI handle and memory contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_GUEST_NOTIFICATION_CONTROL,
            notification,
            u64::from(operation),
            0,
            0,
            0,
            0,
        )
    }
}

/// Creates a Native virtio-scsi initiator over a dedicated shared memory grant.
///
/// # Safety
/// Input handles must remain valid throughout this call.
#[inline]
pub unsafe fn native_block_create(
    memory: u64,
    backend: u64,
    guest_base: u64,
    notification_base: u64,
    notification_irq: u32,
) -> CallResult {
    // SAFETY: The caller retains the input capabilities.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_NATIVE_BLOCK_CREATE,
            memory,
            backend,
            guest_base,
            notification_base,
            u64::from(notification_irq),
            0,
        )
    }
}

/// Activates a negotiated initiator and discovers its SCSI capacity.
///
/// # Safety
/// The block handle must remain valid throughout this blocking call.
#[inline]
pub unsafe fn native_block_activate(block: u64, readonly: bool) -> CallResult {
    // SAFETY: The caller retains the input capability.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_NATIVE_BLOCK_ACTIVATE,
            block,
            u64::from(readonly),
            0,
            0,
            0,
            0,
        )
    }
}

/// Mounts a Native block volume at a directory-relative path.
///
/// # Safety
/// Both handles and the readable path must remain valid throughout the call.
#[inline]
pub unsafe fn filesystem_mount(
    channel: u64,
    buffer: u64,
    directory: u64,
    path: *const u8,
    length: usize,
    read_only: bool,
) -> CallResult {
    // SAFETY: Caller retains all capabilities and path bytes for the call.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_FILESYSTEM_MOUNT,
            channel,
            buffer,
            directory,
            path as u64,
            length as u64,
            u64::from(read_only),
        )
    }
}
/// Detaches an idle mount after its filesystem durability fence succeeds.
/// # Safety
/// The directory capability and readable path remain valid through the call.
pub unsafe fn filesystem_unmount(directory: u64, path: *const u8, length: usize) -> CallResult {
    // SAFETY: Caller owns the capability and path for the duration of this call.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_FILESYSTEM_UNMOUNT,
            directory,
            path as u64,
            length as u64,
            0,
            0,
            0,
        )
    }
}
/// Transfers complete sectors, or flushes all earlier writes (operation 2).
/// # Safety
/// The buffer must be writable for reads (0), readable for writes (1), and
/// absent for flush (2). Its whole extent and block capability remain valid.
pub unsafe fn native_block_transfer(
    block: u64,
    operation: u32,
    first: u64,
    buffer: *mut u8,
    length: usize,
) -> CallResult {
    // SAFETY: Caller supplies the operation-specific borrowed buffer.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_NATIVE_BLOCK_TRANSFER,
            block,
            u64::from(operation),
            first,
            buffer as u64,
            length as u64,
            0,
        )
    }
}

/// Creates a retained sparse DMA mapping in an installed backend VM.
/// # Safety
/// Input handles must remain valid throughout the call.
pub unsafe fn guest_mapping_create(backend: u64, memory: u64, frontend: u64) -> CallResult {
    // SAFETY: caller retains the borrowed input capabilities.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_GUEST_MAPPING_CREATE,
            backend,
            memory,
            frontend,
            0,
            0,
            0,
        )
    }
}
/// Releases a mapping after backend-certified DMA quiescence.
/// # Safety
/// The mapping handle must remain valid throughout the call.
pub unsafe fn guest_mapping_release(mapping: u64) -> CallResult {
    // SAFETY: caller retains the borrowed mapping capability.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_GUEST_MAPPING_RELEASE,
            mapping,
            0,
            0,
            0,
            0,
            0,
        )
    }
}
