// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Guest mailboxes, notifications, mappings, and block backends.

use crate::ffi::ffi_native_invoke6;
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
        ffi_native_invoke6(
            machine,
            abi::HYPER_NATIVE_OP_GUEST_MAILBOX_CREATE,
            base,
            u64::from(irq),
            0,
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
        ffi_native_invoke6(
            mailbox,
            abi::HYPER_NATIVE_OP_GUEST_MAILBOX_SEND,
            bytes as u64,
            length as u64,
            0,
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
        ffi_native_invoke6(
            mailbox,
            abi::HYPER_NATIVE_OP_GUEST_MAILBOX_RECEIVE,
            bytes as u64,
            capacity as u64,
            0,
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
        ffi_native_invoke6(
            frontend,
            abi::HYPER_NATIVE_OP_GUEST_NOTIFICATION_CREATE,
            backend,
            frontend_base,
            backend_base,
            u64::from(frontend_irq),
            u64::from(backend_irq),
            0,
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
        ffi_native_invoke6(
            notification,
            abi::HYPER_NATIVE_OP_GUEST_NOTIFICATION_CONTROL,
            u64::from(operation),
            0,
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
        ffi_native_invoke6(
            memory,
            abi::HYPER_NATIVE_OP_NATIVE_BLOCK_CREATE,
            backend,
            guest_base,
            notification_base,
            u64::from(notification_irq),
            0,
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
        ffi_native_invoke6(
            block,
            abi::HYPER_NATIVE_OP_NATIVE_BLOCK_ACTIVATE,
            u64::from(readonly),
            0,
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
    queue: u64,
    directory: u64,
    path: *const u8,
    length: usize,
    read_only: bool,
) -> CallResult {
    // SAFETY: Caller retains all capabilities and path bytes for the call.
    unsafe {
        ffi_native_invoke6(
            directory,
            abi::HYPER_NATIVE_OP_FILESYSTEM_MOUNT,
            channel,
            buffer,
            path as u64,
            length as u64,
            u64::from(read_only),
            queue,
        )
    }
}
/// Detaches an idle mount after its filesystem durability fence succeeds.
/// # Safety
/// The directory capability and readable path remain valid through the call.
pub unsafe fn filesystem_unmount(directory: u64, path: *const u8, length: usize) -> CallResult {
    // SAFETY: Caller owns the capability and path for the duration of this call.
    unsafe {
        ffi_native_invoke6(
            directory,
            abi::HYPER_NATIVE_OP_FILESYSTEM_UNMOUNT,
            path as u64,
            length as u64,
            0,
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
        ffi_native_invoke6(
            block,
            abi::HYPER_NATIVE_OP_NATIVE_BLOCK_TRANSFER,
            u64::from(operation),
            first,
            buffer as u64,
            length as u64,
            0,
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
        ffi_native_invoke6(
            backend,
            abi::HYPER_NATIVE_OP_GUEST_MAPPING_CREATE,
            memory,
            frontend,
            0,
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
        ffi_native_invoke6(
            mapping,
            abi::HYPER_NATIVE_OP_GUEST_MAPPING_RELEASE,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Configures the frontend decode of an existing notification route.
///
/// # Safety
/// The VM handle must remain valid through this non-retaining call.
#[inline]
pub unsafe fn guest_notification_configure(
    machine: u64,
    original_base: u64,
    base: u64,
    flags: u32,
) -> CallResult {
    // SAFETY: The caller retains the machine handle for the complete call.
    unsafe {
        ffi_native_invoke6(
            machine,
            abi::HYPER_NATIVE_OP_GUEST_NOTIFICATION_CONFIGURE,
            original_base,
            base,
            u64::from(flags),
            0,
            0,
            0,
        )
    }
}

/// Operate the admitted frontend notification state for a userspace transport.
///
/// # Safety
/// The VM handle must remain valid through this non-retaining scalar call.
#[inline]
pub unsafe fn guest_notification_access(
    machine: u64,
    original_base: u64,
    operation: u32,
    value: u32,
) -> CallResult {
    // SAFETY: The caller retains the machine handle for the complete call.
    unsafe {
        ffi_native_invoke6(
            machine,
            abi::HYPER_NATIVE_OP_GUEST_NOTIFICATION_ACCESS,
            original_base,
            u64::from(operation),
            u64::from(value),
            0,
            0,
            0,
        )
    }
}

/// Copies at most 4096 bytes to/from explicitly delegated guest backing.
///
/// # Safety
/// Handles and the pointer range must satisfy the Native ABI for this call.
pub unsafe fn guest_memory_transfer(
    memory: u64,
    operation: u32,
    offset: u64,
    buffer: *mut u8,
    length: usize,
) -> CallResult {
    // SAFETY: The caller supplies valid borrowed handles and a bounded buffer.
    unsafe {
        ffi_native_invoke6(
            memory,
            abi::HYPER_NATIVE_OP_GUEST_MEMORY_TRANSFER,
            u64::from(operation),
            offset,
            buffer as u64,
            length as u64,
            0,
            0,
        )
    }
}

/// Accesses one aligned guest word, with acquire-load or release/store-fence ordering.
///
/// # Safety
/// Retain a `GuestMemory` handle with the operation's required rights.
pub unsafe fn guest_memory_scalar(
    memory: u64,
    operation: u32,
    offset: u64,
    width: u32,
    value: u64,
) -> CallResult {
    // SAFETY: The caller supplies a valid borrowed handle; remaining inputs are scalar.
    unsafe {
        ffi_native_invoke6(
            memory,
            abi::HYPER_NATIVE_OP_GUEST_MEMORY_SCALAR,
            u64::from(operation),
            offset,
            u64::from(width),
            value,
            0,
            0,
        )
    }
}

/// Reserves a guest level interrupt without assigning a device model to the kernel.
///
/// # Safety
/// Retain the borrowed `VirtualMachine` WRITE handle.
pub unsafe fn guest_interrupt_create(machine: u64, irq: u32) -> CallResult {
    // SAFETY: The caller supplies the borrowed handle and scalar IRQ identity.
    unsafe {
        ffi_native_invoke6(
            machine,
            abi::HYPER_NATIVE_OP_GUEST_INTERRUPT_CREATE,
            u64::from(irq),
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Changes the level of an exclusively owned guest interrupt.
///
/// # Safety
/// Retain the borrowed `GuestInterrupt` WRITE handle.
pub unsafe fn guest_interrupt_set_level(interrupt: u64, asserted: bool) -> CallResult {
    // SAFETY: The caller supplies the borrowed handle; level is a canonical boolean.
    unsafe {
        ffi_native_invoke6(
            interrupt,
            abi::HYPER_NATIVE_OP_GUEST_INTERRUPT_SET_LEVEL,
            u64::from(asserted),
            0,
            0,
            0,
            0,
            0,
        )
    }
}
