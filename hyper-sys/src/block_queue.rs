// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Raw asynchronous block queue invocations. Submission never retains user pointers.
//! Window submissions reference only an active kernel-owned filesystem lease.

use crate::ffi::ffi_native_invoke6;
use crate::{CallResult, abi};

/// Derives a bounded logical queue from an activated block capability.
///
/// # Safety
/// The caller retains the block capability for this call.
pub unsafe fn block_queue_create(
    block: u64,
    capacity: u32,
    bytes: u64,
    inflight: u32,
) -> CallResult {
    // SAFETY: The caller retains the borrowed capability.
    unsafe {
        ffi_native_invoke6(
            block,
            abi::HYPER_NATIVE_OP_BLOCK_QUEUE_CREATE,
            u64::from(capacity),
            bytes,
            u64::from(inflight),
            0,
            0,
            0,
        )
    }
}

/// Atomically submits one bounded batch; a successful result owns its input copy.
///
/// # Safety
/// `frame` is readable for `length` bytes throughout this call, unless both are
/// zero for flush. The queue capability remains valid during submission.
pub unsafe fn block_queue_submit(
    queue: u64,
    operation: u32,
    count: u32,
    frame: *const u8,
    length: usize,
) -> CallResult {
    // SAFETY: The caller supplies the borrowed frame and queue capability.
    unsafe {
        ffi_native_invoke6(
            queue,
            abi::HYPER_NATIVE_OP_BLOCK_QUEUE_SUBMIT,
            u64::from(operation),
            u64::from(count),
            frame as u64,
            length as u64,
            0,
            0,
        )
    }
}

/// Observes exact or any-ticket completion without consuming its result.
///
/// # Safety
/// The queue capability remains valid throughout the potentially blocking call.
pub unsafe fn block_queue_wait(queue: u64, ticket: u64, deadline: u64) -> CallResult {
    // SAFETY: The caller retains the borrowed capability.
    unsafe {
        ffi_native_invoke6(
            queue,
            abi::HYPER_NATIVE_OP_BLOCK_QUEUE_WAIT,
            ticket,
            deadline,
            0,
            0,
            0,
            0,
        )
    }
}

/// Copies a completed read result and consumes completion after a successful copy.
///
/// # Safety
/// The capability and writable output remain valid during the call. Write,
/// flush and failed-read results require a zero-length output.
pub unsafe fn block_queue_reap(
    queue: u64,
    ticket: u64,
    output: *mut u8,
    length: usize,
) -> CallResult {
    // SAFETY: The caller supplies a writable output extent and retains the queue.
    unsafe {
        ffi_native_invoke6(
            queue,
            abi::HYPER_NATIVE_OP_BLOCK_QUEUE_REAP,
            ticket,
            output as u64,
            length as u64,
            0,
            0,
            0,
        )
    }
}

/// Reads queue limits, occupancy and command counters.
///
/// # Safety
/// The queue capability and writable record remain valid during the call.
pub unsafe fn block_queue_info(
    queue: u64,
    output: *mut abi::HyperNativeBlockQueueInfo,
    size: usize,
) -> CallResult {
    // SAFETY: The caller supplies the writable record and retained capability.
    unsafe {
        ffi_native_invoke6(
            queue,
            abi::HYPER_NATIVE_OP_BLOCK_QUEUE_INFO,
            output as u64,
            size as u64,
            0,
            0,
            0,
            0,
        )
    }
}

/// Waits until queue and device budgets can admit one request of the given size.
///
/// # Safety
/// The queue capability remains valid throughout the potentially blocking call.
pub unsafe fn block_queue_wait_space(queue: u64, bytes: usize, deadline: u64) -> CallResult {
    // SAFETY: The caller retains the borrowed capability.
    unsafe {
        ffi_native_invoke6(
            queue,
            abi::HYPER_NATIVE_OP_BLOCK_QUEUE_WAIT_SPACE,
            bytes as u64,
            deadline,
            0,
            0,
            0,
            0,
        )
    }
}

/// Returns a read-only mapping capability for this queue's Native staging window.
///
/// # Safety
/// The queue capability remains valid during the call.
pub unsafe fn block_queue_create_window(queue: u64) -> CallResult {
    // SAFETY: The caller retains the borrowed capability.
    unsafe {
        ffi_native_invoke6(
            queue,
            abi::HYPER_NATIVE_OP_BLOCK_QUEUE_CREATE_WINDOW,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Submits metadata referencing an active kernel-owned filesystem write window.
///
/// # Safety
/// The frame is readable for `length` bytes and the queue remains valid until
/// return. The kernel validates the token and every referenced byte range.
pub unsafe fn block_queue_submit_window(
    queue: u64,
    token: u64,
    count: u32,
    frame: *const u8,
    length: usize,
) -> CallResult {
    // SAFETY: The caller retains the frame and queue through the call.
    unsafe {
        ffi_native_invoke6(
            queue,
            abi::HYPER_NATIVE_OP_BLOCK_QUEUE_SUBMIT_WINDOW,
            token,
            u64::from(count),
            frame as u64,
            length as u64,
            0,
            0,
        )
    }
}
