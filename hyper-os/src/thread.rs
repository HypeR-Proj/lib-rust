// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Native thread lifecycle and process-private atomic address waits.

use crate::handle::{AnyObject, HandleRef, OwnedHandle, ThreadObject};
use crate::{Result, Status};
use core::sync::atomic::AtomicU32;

/// Prepares a dormant thread inheriting the calling thread's CPU affinity.
///
/// # Safety
/// Entry must follow the Native function ABI and exit through `thread_exit`.
/// The caller owns a distinct valid stack and TLS area until TERMINATED, and
/// must preserve every value reached through the entry argument. Prefer
/// `std::thread` for language-level spawn and automatic resource reclamation.
pub unsafe fn create(
    entry: u64,
    stack: u64,
    tls: u64,
    argument: u64,
) -> Result<OwnedHandle<ThreadObject>> {
    // SAFETY: the caller supplies valid initial execution state; null/zero
    // requests a kernel snapshot of the calling thread's affinity.
    let result =
        unsafe { hyper_sys::thread_create(entry, stack, tls, argument, core::ptr::null(), 0) };
    adopt_thread(result)
}

/// Prepares a dormant thread with an explicit allowed CPU set. Bit N selects
/// logical CPU N. The kernel validates that the mask admits an available CPU.
///
/// # Safety
/// The entry, stack, TLS and argument have the same requirements as [`create`].
pub unsafe fn create_with_affinity(
    entry: u64,
    stack: u64,
    tls: u64,
    argument: u64,
    affinity: &[u64],
) -> Result<OwnedHandle<ThreadObject>> {
    let encoded = encode_affinity(affinity)?;
    // SAFETY: The caller supplies valid initial state. The bounded encoded
    // affinity is aligned and borrowed until the syscall has copied it.
    let result = unsafe {
        hyper_sys::thread_create(
            entry,
            stack,
            tls,
            argument,
            encoded.as_ptr(),
            affinity.len(),
        )
    };
    adopt_thread(result)
}

const AFFINITY_WORDS: usize = hyper_abi::HYPER_NATIVE_PROCESS_AFFINITY_MAX_WORDS as usize;

fn encode_affinity(words: &[u64]) -> Result<[u64; AFFINITY_WORDS]> {
    if words.is_empty() || words.len() > AFFINITY_WORDS || words.iter().all(|word| *word == 0) {
        return Err(crate::Error::Status(Status::INVALID_ARGUMENT));
    }
    let mut encoded = [0; AFFINITY_WORDS];
    for (output, word) in encoded.iter_mut().zip(words) {
        *output = word.to_le();
    }
    Ok(encoded)
}

fn adopt_thread(result: hyper_sys::CallResult) -> Result<OwnedHandle<ThreadObject>> {
    Status::from_raw(result.status).into_result()?;
    // SAFETY: success transfers one fresh handle.
    let owner =
        unsafe { crate::handle::adopt_produced_handle_excluding::<AnyObject>(result.value0, &[])? };
    owner
        .downcast::<ThreadObject>()
        .map_err(|failure| failure.error())
}

pub fn start(thread: HandleRef<'_, ThreadObject>) -> Result<()> {
    // SAFETY: the typed borrowed handle remains valid for this call.
    Status::from_raw(unsafe { hyper_sys::thread_start(thread.raw().get()) }).into_result()
}

/// Requests termination without executing language cleanup.
///
/// # Safety
/// The caller must tolerate abandonment of all target thread resources and
/// must not reclaim its stack or reachable state before observing TERMINATED.
pub unsafe fn request_stop(thread: HandleRef<'_, ThreadObject>) -> Result<()> {
    // SAFETY: the caller accepts asynchronous termination; the handle is live.
    Status::from_raw(unsafe { hyper_sys::thread_request_stop(thread.raw().get()) }).into_result()
}

/// Parks only if the aligned word still equals expected. Spurious wakes are
/// permitted. Deadline is absolute monotonic nanoseconds; `u64::MAX` is infinite.
/// Keep the mapping live until this call returns. A replacement mapping cannot
/// wake a waiter on the old mapping, even at the same virtual address.
pub fn atomic_wait(word: &AtomicU32, expected: u32, deadline: u64) -> Result<()> {
    // SAFETY: the borrowed AtomicU32 is aligned and live for the entire wait.
    Status::from_raw(unsafe { hyper_sys::atomic_wait(word.as_ptr(), expected, deadline) })
        .into_result()
}

/// Wakes at most count current waiters; wake does not publish ordinary data.
pub fn atomic_wake(word: &AtomicU32, count: u32) -> Result<u64> {
    // SAFETY: the borrowed AtomicU32 is aligned and live for the syscall.
    let result = unsafe { hyper_sys::atomic_wake(word.as_ptr(), count) };
    Status::from_raw(result.status).into_result()?;
    Ok(result.value0)
}

pub fn sleep_until(deadline: u64) -> Result<()> {
    // SAFETY: a scalar monotonic deadline carries no borrowed resources.
    Status::from_raw(unsafe { hyper_sys::thread_sleep(deadline) }).into_result()
}

/// Usable extent and reserved growth capacity of the current runtime stack.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StackInfo {
    pub base: usize,
    pub top: usize,
    pub size: usize,
    pub capacity: usize,
}

unsafe extern "C" {
    fn hyper_stack_current() -> *mut core::ffi::c_void;
    fn hyper_stack_get_info(stack: *mut core::ffi::c_void, info: *mut StackInfo) -> i64;
    fn hyper_stack_grow(stack: *mut core::ffi::c_void, size: usize) -> i64;
}

/// Queries the same guarded stack abstraction on main and SDK/std threads.
/// Raw Native threads without a runtime stack return an error.
pub fn current_stack() -> Result<StackInfo> {
    let mut info = StackInfo::default();
    // SAFETY: the borrowed descriptor stays live while this thread executes;
    // the output has the matching C layout and is exclusively borrowed.
    Status::from_raw(unsafe { hyper_stack_get_info(hyper_stack_current(), &mut info) })
        .into_result()?;
    Ok(info)
}

/// Extends the current stack downwards, within its reserved capacity.
///
/// Existing frames and the top address remain unchanged. Call with enough
/// headroom before entering a deeper workload; this is not automatic fault
/// growth. The size rounds up to pages; shrinking is rejected.
pub fn grow_current_stack(size: usize) -> Result<()> {
    // SAFETY: the current thread keeps its runtime descriptor alive. Growth
    // only adds disjoint mappings and never moves or unmaps existing frames.
    Status::from_raw(unsafe { hyper_stack_grow(hyper_stack_current(), size) }).into_result()
}
