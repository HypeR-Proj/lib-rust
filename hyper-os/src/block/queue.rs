// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Bounded asynchronous block I/O with kernel-owned submission data.

use alloc::vec::Vec;
use core::num::NonZeroU64;

use super::WriteRequest;
use crate::handle::{
    BlockQueueObject, HandleRef, NativeBlockObject, OwnedHandle, Rights, VmoObject,
};
use crate::{Error, Result, Status};

/// Limits shared by every submitting thread holding this logical queue.
/// Device-wide and resource-domain limits remain in effect across all queues.
/// The initial device reserves one request and 512 KiB for synchronous pager
/// progress; public queues share at most 63 requests and 7.5 MiB of payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueConfig {
    /// Includes pending, in-flight and completed but unreaped batches.
    pub capacity: u32,
    /// Retained payload bytes, including completed reads awaiting reap.
    pub byte_limit: u64,
    /// Maximum physical commands from this queue allowed in flight together.
    /// The initial transport shares a 512 KiB payload pool among four command
    /// heads; a larger merged command may consume several 128 KiB data spans.
    pub inflight_limit: u32,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            capacity: 16,
            byte_limit: 2 * 1024 * 1024,
            inflight_limit: 4,
        }
    }
}

/// One complete-sector range in a scatter read. Reap concatenates ranges in this order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadRequest {
    pub first: u64,
    pub length: usize,
}

/// One complete-sector write referencing an active read-only staging window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowWrite {
    pub first: u64,
    pub offset: u64,
    pub bytes: u64,
}

/// Queue-local generation-qualified completion identity; it is not a capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Ticket(NonZeroU64);
impl Ticket {
    pub const fn get(self) -> u64 {
        self.0.get()
    }
    fn decode(raw: u64) -> Result<Self> {
        NonZeroU64::new(raw).map(Self).ok_or(Error::InvalidResponse)
    }
}

/// A durable terminal outcome. Waiting does not consume it; reaping does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    pub ticket: Ticket,
    /// Device outcome, separate from errors attempting to wait or reap.
    pub status: Status,
    /// Completed byte count reported by reap; wait leaves this field zero.
    pub bytes: usize,
}
impl Completion {
    pub fn result(self) -> Result<()> {
        self.status.into_result()
    }
}

/// One observation of limits, occupancy and command counters. Counters count
/// batches unless explicitly named ranges or commands; values can change
/// immediately after observation. No fields grant scheduling authority.
pub type QueueInfo = hyper_abi::HyperNativeBlockQueueInfo;

/// A logical queue with independently owned completions and bounded admission.
///
/// Ordinary write submission copies data before returning; window submissions
/// retain a validated kernel-owned source lease instead. Dropping a
/// ticket does not cancel I/O or release completion storage: reap it or close
/// the queue. Closing the queue never prematurely releases device DMA backing.
/// Queue and device credits are bounded independently of physical command slots.
/// Completed results retain credits, so producers waiting for more space must
/// reap their completions; `WRITABLE` conservatively budgets a full-size batch.
pub struct BlockQueue {
    handle: OwnedHandle<BlockQueueObject>,
}

impl BlockQueue {
    pub(super) fn create(
        block: HandleRef<'_, NativeBlockObject>,
        config: QueueConfig,
    ) -> Result<Self> {
        validate_config(config)?;
        // SAFETY: The block capability remains borrowed through derivation.
        let result = unsafe {
            hyper_sys::block_queue_create(
                block.raw().get(),
                config.capacity,
                config.byte_limit,
                config.inflight_limit,
            )
        };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: Successful derivation produces one independently owned capability.
        let handle = unsafe {
            crate::handle::adopt_produced_handle_excluding::<BlockQueueObject>(
                result.value0,
                &[block.raw()],
            )?
        };
        let allowed = Rights::READ
            .union(Rights::WRITE)
            .union(Rights::WAIT)
            .union(Rights::INSPECT)
            .union(Rights::TRANSFER);
        if result.value1 != 0
            || handle.info()?.rights.bits()
                != (block.info()?.rights.bits() & allowed.bits()) | Rights::DUPLICATE.bits()
        {
            return Err(Error::InvalidResponse);
        }
        Ok(Self { handle })
    }

    pub fn from_handle(handle: OwnedHandle<BlockQueueObject>) -> Self {
        Self { handle }
    }
    pub fn into_handle(self) -> OwnedHandle<BlockQueueObject> {
        self.handle
    }
    pub fn as_handle_ref(&self) -> HandleRef<'_, BlockQueueObject> {
        self.handle.as_handle_ref()
    }

    /// Map this queue's staging window read-only in a filesystem worker.
    pub fn create_window(&self) -> Result<OwnedHandle<VmoObject>> {
        self.as_handle_ref().create_window()
    }

    /// Submit ranges from a kernel-owned write lease. No payload bytes are
    /// serialized here; the kernel validates token identity and range bounds.
    pub fn submit_window(&self, token: u64, requests: &[WindowWrite]) -> Result<Ticket> {
        let invalid = || Error::Status(Status::INVALID_ARGUMENT);
        if token == 0 || requests.is_empty() || requests.len() > 16 {
            return Err(invalid());
        }
        let mut frame = [0u8; 384];
        let bytes = encode_window(requests, &mut frame)?;
        // SAFETY: The bounded initialized metadata frame and queue outlive the call.
        let result = unsafe {
            hyper_sys::block_queue_submit_window(
                self.handle.as_handle_ref().raw().get(),
                token,
                requests.len() as u32,
                frame.as_ptr(),
                bytes,
            )
        };
        Status::from_raw(result.status).into_result()?;
        if result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Ticket::decode(result.value0)
    }

    /// Submits a read whose storage is owned by the queue until reap.
    pub fn submit_read(&self, first: u64, length: usize) -> Result<Ticket> {
        validate_range(first, length)?;
        let mut frame = [0; 16];
        frame[..8].copy_from_slice(&first.to_le_bytes());
        frame[8..].copy_from_slice(&(length as u64).to_le_bytes());
        self.submit(0, 1, &frame)
    }

    /// Submits up to sixteen disjoint read ranges as one completion batch.
    pub fn submit_reads(&self, requests: &[ReadRequest]) -> Result<Ticket> {
        let invalid = || Error::Status(Status::INVALID_ARGUMENT);
        if requests.is_empty()
            || requests.len() > hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_BATCH_MAX as usize
        {
            return Err(invalid());
        }
        let mut frame = [0u8; 16 * hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_BATCH_MAX as usize];
        let mut total = 0usize;
        for (index, request) in requests.iter().enumerate() {
            validate_range(request.first, request.length)?;
            total = total.checked_add(request.length).ok_or_else(invalid)?;
            let end = request.first + (request.length / 512) as u64;
            for previous in &requests[..index] {
                let previous_end = previous.first + (previous.length / 512) as u64;
                if request.first < previous_end && previous.first < end {
                    return Err(invalid());
                }
            }
            frame[index * 16..index * 16 + 8].copy_from_slice(&request.first.to_le_bytes());
            frame[index * 16 + 8..index * 16 + 16]
                .copy_from_slice(&(request.length as u64).to_le_bytes());
        }
        if total > hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_TRANSFER_BYTES as usize {
            return Err(invalid());
        }
        self.submit(0, requests.len() as u32, &frame[..requests.len() * 16])
    }

    pub fn submit_write(&self, first: u64, bytes: &[u8]) -> Result<Ticket> {
        self.submit_writes(&[WriteRequest { first, bytes }])
    }

    /// Atomically admits up to sixteen disjoint ranges totaling at most 512 KiB.
    /// On `WOULD_BLOCK` nothing was submitted. Failed completed I/O may have
    /// partial device effects; completion is aggregate, not a rollback promise.
    pub fn submit_writes(&self, requests: &[WriteRequest<'_>]) -> Result<Ticket> {
        let frame = encode_writes(requests)?;
        self.submit(1, requests.len() as u32, &frame)
    }

    /// Places a device-wide ordering and durability fence after earlier work.
    pub fn submit_flush(&self) -> Result<Ticket> {
        self.submit(2, 0, &[])
    }

    fn submit(&self, operation: u32, count: u32, frame: &[u8]) -> Result<Ticket> {
        // SAFETY: This immutable frame and capability stay borrowed until the
        // kernel has copied the input; no user pointer survives the invocation.
        let result = unsafe {
            hyper_sys::block_queue_submit(
                self.as_handle_ref().raw().get(),
                operation,
                count,
                if frame.is_empty() {
                    core::ptr::null()
                } else {
                    frame.as_ptr()
                },
                frame.len(),
            )
        };
        Status::from_raw(result.status).into_result()?;
        if result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Ticket::decode(result.value0)
    }

    /// Observes a particular completion without consuming it. The deadline is
    /// absolute monotonic nanoseconds; `u64::MAX` waits indefinitely and zero polls.
    /// Timeout/cancellation stops waiting but does not cancel submitted device I/O.
    pub fn wait(&self, ticket: Ticket, deadline: u64) -> Result<Completion> {
        let completion = self.wait_raw(ticket.get(), deadline)?;
        if completion.ticket != ticket {
            return Err(Error::InvalidResponse);
        }
        Ok(completion)
    }

    /// Waits for any completed ticket. Multiple observers may see the same
    /// result; only one reaper consumes it. Use this to refill without waiting
    /// for the oldest, potentially slower request.
    pub fn wait_any(&self, deadline: u64) -> Result<Completion> {
        self.wait_raw(0, deadline)
    }

    fn wait_raw(&self, ticket: u64, deadline: u64) -> Result<Completion> {
        // SAFETY: The capability stays borrowed throughout the wait.
        let result = unsafe {
            hyper_sys::block_queue_wait(self.as_handle_ref().raw().get(), ticket, deadline)
        };
        Status::from_raw(result.status).into_result()?;
        Ok(Completion {
            ticket: Ticket::decode(result.value0)?,
            status: decode_completion_status(result.value1)?,
            bytes: 0,
        })
    }

    /// Waits for one admission slot and exactly `bytes` of available payload
    /// budget on both this queue and its device. Zero bytes supports flush;
    /// other sizes must be complete sectors and fit the queue's byte limit and
    /// the 512 KiB submission bound. Success reserves nothing: retry submission
    /// after waking. Resource-domain quota and allocation can still fail.
    ///
    /// Reap this queue's completed requests before waiting if they retain the
    /// required credits. The absolute monotonic deadline is in nanoseconds;
    /// zero polls and `u64::MAX` waits indefinitely. No request is submitted or
    /// cancelled by this call.
    pub fn wait_space(&self, bytes: usize, deadline: u64) -> Result<()> {
        if !bytes.is_multiple_of(512)
            || bytes > hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_TRANSFER_BYTES as usize
        {
            return Err(Error::Status(Status::INVALID_ARGUMENT));
        }
        // SAFETY: The queue capability remains borrowed throughout the wait.
        let result = unsafe {
            hyper_sys::block_queue_wait_space(self.as_handle_ref().raw().get(), bytes, deadline)
        };
        Status::from_raw(result.status).into_result()?;
        if result.value0 != 0 || result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }

    /// Consumes a completed result after a successful output copy. Reads require
    /// their exact submitted length; failed reads, writes and flush use `&mut []`.
    /// A faulting/invalid output leaves the result available for retry.
    pub fn reap(&self, ticket: Ticket, output: &mut [u8]) -> Result<Completion> {
        if output.len() > hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_TRANSFER_BYTES as usize {
            return Err(Error::Status(Status::INVALID_ARGUMENT));
        }
        // SAFETY: The output and capability remain borrowed for the whole copy.
        let result = unsafe {
            hyper_sys::block_queue_reap(
                self.as_handle_ref().raw().get(),
                ticket.get(),
                if output.is_empty() {
                    core::ptr::null_mut()
                } else {
                    output.as_mut_ptr()
                },
                output.len(),
            )
        };
        Status::from_raw(result.status).into_result()?;
        let bytes = usize::try_from(result.value1).map_err(|_| Error::InvalidResponse)?;
        if bytes > hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_TRANSFER_BYTES as usize {
            return Err(Error::InvalidResponse);
        }
        Ok(Completion {
            ticket,
            status: decode_completion_status(result.value0)?,
            bytes,
        })
    }

    pub fn info(&self) -> Result<QueueInfo> {
        let mut info = QueueInfo {
            capacity: 0,
            byte_limit: 0,
            inflight_limit: 0,
            outstanding_requests: 0,
            outstanding_bytes: 0,
            pending_requests: 0,
            inflight_commands: 0,
            completed_requests: 0,
            submitted_batches: 0,
            submitted_ranges: 0,
            dispatched_commands: 0,
            merged_ranges: 0,
            completed_batches: 0,
            peak_inflight: 0,
            device_inflight_limit: 0,
            reserved: 0,
        };
        let size = core::mem::size_of::<QueueInfo>();
        // SAFETY: The initialized record remains exclusively writable for the call.
        let result = unsafe {
            hyper_sys::block_queue_info(self.as_handle_ref().raw().get(), &mut info, size)
        };
        Status::from_raw(result.status).into_result()?;
        if result.value0 != size as u64 || result.value1 != 0 || info.reserved != 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(info)
    }
}

fn decode_completion_status(raw: u64) -> Result<Status> {
    let status = raw as i64;
    if status > 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(Status::from_raw(status))
}

/// Validate the metadata frame independently of syscall dispatch. It never
/// reads bytes from the mapping or creates a second payload allocation.
fn encode_window(requests: &[WindowWrite], frame: &mut [u8; 384]) -> Result<usize> {
    let invalid = || Error::Status(Status::INVALID_ARGUMENT);
    if requests.is_empty() || requests.len() > 16 {
        return Err(invalid());
    }
    let mut total = 0usize;
    for (index, request) in requests.iter().enumerate() {
        let length = usize::try_from(request.bytes).map_err(|_| invalid())?;
        validate_range(request.first, length)?;
        request
            .offset
            .checked_add(request.bytes)
            .filter(|end| *end <= hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_WINDOW_BYTES)
            .ok_or_else(invalid)?;
        total = total
            .checked_add(length)
            .filter(|total| *total <= hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_TRANSFER_BYTES as usize)
            .ok_or_else(invalid)?;
        let at = index * 24;
        frame[at..at + 8].copy_from_slice(&request.first.to_le_bytes());
        frame[at + 8..at + 16].copy_from_slice(&request.offset.to_le_bytes());
        frame[at + 16..at + 24].copy_from_slice(&request.bytes.to_le_bytes());
    }
    Ok(requests.len() * 24)
}

fn validate_config(config: QueueConfig) -> Result<()> {
    if config.capacity == 0
        || u64::from(config.capacity) > hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_CAPACITY_MAX
        || config.byte_limit < 512
        || config.byte_limit > hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_BYTE_LIMIT_MAX
        || config.inflight_limit == 0
        || u64::from(config.inflight_limit) > hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_INFLIGHT_MAX
    {
        return Err(Error::Status(Status::INVALID_ARGUMENT));
    }
    Ok(())
}

fn validate_range(first: u64, length: usize) -> Result<()> {
    if length == 0
        || !length.is_multiple_of(512)
        || length > hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_TRANSFER_BYTES as usize
        || first.checked_add((length / 512) as u64).is_none()
    {
        return Err(Error::Status(Status::INVALID_ARGUMENT));
    }
    Ok(())
}

fn encode_writes(requests: &[WriteRequest<'_>]) -> Result<Vec<u8>> {
    let invalid = || Error::Status(Status::INVALID_ARGUMENT);
    if requests.is_empty()
        || requests.len() > hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_BATCH_MAX as usize
    {
        return Err(invalid());
    }
    let mut total = 0usize;
    for (index, request) in requests.iter().enumerate() {
        validate_range(request.first, request.bytes.len())?;
        total = total.checked_add(request.bytes.len()).ok_or_else(invalid)?;
        let end = request.first + (request.bytes.len() / 512) as u64;
        for previous in &requests[..index] {
            let previous_end = previous.first + (previous.bytes.len() / 512) as u64;
            if request.first < previous_end && previous.first < end {
                return Err(invalid());
            }
        }
    }
    if total > hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_TRANSFER_BYTES as usize {
        return Err(invalid());
    }
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(requests.len() * 16 + total)
        .map_err(|_| Error::Status(Status::NO_MEMORY))?;
    for request in requests {
        frame.extend_from_slice(&request.first.to_le_bytes());
        frame.extend_from_slice(&(request.bytes.len() as u64).to_le_bytes());
    }
    for request in requests {
        frame.extend_from_slice(request.bytes);
    }
    Ok(frame)
}

impl HandleRef<'_, BlockQueueObject> {
    /// Obtain a read-only VMO for the queue-owned Native staging window.
    pub fn create_window(self) -> Result<OwnedHandle<VmoObject>> {
        // SAFETY: This handle is borrowed for the complete call.
        let result = unsafe { hyper_sys::block_queue_create_window(self.raw().get()) };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: Successful creation returns one owned capability.
        let handle = unsafe {
            crate::handle::adopt_produced_handle_excluding::<VmoObject>(
                result.value0,
                &[self.raw()],
            )?
        };
        let expected = Rights::READ
            .union(Rights::MAP)
            .union(Rights::DUPLICATE)
            .union(Rights::TRANSFER)
            .union(Rights::INSPECT);
        if result.value1 != 0 || handle.info()?.rights != expected {
            return Err(Error::InvalidResponse);
        }
        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_encode_owned_payload_and_reject_overlap() -> Result<()> {
        let a = [0x13; 512];
        let b = [0x29; 1024];
        let frame = encode_writes(&[
            WriteRequest {
                first: 7,
                bytes: &a,
            },
            WriteRequest {
                first: 8,
                bytes: &b,
            },
        ])?;
        assert_eq!(frame.len(), 32 + 1536);
        assert_eq!(&frame[..8], &7u64.to_le_bytes());
        assert_eq!(&frame[32..544], &a);
        assert_eq!(&frame[544..], &b);
        assert!(
            encode_writes(&[
                WriteRequest {
                    first: 7,
                    bytes: &b
                },
                WriteRequest {
                    first: 8,
                    bytes: &a
                }
            ])
            .is_err()
        );
        assert!(encode_writes(&[]).is_err());
        assert!(
            encode_writes(&[WriteRequest {
                first: 0,
                bytes: &[]
            }])
            .is_err()
        );
        assert!(
            encode_writes(&[WriteRequest {
                first: u64::MAX,
                bytes: &a
            }])
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn window_frames_carry_only_bounds_checked_metadata() -> Result<()> {
        let mut frame = [0xa5; 384];
        let request = WindowWrite {
            first: 71,
            offset: 17,
            bytes: 1024,
        };
        assert_eq!(encode_window(&[request], &mut frame)?, 24);
        assert_eq!(&frame[..8], &71u64.to_le_bytes());
        assert_eq!(&frame[8..16], &17u64.to_le_bytes());
        assert_eq!(&frame[16..24], &1024u64.to_le_bytes());
        assert!(frame[24..].iter().all(|byte| *byte == 0xa5));
        assert!(
            encode_window(
                &[WindowWrite {
                    offset: u64::MAX,
                    ..request
                }],
                &mut frame
            )
            .is_err()
        );
        assert!(
            encode_window(
                &[WindowWrite {
                    bytes: 513,
                    ..request
                }],
                &mut frame
            )
            .is_err()
        );
        assert!(
            encode_window(
                &[WindowWrite {
                    offset: hyper_abi::HYPER_NATIVE_BLOCK_QUEUE_WINDOW_BYTES,
                    ..request
                }],
                &mut frame
            )
            .is_err()
        );
        assert!(encode_window(&[request; 17], &mut frame).is_err());
        Ok(())
    }

    #[test]
    fn queue_bounds_and_response_namespace_are_explicit() -> Result<()> {
        validate_config(QueueConfig::default())?;
        assert!(
            validate_config(QueueConfig {
                capacity: 0,
                ..QueueConfig::default()
            })
            .is_err()
        );
        assert!(
            validate_config(QueueConfig {
                byte_limit: u64::MAX,
                ..QueueConfig::default()
            })
            .is_err()
        );
        assert!(
            validate_config(QueueConfig {
                inflight_limit: 5,
                ..QueueConfig::default()
            })
            .is_err()
        );
        assert!(Ticket::decode(0).is_err());
        assert!(decode_completion_status(1).is_err());
        assert_eq!(
            decode_completion_status(Status::IO_ERROR.as_raw() as u64)?,
            Status::IO_ERROR
        );
        Ok(())
    }
}
