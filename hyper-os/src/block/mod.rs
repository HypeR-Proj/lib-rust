// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Native filesystem block initiator setup. Runtime policy negotiates the
//! Linux backend; the kernel owns subsequent virtio-scsi requests and waits.
//! Synchronous transfers use a persistent internal logical queue on the same
//! engine as explicit [`BlockQueue`] submissions and share device ordering.

mod queue;
pub use queue::{BlockQueue, Completion, QueueConfig, QueueInfo, ReadRequest, Ticket, WindowWrite};

use crate::handle::{
    AnyObject, GuestMemoryObject, HandleRef, NativeBlockObject, OwnedHandle, Rights,
    VirtualMachineObject,
};
use crate::{Error, Result, Status};

pub const RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::MAP)
    .union(Rights::TRANSFER)
    .union(Rights::INSPECT)
    .union(Rights::WAIT);
pub const PEER_CLOSED: u64 = hyper_abi::HYPER_NATIVE_SIGNAL_NATIVE_BLOCK_PEER_CLOSED;
pub const MEMORY_BYTES: u64 = hyper_abi::HYPER_NATIVE_NATIVE_BLOCK_MEMORY_BYTES;
pub const QUEUE_COUNT: usize = hyper_abi::HYPER_NATIVE_NATIVE_BLOCK_QUEUE_COUNT as usize;
pub const QUEUE_SIZE: u32 = hyper_abi::HYPER_NATIVE_NATIVE_BLOCK_QUEUE_SIZE as u32;
pub const QUEUE_STRIDE: u64 = hyper_abi::HYPER_NATIVE_NATIVE_BLOCK_QUEUE_STRIDE;
pub const AVAILABLE_OFFSET: u64 = hyper_abi::HYPER_NATIVE_NATIVE_BLOCK_AVAILABLE_OFFSET;
pub const USED_OFFSET: u64 = hyper_abi::HYPER_NATIVE_NATIVE_BLOCK_USED_OFFSET;

/// One disjoint complete-sector write in a bounded submission batch.
#[derive(Clone, Copy)]
pub struct WriteRequest<'a> {
    pub first: u64,
    pub bytes: &'a [u8],
}

/// Verified logical geometry and the kernel's immutable admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeInfo {
    pub sectors: u64,
    pub read_only: bool,
}

pub struct NativeBlock {
    handle: OwnedHandle<NativeBlockObject>,
}
impl NativeBlock {
    /// Dedicates an exactly `MEMORY_BYTES` resident grant to one initiator.
    /// Map that grant into the backend before installation. Queue addresses in
    /// ACTIVATE use `guest_base`; the Linux alias may have a different address.
    pub fn create(
        memory: HandleRef<'_, GuestMemoryObject>,
        backend: HandleRef<'_, VirtualMachineObject>,
        guest_base: u64,
        notification_base: u64,
        notification_irq: u32,
    ) -> Result<Self> {
        // SAFETY: Both capabilities stay borrowed for this non-retaining call.
        let result = unsafe {
            hyper_sys::native_block_create(
                memory.raw().get(),
                backend.raw().get(),
                guest_base,
                notification_base,
                notification_irq,
            )
        };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: A successful create returns an independently owned handle.
        let owner = unsafe {
            crate::handle::adopt_produced_handle_excluding::<AnyObject>(
                result.value0,
                &[memory.raw(), backend.raw()],
            )?
        };
        let rights = Rights::READ
            .union(Rights::WRITE)
            .union(Rights::MAP)
            .union(Rights::TRANSFER)
            .union(Rights::INSPECT)
            .union(Rights::WAIT);
        if result.value1 != 0 || owner.info()?.rights != rights {
            return Err(Error::InvalidResponse);
        }
        Ok(Self {
            handle: owner
                .downcast::<NativeBlockObject>()
                .map_err(|failure| failure.error())?,
        })
    }
    pub fn as_handle_ref(&self) -> HandleRef<'_, NativeBlockObject> {
        self.handle.as_handle_ref()
    }
    /// Call only after backend ACTIVATE succeeds. Returns verified 512-byte
    /// sector count, rather than trusting a userspace-supplied geometry.
    pub fn activate(&self, readonly: bool) -> Result<VolumeInfo> {
        // SAFETY: The block capability remains borrowed through discovery.
        let result = unsafe {
            hyper_sys::native_block_activate(self.handle.as_handle_ref().raw().get(), readonly)
        };
        Status::from_raw(result.status).into_result()?;
        if result.value0 == 0 || result.value1 > 1 {
            return Err(Error::InvalidResponse);
        }
        Ok(VolumeInfo {
            sectors: result.value0,
            read_only: result.value1 != 0,
        })
    }
    /// Adopts the exclusively transferred activated device.
    pub fn from_handle(handle: OwnedHandle<NativeBlockObject>) -> Self {
        Self { handle }
    }
    pub fn into_handle(self) -> OwnedHandle<NativeBlockObject> {
        self.handle
    }
    /// Creates an independently owned logical queue with bounded retained requests.
    /// The queue inherits only the parent rights allowed for block queues;
    /// closing this parent does not close an independently held derived queue.
    pub fn create_queue(&self, config: QueueConfig) -> Result<BlockQueue> {
        BlockQueue::create(self.as_handle_ref(), config)
    }
    pub fn read_sectors(&self, first: u64, bytes: &mut [u8]) -> Result<()> {
        self.transfer(0, first, bytes.as_mut_ptr(), bytes.len())
    }
    pub fn write_sectors(&self, first: u64, bytes: &[u8]) -> Result<()> {
        self.transfer(1, first, bytes.as_ptr().cast_mut(), bytes.len())
    }
    /// Submit at most four disjoint ranges, totaling at most 512 KiB. The
    /// kernel validates every range before issuing any writes; on I/O failure
    /// any subset may already have reached the medium.
    pub fn write_batch(&self, requests: &[WriteRequest<'_>]) -> Result<()> {
        let frame = encode_batch(requests)?;
        self.transfer(
            3,
            requests.len() as u64,
            frame.as_ptr().cast_mut(),
            frame.len(),
        )
    }
    pub fn flush(&self) -> Result<()> {
        self.transfer(2, 0, core::ptr::null_mut(), 0)
    }
    fn transfer(&self, operation: u32, first: u64, pointer: *mut u8, length: usize) -> Result<()> {
        let maximum = if operation == 3 {
            hyper_abi::HYPER_NATIVE_NATIVE_BLOCK_TRANSFER_FRAME_BYTES
        } else {
            hyper_abi::HYPER_NATIVE_NATIVE_BLOCK_TRANSFER_BYTES
        };
        if length as u64 > maximum || (operation != 3 && !length.is_multiple_of(512)) {
            return Err(Error::InvalidResponse);
        }
        // SAFETY: The private caller lends the operation-appropriate slice and
        // retains its borrow until this synchronous transfer completes.
        let result = unsafe {
            hyper_sys::native_block_transfer(
                self.handle.as_handle_ref().raw().get(),
                operation,
                first,
                pointer,
                length,
            )
        };
        Status::from_raw(result.status).into_result()?;
        if result.value0 != 0 || result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }
}

fn encode_batch(requests: &[WriteRequest<'_>]) -> Result<alloc::vec::Vec<u8>> {
    let invalid = || Error::Status(Status::INVALID_ARGUMENT);
    if requests.is_empty()
        || requests.len() > hyper_abi::HYPER_NATIVE_NATIVE_BLOCK_BATCH_MAX as usize
    {
        return Err(invalid());
    }
    let mut payload = 0usize;
    for request in requests {
        if !request.bytes.len().is_multiple_of(512) {
            return Err(invalid());
        }
        payload = payload
            .checked_add(request.bytes.len())
            .ok_or_else(invalid)?;
    }
    if payload > hyper_abi::HYPER_NATIVE_NATIVE_BLOCK_TRANSFER_BYTES as usize {
        return Err(invalid());
    }
    let header = requests.len() * hyper_abi::HYPER_NATIVE_NATIVE_BLOCK_BATCH_RECORD_BYTES as usize;
    let mut frame = alloc::vec::Vec::new();
    frame
        .try_reserve_exact(header + payload)
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_frame_retains_order_and_rejects_unbounded_input() -> Result<()> {
        let first = [0x11; 512];
        let second = [0x22; 1024];
        let frame = encode_batch(&[
            WriteRequest {
                first: 3,
                bytes: &first,
            },
            WriteRequest {
                first: 91,
                bytes: &second,
            },
        ])?;
        assert_eq!(&frame[..8], &3u64.to_le_bytes());
        assert_eq!(&frame[8..16], &512u64.to_le_bytes());
        assert_eq!(&frame[16..24], &91u64.to_le_bytes());
        assert_eq!(&frame[24..32], &1024u64.to_le_bytes());
        assert_eq!(&frame[32..544], &first);
        assert_eq!(&frame[544..], &second);
        assert!(encode_batch(&[]).is_err());
        assert!(
            encode_batch(
                &[WriteRequest {
                    first: 0,
                    bytes: &[]
                }; 5]
            )
            .is_err()
        );
        assert!(
            encode_batch(&[WriteRequest {
                first: 0,
                bytes: &[0]
            }])
            .is_err()
        );
        Ok(())
    }
}
