// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Runtime-allocated shared output and bounded guest input injection.

use crate::handle::{AnyObject, HandleRef, OwnedHandle, Rights, VirtualSerialObject};
use crate::{Error, Result, Status};

const _: () =
    assert!(hyper_abi::HYPER_NATIVE_VIRTUAL_SERIAL_MAX_TRANSFER_BYTES <= usize::MAX as u64);
/// Maximum byte prefix transferred by one virtual-serial operation.
pub const MAX_TRANSFER_BYTES: usize =
    hyper_abi::HYPER_NATIVE_VIRTUAL_SERIAL_MAX_TRANSFER_BYTES as usize;

/// Whole-page VMO size required by the output registration ABI.
pub const BUFFER_BYTES: u64 = hyper_abi::HYPER_NATIVE_VIRTUAL_SERIAL_OUTPUT_BYTES;

const FULL_RIGHTS: Rights = Rights::DUPLICATE
    .union(Rights::TRANSFER)
    .union(Rights::INSPECT)
    .union(Rights::WRITE)
    .union(Rights::READ)
    .union(Rights::WAIT)
    .union(Rights::ASSIGN_DEVICE);

/// Creates one unbound port; register output before assigning it to a VM.
pub fn create() -> Result<OwnedHandle<VirtualSerialObject>> {
    // SAFETY: the safe layer adopts the sole produced handle on success.
    let result = unsafe { hyper_sys::virtual_serial_create() };
    Status::from_raw(result.status).into_result()?;
    // SAFETY: an OK result transfers one new handle to the caller.
    let owner =
        unsafe { crate::handle::adopt_produced_handle_excluding::<AnyObject>(result.value0, &[])? };
    if owner.info()?.rights != FULL_RIGHTS {
        return Err(Error::InvalidResponse);
    }
    owner
        .downcast::<VirtualSerialObject>()
        .map_err(|failure| failure.error())
}

/// Registered shared output. Mapping ownership is private so safe callers cannot
/// unmap storage while a read is active. Output is mapped read-only; each
/// nonempty batch acknowledges consumption without a syscall data copy.
pub struct Output {
    serial: OwnedHandle<VirtualSerialObject>,
    region: Option<OwnedHandle<crate::handle::VmarObject>>,
    mapped: bool,
    address: usize,
    cursor: u64,
}

impl Output {
    /// Maps caller-allocated whole pages and registers them before VM binding.
    /// The VMAR reserves an unused range; overlaps are rejected, never replaced.
    pub fn register(
        serial: &OwnedHandle<VirtualSerialObject>,
        root: HandleRef<'_, crate::handle::VmarObject>,
        address: u64,
        memory: crate::memory::WritableVmo,
    ) -> Result<Self> {
        let output_owner = serial.duplicate(Rights::READ.union(Rights::WAIT))?;
        let serial = serial.as_handle_ref();
        let size = BUFFER_BYTES;
        if memory.size() != size
            || address == 0
            || !address.is_multiple_of(crate::memory::PAGE_SIZE)
            || address.checked_add(size).is_none()
        {
            return Err(Error::InvalidMemoryRange);
        }
        let base = usize::try_from(address).map_err(|_| Error::InvalidMemoryRange)?;
        // SAFETY: root remains borrowed; success reserves an exact unused region.
        let result = unsafe {
            hyper_sys::vmar_allocate(
                root.raw().get(),
                address,
                size,
                hyper_abi::HYPER_NATIVE_VMAR_ALLOCATE_EXACT,
            )
        };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: success transfers a fresh child VMAR owner.
        let region = unsafe {
            crate::handle::adopt_produced_handle_excluding::<crate::handle::VmarObject>(
                result.value0,
                &[root.raw(), memory.as_handle_ref().raw(), serial.raw()],
            )?
        };
        let region_raw = region.as_handle_ref().raw().get();
        let mut mapping = Self {
            serial: output_owner,
            region: Some(region),
            mapped: false,
            address: base,
            cursor: 0,
        };
        // SAFETY: this owner retains both the fresh region and caller's VMO;
        // the fixed layout fits completely within its page-aligned extent.
        Status::from_raw(unsafe {
            hyper_sys::vmar_map(
                region_raw,
                memory.as_handle_ref().raw().get(),
                0,
                address,
                size,
                hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_READ,
            )
        })
        .into_result()?;
        mapping.mapped = true;
        // SAFETY: no shared references have escaped and no consumer runs yet.
        // Registration pins the VMO and initializes counters before returning.
        Status::from_raw(unsafe {
            hyper_sys::virtual_serial_register_output(
                serial.raw().get(),
                memory.as_handle_ref().raw().get(),
            )
        })
        .into_result()?;
        Ok(mapping)
    }

    /// Copies a published prefix, then releases its slots to the producer.
    /// Returns zero immediately when no bytes are currently published.
    pub fn try_read(&mut self, output: &mut [u8]) -> Result<usize> {
        use core::sync::atomic::{AtomicU8, Ordering};
        let head = self.word(0).load(Ordering::Acquire);
        let count =
            head.saturating_sub(self.cursor)
                .min(output.len() as u64)
                .min(hyper_abi::HYPER_NATIVE_VIRTUAL_SERIAL_OUTPUT_CAPACITY) as usize;
        for (index, byte) in output[..count].iter_mut().enumerate() {
            let slot = (self.cursor + index as u64)
                % hyper_abi::HYPER_NATIVE_VIRTUAL_SERIAL_OUTPUT_CAPACITY;
            let address = self.address
                + hyper_abi::HYPER_NATIVE_VIRTUAL_SERIAL_OUTPUT_HEADER_BYTES as usize
                + slot as usize;
            // SAFETY: Output exclusively owns the consumer cursor; the kernel
            // cannot reuse these published slots before our release below.
            // The bounded offset stays in the registered data mapping. Atomic
            // byte accesses also tolerate an unsafe caller prematurely
            // acknowledging slots; no ordinary references to shared bytes escape.
            *byte = unsafe { &*core::ptr::with_exposed_provenance::<AtomicU8>(address) }
                .load(Ordering::Relaxed);
        }
        self.cursor += count as u64;
        if count != 0 {
            // SAFETY: the private handle identifies this registration. All
            // reads finish before the syscall releases slots to the producer.
            Status::from_raw(unsafe {
                hyper_sys::virtual_serial_acknowledge_output(
                    self.serial.as_handle_ref().raw().get(),
                    self.cursor,
                )
            })
            .into_result()?;
        }
        Ok(count)
    }

    /// Blocks without polling until a batch or end of stream is available.
    pub fn read(&mut self, output: &mut [u8]) -> Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            let count = self.try_read(output)?;
            if count != 0 {
                return Ok(count);
            }
            let observed = crate::wait::wait_many(&[self.wait_item()], crate::DEADLINE_INFINITE)?;
            if crate::wait::ObjectSignals::<VirtualSerialObject>::PEER_CLOSED
                .is_present_in(observed.observed)
            {
                return self.try_read(output);
            }
        }
    }

    #[must_use]
    pub fn wait_item(&self) -> crate::wait::WaitItem<'_> {
        crate::wait::WaitItem::new(
            self.serial.as_handle_ref(),
            crate::wait::ObjectSignals::<VirtualSerialObject>::READABLE
                .union(crate::wait::ObjectSignals::<VirtualSerialObject>::PEER_CLOSED),
        )
    }

    fn word(&self, offset: usize) -> &core::sync::atomic::AtomicU64 {
        // SAFETY: callers supply fixed, aligned ABI header offsets within the
        // registered VMO. Mapping lifetime is owned by self; all participants
        // access these words atomically.
        unsafe {
            &*core::ptr::with_exposed_provenance::<core::sync::atomic::AtomicU64>(
                self.address + offset,
            )
        }
    }

    #[must_use]
    pub fn lost_bytes(&self) -> u64 {
        self.word(8).load(core::sync::atomic::Ordering::Relaxed)
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        let Some(region) = self.region.take() else {
            return;
        };
        let raw = region.as_handle_ref().raw().get();
        if self.mapped {
            // SAFETY: Output exclusively owns this exact fixed mapping and no
            // references to its bytes escape. Kernel unmap joins translation
            // retirement before releasing backing; registration pins it separately.
            let status = unsafe { hyper_sys::vmar_unmap(raw, self.address as u64, BUFFER_BYTES) };
            if Status::from_raw(status).into_result().is_err() {
                // Leave a failed unmap owned by the process. Closing the region
                // handle cannot release still-reachable mappings or backing.
                return;
            }
        }
        // VMAR destruction accepts only an empty region and consumes its handle
        // on success. Do not let OwnedHandle close that consumed identity again.
        // SAFETY: this exact private region is empty after successful unmap, or
        // because register failed before installing any mapping.
        if Status::from_raw(unsafe { hyper_sys::vmar_destroy(raw) })
            .into_result()
            .is_ok()
        {
            let _ = region.into_raw();
        }
    }
}

fn checked_count(raw: u64, capacity: usize) -> Result<usize> {
    let count = usize::try_from(raw).map_err(|_| Error::InvalidResponse)?;
    if count <= capacity {
        Ok(count)
    } else {
        Err(Error::InvalidResponse)
    }
}

/// Injects one batch without waiting; runtimes must retain the unaccepted suffix.
pub fn try_write(serial: HandleRef<'_, VirtualSerialObject>, bytes: &[u8]) -> Result<usize> {
    let capacity = bytes.len().min(MAX_TRANSFER_BYTES);
    // SAFETY: the borrowed handle and source slice remain live during the call.
    let result =
        unsafe { hyper_sys::virtual_serial_write(serial.raw().get(), bytes.as_ptr(), capacity) };
    Status::from_raw(result.status).into_result()?;
    checked_count(result.value0, capacity)
}
