// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Filesystem server transport registration and owned shared-buffer mappings.
mod namespace;
pub use namespace::{begin_root_switch, finish_root_switch, mount_ramfs, switch_root};

use crate::{
    Error, Result, Status,
    handle::{ByteChannelObject, DirectoryObject, HandleRef, OwnedHandle, VmarObject, VmoObject},
    memory::WritableVmo,
};

/// Mount an ordered filesystem endpoint. Keep its handle alive for the mount's
/// entire lifetime; closure permanently disconnects that filesystem generation.
/// Both processes must implement the shared-buffer request ownership protocol.
pub fn mount(
    channel: HandleRef<'_, ByteChannelObject>,
    buffer: HandleRef<'_, VmoObject>,
    directory: HandleRef<'_, DirectoryObject>,
    path: &str,
    read_only: bool,
) -> Result<()> {
    // SAFETY: All borrowed capabilities and path bytes outlive this call.
    let result = unsafe {
        hyper_sys::filesystem_mount(
            channel.raw().get(),
            buffer.raw().get(),
            directory.raw().get(),
            path.as_ptr(),
            path.len(),
            read_only,
        )
    };
    Status::from_raw(result.status).into_result()?;
    if result.value0 != 0 || result.value1 != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}
/// Refuse active file/directory users, synchronize, then retire one mount.
/// No lazy or forced detach is supported; failure preserves the namespace edge.
pub fn unmount(directory: HandleRef<'_, DirectoryObject>, path: &str) -> Result<()> {
    // SAFETY: Capability and path are borrowed through the synchronous syscall.
    let result =
        unsafe { hyper_sys::filesystem_unmount(directory.raw().get(), path.as_ptr(), path.len()) };
    Status::from_raw(result.status).into_result()?;
    if result.value0 != 0 || result.value1 != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}
/// A fixed mapping owned independently of the root VMAR. Closing does not run
/// remote callbacks; final process teardown also retires failed unmap attempts.
pub struct SharedBuffer {
    memory: OwnedHandle<VmoObject>,
    region: OwnedHandle<VmarObject>,
    address: usize,
    size: usize,
    mapped: bool,
}
impl SharedBuffer {
    pub fn create(root: HandleRef<'_, VmarObject>, size: usize) -> Result<Self> {
        Self::from_memory(root, WritableVmo::create(size as u64)?.into_handle(), size)
    }

    /// Map an existing transport buffer without replacing its shared backing.
    /// The kernel checks the VMO extent and mapping rights before publication.
    pub fn from_memory(
        root: HandleRef<'_, VmarObject>,
        memory: OwnedHandle<VmoObject>,
        size: usize,
    ) -> Result<Self> {
        if size == 0
            || size > isize::MAX as usize
            || !size.is_multiple_of(crate::memory::PAGE_SIZE as usize)
        {
            return Err(Error::InvalidMemoryRange);
        }
        // SAFETY: Root is current process authority; zero hint asks the kernel
        // to reserve one free interval atomically rather than replacing mappings.
        let result = unsafe { hyper_sys::vmar_allocate(root.raw().get(), 0, size as u64, 0) };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: Successful creation returns one owned region disjoint from inputs.
        let region = unsafe {
            crate::handle::adopt_produced_handle_excluding::<VmarObject>(
                result.value0,
                &[root.raw(), memory.as_handle_ref().raw()],
            )?
        };
        let address = usize::try_from(result.value1).map_err(|_| Error::InvalidResponse)?;
        if address == 0 || address.checked_add(size).is_none() {
            return Err(Error::InvalidResponse);
        }
        let mut buffer = Self {
            memory,
            region,
            address,
            size,
            mapped: false,
        };
        // SAFETY: Fresh region and exact VMO extent are owned exclusively here.
        let result = unsafe {
            hyper_sys::vmar_map(
                buffer.region.as_handle_ref().raw().get(),
                buffer.memory.as_handle_ref().raw().get(),
                0,
                address as u64,
                size as u64,
                hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_READ
                    | hyper_abi::HYPER_NATIVE_VMAR_PERMISSION_WRITE,
            )
        };
        Status::from_raw(result).into_result()?;
        buffer.mapped = true;
        Ok(buffer)
    }
    pub fn memory(&self) -> &OwnedHandle<VmoObject> {
        &self.memory
    }
    /// # Safety
    /// The caller must own the shared-buffer protocol's producer/consumer phase;
    /// neither the peer nor any alias may access bytes until this borrow ends.
    pub unsafe fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: Mapping lives with self; caller proves cross-process ownership.
        unsafe { core::slice::from_raw_parts_mut(self.address as *mut u8, self.size) }
    }
}
impl Drop for SharedBuffer {
    fn drop(&mut self) {
        if self.mapped {
            // SAFETY: No outstanding borrow can survive &mut self destruction.
            let _ = unsafe {
                hyper_sys::vmar_unmap(
                    self.region.as_handle_ref().raw().get(),
                    self.address as u64,
                    self.size as u64,
                )
            };
        }
        // SAFETY: Owned child reservation is no longer used by this wrapper.
        let _ = unsafe { hyper_sys::vmar_destroy(self.region.as_handle_ref().raw().get()) };
    }
}
