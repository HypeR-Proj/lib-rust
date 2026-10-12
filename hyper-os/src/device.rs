// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Explicit authority to assign discovered physical devices to guest VMs.

use crate::handle::{
    DeviceAssignmentAuthorityObject, HandleRef, OwnedHandle, PendingVirtualMachineObject,
    PhysicalDeviceObject, Rights, VmoObject,
};
use crate::{Error, Result, Status};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    /// Virtio device identifier, or zero for a non-virtio device.
    pub device_id: u32,
    /// Virtio transport version, or zero when no kernel transport is identified.
    pub transport_version: u32,
    pub mmio_size: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaExtent {
    pub physical_base: u64,
    pub length: u64,
}

/// Claims one firmware-enumerated, unbound device. The index is a discovery
/// selector, never an arbitrary physical address or interrupt number.
pub fn claim(
    authority: HandleRef<'_, DeviceAssignmentAuthorityObject>,
    index: u32,
) -> Result<OwnedHandle<PhysicalDeviceObject>> {
    // SAFETY: Authority stays borrowed; the successful result transfers one owner.
    let result = unsafe { hyper_sys::device_claim(authority.raw().get(), index) };
    crate::guest_io::adopt_created(
        result,
        Rights::TRANSFER
            .union(Rights::DUPLICATE)
            .union(Rights::INSPECT)
            .union(Rights::WRITE),
        &[authority.raw()],
    )
}

/// Assignment profiles encode the kernel's validated device/reset contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Profile {
    VirtioMmioScsi = hyper_abi::HYPER_NATIVE_DEVICE_PROFILE_VIRTIO_MMIO_SCSI as u32,
    /// Register semantics and IRQ acknowledgement are owned by userspace.
    Userspace = hyper_abi::HYPER_NATIVE_DEVICE_PROFILE_USERSPACE as u32,
    VirtioMmioNet = hyper_abi::HYPER_NATIVE_DEVICE_PROFILE_VIRTIO_MMIO_NET as u32,
    /// One PCI function behind a mediated configuration space and MSI controller.
    PciFunction = hyper_abi::HYPER_NATIVE_DEVICE_PROFILE_PCI_FUNCTION as u32,
}

/// Maximum physical controllers assigned to one VM, sharing its DMA lifetime.
pub const MAX_ASSIGNED_DEVICES: usize =
    hyper_abi::HYPER_NATIVE_DEVICE_ASSIGNMENT_MAX_DEVICES as usize;

/// Resource kinds and attributes returned by device inspection.
pub const RESOURCE_PCI_ECAM: u32 = hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_PCI_ECAM as u32;
pub const RESOURCE_PCI_MSI: u32 = hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_PCI_MSI as u32;
pub const RESOURCE_PCI_BAR0: u32 = hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_PCI_BAR0 as u32;
pub const RESOURCE_MEMORY_64: u32 = hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_MEMORY_64 as u32;
pub const RESOURCE_PREFETCHABLE: u32 = hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_PREFETCHABLE as u32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareIdentity<'a> {
    Compatible(&'a str),
    FdtPath(&'a str),
    PciId { vendor: u16, device: u16 },
}

/// Claims a unique profile/firmware match. Ambiguous selectors fail instead of
/// falling back to a different device when the first match is already claimed.
pub fn claim_matching(
    authority: HandleRef<'_, DeviceAssignmentAuthorityObject>,
    profile: Profile,
    identity: FirmwareIdentity<'_>,
) -> Result<OwnedHandle<PhysicalDeviceObject>> {
    let pci_id;
    let (kind, text) = match identity {
        FirmwareIdentity::Compatible(text) => (
            hyper_abi::HYPER_NATIVE_DEVICE_IDENTITY_COMPATIBLE as u32,
            text,
        ),
        FirmwareIdentity::FdtPath(text) => (
            hyper_abi::HYPER_NATIVE_DEVICE_IDENTITY_FDT_PATH as u32,
            text,
        ),
        FirmwareIdentity::PciId { vendor, device } => {
            pci_id = encode_pci_identity(vendor, device);
            (
                hyper_abi::HYPER_NATIVE_DEVICE_IDENTITY_PCI_ID as u32,
                core::str::from_utf8(&pci_id).map_err(|_| Error::InvalidResponse)?,
            )
        }
    };
    // SAFETY: Authority and identity remain borrowed throughout this call.
    let result = unsafe {
        hyper_sys::device_claim_matching(
            authority.raw().get(),
            profile as u32,
            kind,
            text.as_ptr(),
            text.len(),
        )
    };
    crate::guest_io::adopt_created(
        result,
        Rights::TRANSFER
            .union(Rights::DUPLICATE)
            .union(Rights::INSPECT)
            .union(Rights::WRITE),
        &[authority.raw()],
    )
}

#[path = "device/profile.rs"]
mod profile;
pub use profile::{ProfileInfo, ResourceInfo, profile_info, resource_info};

fn encode_pci_identity(vendor: u16, device: u16) -> [u8; 9] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [b':'; 9];
    for (start, value) in [(0, vendor), (5, device)] {
        for digit in 0..4 {
            bytes[start + digit] = HEX[usize::from((value >> ((3 - digit) * 4)) & 15)];
        }
    }
    bytes
}

pub fn info(device: HandleRef<'_, PhysicalDeviceObject>) -> Result<Info> {
    let mut record = hyper_abi::HyperNativePhysicalDeviceInfo {
        device_id: 0,
        transport_version: 0,
        mmio_size: 0,
    };
    // SAFETY: The typed handle and initialized output are live throughout the call.
    let result = unsafe {
        hyper_sys::physical_device_info(
            device.raw().get(),
            &mut record,
            core::mem::size_of_val(&record),
        )
    };
    crate::validate_info_result(
        result,
        hyper_abi::HYPER_NATIVE_PHYSICAL_DEVICE_INFO_MIN_SIZE,
    )?;
    decode_info(record)
}

fn decode_info(record: hyper_abi::HyperNativePhysicalDeviceInfo) -> Result<Info> {
    if (record.device_id == 0 && record.transport_version != 0) || record.mmio_size == 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(Info {
        device_id: record.device_id,
        transport_version: record.transport_version,
        mmio_size: record.mmio_size,
    })
}

/// Inspects an already resident contiguous extent for constructing DMA metadata.
/// The caller must retain the VMO. This does not enable DMA or replace the
/// frozen guest-memory grants required when attaching a device to a VM.
pub fn dma_extent(
    authority: HandleRef<'_, DeviceAssignmentAuthorityObject>,
    vmo: HandleRef<'_, VmoObject>,
    offset: u64,
    length: u64,
) -> Result<DmaExtent> {
    let mut record = hyper_abi::HyperNativeDmaExtent {
        physical_base: 0,
        length: 0,
    };
    // SAFETY: Borrowed handles and the output record remain live for the call.
    let result = unsafe {
        hyper_sys::vmo_get_dma_extent(
            authority.raw().get(),
            vmo.raw().get(),
            offset,
            length,
            &mut record,
            core::mem::size_of_val(&record),
        )
    };
    crate::validate_info_result(result, hyper_abi::HYPER_NATIVE_DMA_EXTENT_MIN_SIZE)?;
    if record.length != length || length == 0 || record.physical_base.checked_add(length).is_none()
    {
        return Err(Error::InvalidResponse);
    }
    Ok(DmaExtent {
        physical_base: record.physical_base,
        length,
    })
}

/// Binds the claimed device before sealing a VM. `base` selects the inspected
/// aperture and `irq` the first of the inspected interrupt range. Non-PCI
/// assignments reserve one virtual interrupt even for a userspace profile with
/// no physical interrupt. The kernel retains DMA backing until hardware
/// quiescence is proven.
pub fn assign(
    pending: HandleRef<'_, PendingVirtualMachineObject>,
    device: HandleRef<'_, PhysicalDeviceObject>,
    base: u64,
    irq: u32,
) -> Result<()> {
    // SAFETY: Both handles stay borrowed; the remaining inputs are scalars.
    Status::from_raw(
        unsafe {
            hyper_sys::pending_virtual_machine_assign_device(
                pending.raw().get(),
                device.raw().get(),
                base,
                irq,
            )
        }
        .status,
    )
    .into_result()
}

#[path = "device/firmware.rs"]
mod firmware;
pub use firmware::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_identity_is_fixed_width_lowercase() {
        assert_eq!(encode_pci_identity(0x1de4, 1), *b"1de4:0001");
        assert_eq!(encode_pci_identity(0xffff, 0x10af), *b"ffff:10af");
    }

    #[test]
    fn device_info_accepts_userspace_and_virtio_identity() {
        for (device_id, transport_version) in [(0, 0), (8, 2)] {
            let expected = Info {
                device_id,
                transport_version,
                mmio_size: 65536,
            };
            assert_eq!(
                decode_info(hyper_abi::HyperNativePhysicalDeviceInfo {
                    device_id,
                    transport_version,
                    mmio_size: 65536,
                }),
                Ok(expected)
            );
        }
        for (device_id, transport_version, mmio_size) in [(0, 2, 65536), (0, 0, 0), (8, 2, 0)] {
            assert_eq!(
                decode_info(hyper_abi::HyperNativePhysicalDeviceInfo {
                    device_id,
                    transport_version,
                    mmio_size,
                }),
                Err(Error::InvalidResponse)
            );
        }
    }
}
