// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Validated assignment metadata. Addresses describe guest resources, not host
//! mappings; inspection never grants additional device authority.

use super::Profile;
use crate::handle::{HandleRef, PhysicalDeviceObject};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileInfo {
    pub profile: Profile,
    pub interrupt_count: u32,
    pub resource_count: u32,
    /// PCI device identifier in bits 31:16 and vendor identifier in bits 15:0.
    /// Zero for a non-PCI profile.
    pub pci_identity: u32,
    pub dma_bus_offset: u64,
    pub aperture_size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceInfo {
    pub kind: u32,
    pub flags: u32,
    /// Offset within the complete assigned guest aperture.
    pub offset: u64,
    pub length: u64,
    /// Initial virtual PCI BAR address, zero for other resources.
    pub bus_address: u64,
}

pub fn profile_info(device: HandleRef<'_, PhysicalDeviceObject>) -> Result<ProfileInfo> {
    let mut record = hyper_abi::HyperNativeDeviceProfileInfo {
        profile: 0,
        interrupt_count: 0,
        resource_count: 0,
        pci_identity: 0,
        dma_bus_offset: 0,
        aperture_size: 0,
    };
    // SAFETY: The typed handle and initialized output remain live throughout the call.
    let result = unsafe {
        hyper_sys::device_profile_info(
            device.raw().get(),
            &mut record,
            core::mem::size_of_val(&record),
        )
    };
    crate::validate_info_result(result, hyper_abi::HYPER_NATIVE_DEVICE_PROFILE_INFO_MIN_SIZE)?;
    decode_profile(record)
}

fn decode_profile(record: hyper_abi::HyperNativeDeviceProfileInfo) -> Result<ProfileInfo> {
    let profile = match record.profile {
        1 => Profile::VirtioMmioScsi,
        2 => Profile::Userspace,
        3 => Profile::VirtioMmioNet,
        4 => Profile::PciFunction,
        _ => return Err(Error::InvalidResponse),
    };
    if record.resource_count == 0 || record.resource_count > 8 {
        return Err(Error::InvalidResponse);
    }
    if profile == Profile::PciFunction {
        let vendor = record.pci_identity & 0xffff;
        if !(1..=64).contains(&record.interrupt_count)
            || record.resource_count < 3
            || matches!(vendor, 0 | 0xffff)
            || record.aperture_size != hyper_abi::HYPER_NATIVE_DEVICE_PCI_APERTURE_SIZE
            || !record.dma_bus_offset.is_multiple_of(4096)
        {
            return Err(Error::InvalidResponse);
        }
    } else if !(record.interrupt_count == 1
        || (profile == Profile::Userspace && record.interrupt_count == 0))
        || record.pci_identity != 0
        || record.dma_bus_offset != 0
        || record.aperture_size != 65536
    {
        return Err(Error::InvalidResponse);
    }
    Ok(ProfileInfo {
        profile,
        interrupt_count: record.interrupt_count,
        resource_count: record.resource_count,
        pci_identity: record.pci_identity,
        dma_bus_offset: record.dma_bus_offset,
        aperture_size: record.aperture_size,
    })
}

pub fn resource_info(
    device: HandleRef<'_, PhysicalDeviceObject>,
    index: u32,
) -> Result<ResourceInfo> {
    let profile = profile_info(device)?;
    if index >= profile.resource_count {
        return Err(Error::Status(crate::Status::INVALID_ARGUMENT));
    }
    let mut record = hyper_abi::HyperNativeDeviceResourceInfo {
        kind: 0,
        flags: 0,
        offset: 0,
        length: 0,
        bus_address: 0,
    };
    // SAFETY: Typed handle and initialized output remain live throughout the call.
    let result = unsafe {
        hyper_sys::device_resource_info(
            device.raw().get(),
            index,
            &mut record,
            core::mem::size_of_val(&record),
        )
    };
    crate::validate_info_result(
        result,
        hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_INFO_MIN_SIZE,
    )?;
    decode_resource(profile, record)
}

fn decode_resource(
    profile: ProfileInfo,
    record: hyper_abi::HyperNativeDeviceResourceInfo,
) -> Result<ResourceInfo> {
    if record.length == 0
        || record
            .offset
            .checked_add(record.length)
            .is_none_or(|end| end > profile.aperture_size)
    {
        return Err(Error::InvalidResponse);
    }
    if profile.profile == Profile::PciFunction {
        match u64::from(record.kind) {
            hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_PCI_ECAM
                if record.offset == 0
                    && record.length == 0x10_0000
                    && record.flags == 0
                    && record.bus_address == 0 => {}
            hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_PCI_MSI
                if record.offset == 0x10_0000
                    && record.length == 4096
                    && record.flags == 0
                    && record.bus_address == 0 => {}
            kind if (hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_PCI_BAR0
                ..hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_PCI_BAR0 + 6)
                .contains(&kind) =>
            {
                let allowed = (hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_MEMORY_64
                    | hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_PREFETCHABLE)
                    as u32;
                if record.flags & !allowed != 0
                    || !record.length.is_power_of_two()
                    || record.length < 16
                    || record.offset < 0x20_0000
                    || !record.offset.is_multiple_of(record.length)
                    || record.bus_address != record.offset
                    || (record.flags & hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_MEMORY_64 as u32
                        != 0
                        && kind == hyper_abi::HYPER_NATIVE_DEVICE_RESOURCE_PCI_BAR0 + 5)
                {
                    return Err(Error::InvalidResponse);
                }
            }
            _ => return Err(Error::InvalidResponse),
        }
    } else if !(1..=8).contains(&record.kind) || record.flags != 0 || record.bus_address != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(ResourceInfo {
        kind: record.kind,
        flags: record.flags,
        offset: record.offset,
        length: record.length,
        bus_address: record.bus_address,
    })
}

#[cfg(test)]
#[path = "../../tests/device/profile.rs"]
mod tests;
