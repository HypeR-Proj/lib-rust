// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub const FIRMWARE_MAX_BYTES: usize = hyper_abi::HYPER_NATIVE_DEVICE_FIRMWARE_MAX_BYTES as usize;
pub const PROPERTY_NAME_MAX_BYTES: usize =
    hyper_abi::HYPER_NATIVE_DEVICE_FIRMWARE_NAME_MAX_BYTES as usize;
pub const BUNDLE_MAX_ENTRIES: usize = hyper_abi::HYPER_NATIVE_DEVICE_BUNDLE_MAX_ENTRIES as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FirmwareField {
    Info = hyper_abi::HYPER_NATIVE_DEVICE_FIRMWARE_FIELD_INFO as u32,
    Path = hyper_abi::HYPER_NATIVE_DEVICE_FIRMWARE_FIELD_PATH as u32,
    Compatible = hyper_abi::HYPER_NATIVE_DEVICE_FIRMWARE_FIELD_COMPATIBLE as u32,
    Registers = hyper_abi::HYPER_NATIVE_DEVICE_FIRMWARE_FIELD_REGISTERS as u32,
    Property = hyper_abi::HYPER_NATIVE_DEVICE_FIRMWARE_FIELD_PROPERTY as u32,
    /// NUL-separated property names from the immutable firmware snapshot.
    PropertyNames = hyper_abi::HYPER_NATIVE_DEVICE_FIRMWARE_FIELD_PROPERTY_NAMES as u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqTrigger {
    Level,
    Edge,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareInterrupt {
    pub number: u32,
    pub trigger: IrqTrigger,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareInfo {
    pub kernel_owned: bool,
    pub register_count: u32,
    pub interrupt: Option<FirmwareInterrupt>,
}
/// Firmware indices start at zero and are contiguous; `NOT_FOUND` ends enumeration.
/// Empty output queries the required size. Other successful calls return bytes
/// copied. Compatible is a NUL-separated list; registers are little-endian pairs
/// of u64 physical base and length. These are inspection data, not mapping rights.
pub fn firmware_read(
    authority: HandleRef<'_, DeviceAssignmentAuthorityObject>,
    node: u32,
    field: FirmwareField,
    name: &str,
    output: &mut [u8],
) -> Result<usize> {
    if output.len() > FIRMWARE_MAX_BYTES
        || name.len() > PROPERTY_NAME_MAX_BYTES
        || name.as_bytes().contains(&0)
        || (field == FirmwareField::Property) == name.is_empty()
    {
        return Err(Error::Status(Status::INVALID_ARGUMENT));
    }
    let query = hyper_abi::HyperNativeDeviceFirmwareQuery {
        node,
        field: field as u32,
        name_address: if name.is_empty() {
            0
        } else {
            name.as_ptr() as u64
        },
        name_length: name.len() as u64,
    };
    // SAFETY: immutable query/name and exclusive output remain borrowed for the call.
    let result = unsafe {
        hyper_sys::device_firmware_read(
            authority.raw().get(),
            &query,
            output.as_mut_ptr(),
            output.len(),
        )
    };
    let value = result_value(result)?;
    let length = usize::try_from(value).map_err(|_| Error::InvalidResponse)?;
    if length > FIRMWARE_MAX_BYTES || (!output.is_empty() && length > output.len()) {
        return Err(Error::InvalidResponse);
    }
    Ok(length)
}
pub fn firmware_info(
    authority: HandleRef<'_, DeviceAssignmentAuthorityObject>,
    node: u32,
) -> Result<FirmwareInfo> {
    let mut bytes = [0; 32];
    if firmware_read(authority, node, FirmwareField::Info, "", &mut bytes)? != bytes.len() {
        return Err(Error::InvalidResponse);
    }
    decode_info(&bytes)
}
fn decode_info(bytes: &[u8; 32]) -> Result<FirmwareInfo> {
    let word = |offset: usize| {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    };
    let flags = word(0);
    let interrupt = match word(12) {
        0 if word(8) == 0 => None,
        1 => Some(FirmwareInterrupt {
            number: word(8),
            trigger: IrqTrigger::Level,
        }),
        2 => Some(FirmwareInterrupt {
            number: word(8),
            trigger: IrqTrigger::Edge,
        }),
        _ => return Err(Error::InvalidResponse),
    };
    if flags & !1 != 0 || bytes[16..].iter().any(|byte| *byte != 0) {
        return Err(Error::InvalidResponse);
    }
    Ok(FirmwareInfo {
        kernel_owned: flags != 0,
        register_count: word(4),
        interrupt,
    })
}
/// Offsets select exact firmware resources inside the existing 64 KiB guest aperture.
pub type BundleEntry = hyper_abi::HyperNativeDeviceBundleEntry;
pub fn claim_bundle(
    authority: HandleRef<'_, DeviceAssignmentAuthorityObject>,
    entries: &[BundleEntry],
    irq_node: u32,
) -> Result<OwnedHandle<PhysicalDeviceObject>> {
    if entries.is_empty() || entries.len() > BUNDLE_MAX_ENTRIES {
        return Err(Error::Status(Status::INVALID_ARGUMENT));
    }
    // SAFETY: borrowed entries are valid and ownership is adopted only on success.
    let result = unsafe {
        hyper_sys::device_claim_bundle(
            authority.raw().get(),
            entries.as_ptr(),
            entries.len(),
            irq_node,
        )
    };
    crate::guest_io::adopt_created(
        result,
        Rights::TRANSFER
            .union(Rights::DUPLICATE)
            .union(Rights::INSPECT)
            .union(Rights::READ)
            .union(Rights::WRITE)
            .union(Rights::ASSIGN_DEVICE)
            .union(Rights::ACK_INTERRUPT)
            .union(Rights::WAIT),
        &[authority.raw()],
    )
}
fn result_value(result: hyper_sys::CallResult) -> Result<u64> {
    if result.status != 0 {
        return Err(Error::Status(Status::from_raw(result.status)));
    }
    if result.value1 != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(result.value0)
}
/// Reads require `READ` and an active assignment with retained DMA backing: even reads
/// may have device-specific side effects. Perform capability checks after install.
pub fn mmio_read(
    device: HandleRef<'_, PhysicalDeviceObject>,
    offset: u64,
    width: u32,
) -> Result<u64> {
    // SAFETY: typed capability stays live; kernel validates alignment/window/width.
    result_value(unsafe { hyper_sys::device_mmio(device.raw().get(), offset, width, 0, 0) })
}
/// Writes require `WRITE` and an active assignment with kernel-retained DMA backing.
pub fn mmio_write(
    device: HandleRef<'_, PhysicalDeviceObject>,
    offset: u64,
    width: u32,
    value: u64,
) -> Result<()> {
    // SAFETY: typed capability stays live; kernel enforces activation and bounds.
    if result_value(unsafe { hyper_sys::device_mmio(device.raw().get(), offset, width, 1, value) })?
        != 0
    {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}
/// Returns zero if idle, otherwise the sequence to use for IRQ completion.
pub fn irq_pending(device: HandleRef<'_, PhysicalDeviceObject>) -> Result<u64> {
    // SAFETY: the typed device remains borrowed for the call.
    result_value(unsafe { hyper_sys::device_irq_pending(device.raw().get()) })
}
/// Requires `ACK_INTERRUPT`. Updates the bound guest level.
/// False acknowledges/rearms the physical IRQ;
/// true retains its masked pending sequence but consumes READABLE notification.
/// The same sequence remains queryable for a later register-write resampling.
/// BUSY means reread the sequence.
/// Sequence zero is valid only while no physical IRQ is pending.
pub fn irq_complete(
    device: HandleRef<'_, PhysicalDeviceObject>,
    sequence: u64,
    asserted: bool,
) -> Result<()> {
    // SAFETY: the kernel validates sequence and bound assignment atomically.
    if result_value(unsafe {
        hyper_sys::device_irq_complete(device.raw().get(), sequence, asserted)
    })? != 0
    {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn firmware_info_rejects_unknown_flags_trigger_and_reserved_words() {
        let mut bytes = [0; 32];
        assert_eq!(
            decode_info(&bytes),
            Ok(FirmwareInfo {
                kernel_owned: false,
                register_count: 0,
                interrupt: None
            })
        );
        bytes[0] = 2;
        assert_eq!(decode_info(&bytes), Err(Error::InvalidResponse));
        bytes[0] = 0;
        bytes[12] = 3;
        assert_eq!(decode_info(&bytes), Err(Error::InvalidResponse));
        bytes[12] = 0;
        bytes[16] = 1;
        assert_eq!(decode_info(&bytes), Err(Error::InvalidResponse));
        bytes[16] = 0;
        bytes[8] = 33;
        bytes[12] = 1;
        assert_eq!(
            decode_info(&bytes).map(|info| info.interrupt),
            Ok(Some(FirmwareInterrupt {
                number: 33,
                trigger: IrqTrigger::Level
            }))
        );
    }
}
