// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Physical-device claims, resources, firmware, MMIO, and IRQs.

use crate::ffi::ffi_native_call6;
use crate::{CallResult, abi};

/// Executes the Native `device_claim` operation.
///
/// # Safety
/// Retain all input handles and provide valid readable/writable pointer ranges
/// as specified by the Native ABI for the complete non-retaining call.
#[inline]
pub unsafe fn device_claim(authority: u64, index: u32) -> CallResult {
    // SAFETY: The caller establishes the ABI handle and memory contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DEVICE_CLAIM,
            authority,
            u64::from(index),
            0,
            0,
            0,
            0,
        )
    }
}

/// Claims exactly one device matching an explicit firmware identity and profile.
///
/// # Safety
/// The identity pointer must remain readable for `length` bytes during this call.
pub unsafe fn device_claim_matching(
    authority: u64,
    profile: u32,
    identity_kind: u32,
    identity: *const u8,
    length: usize,
) -> CallResult {
    // SAFETY: Caller retains the authority and readable identity bytes.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DEVICE_CLAIM_MATCHING,
            authority,
            u64::from(profile),
            u64::from(identity_kind),
            identity as u64,
            length as u64,
            0,
        )
    }
}

/// Queries the immutable validated assignment profile.
///
/// # Safety
/// Output must be writable for `size` bytes and the handle must stay live.
pub unsafe fn device_profile_info(
    device: u64,
    output: *mut abi::HyperNativeDeviceProfileInfo,
    size: usize,
) -> CallResult {
    // SAFETY: Caller establishes the handle and output buffer contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DEVICE_PROFILE_INFO,
            device,
            output as u64,
            size as u64,
            0,
            0,
            0,
        )
    }
}
/// Queries one named, guest-relative register window.
///
/// # Safety
/// Output must be writable for `size` bytes and the handle must stay live.
pub unsafe fn device_resource_info(
    device: u64,
    index: u32,
    output: *mut abi::HyperNativeDeviceResourceInfo,
    size: usize,
) -> CallResult {
    // SAFETY: Caller establishes the handle and output buffer contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DEVICE_RESOURCE_INFO,
            device,
            u64::from(index),
            output as u64,
            size as u64,
            0,
            0,
        )
    }
}

/// Executes the Native `physical_device_info` operation.
///
/// # Safety
/// Retain all input handles and provide valid readable/writable pointer ranges
/// as specified by the Native ABI for the complete non-retaining call.
#[inline]
pub unsafe fn physical_device_info(
    device: u64,
    output: *mut abi::HyperNativePhysicalDeviceInfo,
    size: usize,
) -> CallResult {
    // SAFETY: The caller establishes the ABI handle and memory contracts.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_PHYSICAL_DEVICE_INFO,
            device,
            output as u64,
            size as u64,
            0,
            0,
            0,
        )
    }
}

/// Executes the corresponding Native physical-device operation.
///
/// # Safety
/// Handles and pointer ranges must satisfy the Native ABI for the full call.
pub unsafe fn device_firmware_read(
    authority: u64,
    query: *const abi::HyperNativeDeviceFirmwareQuery,
    output: *mut u8,
    capacity: usize,
) -> CallResult {
    // SAFETY: the caller provides valid handles and complete memory ranges.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DEVICE_FIRMWARE_READ,
            authority,
            query as u64,
            output as u64,
            capacity as u64,
            0,
            0,
        )
    }
}

/// Executes the corresponding Native physical-device operation.
///
/// # Safety
/// Handles and pointer ranges must satisfy the Native ABI for the full call.
pub unsafe fn device_claim_bundle(
    authority: u64,
    entries: *const abi::HyperNativeDeviceBundleEntry,
    count: usize,
    irq_node: u32,
) -> CallResult {
    // SAFETY: the caller provides valid handles and complete memory ranges.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DEVICE_CLAIM_BUNDLE,
            authority,
            entries as u64,
            count as u64,
            u64::from(irq_node),
            0,
            0,
        )
    }
}

/// Executes the corresponding Native physical-device operation.
///
/// # Safety
/// Handles and pointer ranges must satisfy the Native ABI for the full call.
pub unsafe fn device_mmio(
    device: u64,
    offset: u64,
    width: u32,
    operation: u32,
    value: u64,
) -> CallResult {
    // SAFETY: the caller provides valid handles and complete memory ranges.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DEVICE_MMIO,
            device,
            offset,
            u64::from(width),
            u64::from(operation),
            value,
            0,
        )
    }
}

/// Executes the corresponding Native physical-device operation.
///
/// # Safety
/// Handles and pointer ranges must satisfy the Native ABI for the full call.
pub unsafe fn device_irq_pending(device: u64) -> CallResult {
    // SAFETY: the caller provides valid handles and complete memory ranges.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DEVICE_IRQ_PENDING,
            device,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

/// Executes the corresponding Native physical-device operation.
///
/// # Safety
/// Handles and pointer ranges must satisfy the Native ABI for the full call.
pub unsafe fn device_irq_complete(device: u64, sequence: u64, asserted: bool) -> CallResult {
    // SAFETY: the caller provides valid handles and complete memory ranges.
    unsafe {
        ffi_native_call6(
            abi::HYPER_NATIVE_SYS_DEVICE_IRQ_COMPLETE,
            device,
            sequence,
            u64::from(asserted),
            0,
            0,
            0,
        )
    }
}
