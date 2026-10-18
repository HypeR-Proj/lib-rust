// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Non-consuming fault inspection through the existing device authority.

use crate::{
    Error, Result,
    handle::{HandleRef, PhysicalDeviceObject},
};
use hyper_abi as abi;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaFaultScope {
    Stream,
    Controller,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaFault {
    pub timestamp_ns: u64,
    pub stream_id: u32,
    pub scope: DmaFaultScope,
    /// `SMMUv3` event ID for a stream fault, captured GERROR bits for a controller
    /// failure. Zero GERROR bits are possible for software-detected failure.
    pub code: u32,
    /// Available only when the event identifies a DMA translation/access fault.
    pub address: Option<u64>,
    /// True is a device read from memory; false is a device write to memory.
    pub read: Option<bool>,
}

/// Requires `INSPECT | ASSIGN_DEVICE`. The first report survives handle transfer
/// and remains readable indefinitely. This neither clears `DMA_FAULT` nor
/// restores DMA. `None` means no report, not proof that a device is isolated.
pub fn dma_fault(device: HandleRef<'_, PhysicalDeviceObject>) -> Result<Option<DmaFault>> {
    let mut record = abi::HyperNativeDeviceDmaFaultInfo {
        timestamp_ns: 0,
        address: 0,
        stream_id: 0,
        source: 0,
        scope: 0,
        code: 0,
        flags: 0,
        reserved: 0,
    };
    // SAFETY: The typed borrowed handle and writable record outlive the call.
    let result = unsafe {
        hyper_sys::device_dma_fault_info(
            device.raw().get(),
            &mut record,
            core::mem::size_of_val(&record),
        )
    };
    crate::validate_info_result(result, abi::HYPER_NATIVE_DEVICE_DMA_FAULT_INFO_MIN_SIZE)?;
    decode(record)
}

fn decode(record: abi::HyperNativeDeviceDmaFaultInfo) -> Result<Option<DmaFault>> {
    if record.scope == 0 {
        return if record.timestamp_ns == 0
            && record.address == 0
            && record.stream_id == 0
            && record.source == 0
            && record.code == 0
            && record.flags == 0
            && record.reserved == 0
        {
            Ok(None)
        } else {
            Err(Error::InvalidResponse)
        };
    }
    let scope = match u64::from(record.scope) {
        abi::HYPER_NATIVE_DMA_FAULT_SCOPE_STREAM => DmaFaultScope::Stream,
        abi::HYPER_NATIVE_DMA_FAULT_SCOPE_CONTROLLER => DmaFaultScope::Controller,
        _ => return Err(Error::InvalidResponse),
    };
    if u64::from(record.source) != abi::HYPER_NATIVE_DMA_FAULT_SOURCE_SMMUV3 || record.reserved != 0
    {
        return Err(Error::InvalidResponse);
    }
    let (address, read) = match u64::from(record.flags) {
        0 if record.address == 0 => (None, None),
        flags
            if scope == DmaFaultScope::Stream
                && flags
                    == abi::HYPER_NATIVE_DMA_FAULT_ADDRESS_VALID
                        | abi::HYPER_NATIVE_DMA_FAULT_READ =>
        {
            (Some(record.address), Some(true))
        }
        flags
            if scope == DmaFaultScope::Stream
                && flags
                    == abi::HYPER_NATIVE_DMA_FAULT_ADDRESS_VALID
                        | abi::HYPER_NATIVE_DMA_FAULT_WRITE =>
        {
            (Some(record.address), Some(false))
        }
        _ => return Err(Error::InvalidResponse),
    };
    Ok(Some(DmaFault {
        timestamp_ns: record.timestamp_ns,
        stream_id: record.stream_id,
        scope,
        code: record.code,
        address,
        read,
    }))
}

#[cfg(test)]
#[path = "../../tests/device/fault.rs"]
mod tests;
