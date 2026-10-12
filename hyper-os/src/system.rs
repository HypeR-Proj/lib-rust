// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Public scalar system configuration, independent of inspector capabilities.
use crate::{Error, Result, Status};

/// Queries a configuration key; unknown keys return the kernel's unsupported status.
pub fn config(key: u64) -> Result<u64> {
    // SAFETY: a scalar query has no borrowed memory or ownership transfer.
    let result = unsafe { hyper_sys::system_config(key) };
    Status::from_raw(result.status).into_result()?;
    if result.value1 != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(result.value0)
}

/// Returns the Native mapping granule, not a guest or device-protocol granule.
pub fn page_size() -> Result<u64> {
    let size = config(hyper_abi::HYPER_NATIVE_SYSTEM_CONFIG_PAGE_SIZE)?;
    if !size.is_power_of_two() || size < 16 || size > (usize::MAX / 2) as u64 {
        return Err(Error::InvalidResponse);
    }
    Ok(size)
}
