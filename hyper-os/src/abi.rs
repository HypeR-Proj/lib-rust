// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use crate::{Error, Result, Status};

/// Verifies the revision and baseline features required by safe SDK bindings.
pub fn require_core_abi() -> Result<()> {
    // SAFETY: every public `hyper-os` operation is meaningful only in a HypeR
    // Native process linked through the matching SDK runtime.
    let result = unsafe { hyper_sys::abi_query() };
    Status::from_raw(result.status).into_result()?;
    if result.value0 != hyper_abi::HYPER_NATIVE_ABI_REVISION
        || result.value1 & hyper_abi::HYPER_NATIVE_FEATURE_CORE == 0
    {
        return Err(Error::UnsupportedAbi {
            revision: result.value0,
            features: result.value1,
        });
    }
    Ok(())
}
