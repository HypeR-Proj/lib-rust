// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Opt-in system-wide PMU recording. Ordinary INSPECT handles cannot control
//! capture or read call chains. Kernel addresses are image-relative offsets.
use super::CpuInspector;
use crate::{Error, Result};
pub use hyper_abi::{
    HyperNativeCpuProfileInfo as ProfileInfo, HyperNativeCpuProfileSample as ProfileSample,
};

impl CpuInspector {
    /// Starts a global capture; fails BUSY while another capture is running.
    /// Sampling ends after seconds even if the controlling process exits.
    pub fn profile_start(&self, period: u64, seconds: u64) -> Result<u64> {
        // SAFETY: The typed inspector remains live throughout the invocation.
        let result = unsafe {
            hyper_sys::cpu_inspector_profile_start(
                self.handle.as_handle_ref().raw().get(),
                period,
                seconds,
            )
        };
        crate::Status::from_raw(result.status).into_result()?;
        let generation = result.value0;
        if generation == 0 || result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(generation)
    }
    /// Stop is requested even when BUSY is returned. Retry until acknowledged.
    pub fn profile_stop(&self, generation: u64) -> Result<()> {
        // SAFETY: The typed inspector remains live throughout the invocation.
        let result = unsafe {
            hyper_sys::cpu_inspector_profile_stop(
                self.handle.as_handle_ref().raw().get(),
                generation,
            )
        };
        crate::Status::from_raw(result.status).into_result()?;
        Ok(())
    }
    pub fn profile_info(&self) -> Result<ProfileInfo> {
        let mut value = ProfileInfo {
            generation: 0,
            period: 0,
            deadline_ns: 0,
            cpu_count: 0,
            running_generation: 0,
            armed_mask: 0,
            capacity: 0,
            depth: 0,
            active_cpus: 0,
            dropped: 0,
            revision: [0; 64],
        };
        // SAFETY: The ABI record is initialized, writable, and lives across the call.
        let result = unsafe {
            hyper_sys::cpu_inspector_profile_read(
                self.handle.as_handle_ref().raw().get(),
                0,
                u64::MAX,
                0,
                (&mut value as *mut ProfileInfo).cast(),
                core::mem::size_of::<ProfileInfo>(),
            )
        };
        crate::validate_info_result(result, core::mem::size_of::<ProfileInfo>())?;
        if value.cpu_count == 0 || value.cpu_count > 64 || value.depth != 16 {
            return Err(Error::InvalidResponse);
        }
        Ok(value)
    }
    /// Reads the first retained sequence >= cursor. A larger sequence exposes
    /// ring overwrite; `WOULD_BLOCK` means no sample is available at this cursor.
    pub fn profile_sample(&self, generation: u64, cpu: u64, cursor: u64) -> Result<ProfileSample> {
        let mut value = ProfileSample {
            sequence: 0,
            timestamp_ns: 0,
            cpu: 0,
            world: 0,
            depth: 0,
            flags: 0,
            dropped: 0,
            period: 0,
            frames: [0; 128],
        };
        // SAFETY: The ABI record is initialized, writable, and lives across the call.
        let result = unsafe {
            hyper_sys::cpu_inspector_profile_read(
                self.handle.as_handle_ref().raw().get(),
                generation,
                cpu,
                cursor,
                (&mut value as *mut ProfileSample).cast(),
                core::mem::size_of::<ProfileSample>(),
            )
        };
        crate::validate_info_result(result, core::mem::size_of::<ProfileSample>())?;
        if value.depth > 16 || value.world > 2 || value.cpu != cpu || value.sequence < cursor {
            return Err(Error::InvalidResponse);
        }
        Ok(value)
    }
}
