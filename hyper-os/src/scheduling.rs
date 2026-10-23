// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Per-thread scheduling configuration. Weight changes CPU share, while `band`
//! and role govern cross-policy arbitration. Raising treatment requires explicit
//! scheduling rights; ordinary WRITE and thread ownership do not imply them.

use crate::handle::{HandleRef, ThreadObject, VirtualCpuObject};
use crate::{Error, Result, Rights, Status};

/// Scheduling operations which can be independently attenuated on a handle.
pub const RIGHTS: Rights = Rights::SCHED_LOWER
    .union(Rights::SCHED_PRIORITY)
    .union(Rights::SCHED_CLASS)
    .union(Rights::SCHED_BUDGET);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Arbitration role, independent of the policy which accounts execution time.
pub enum Role {
    Ordinary,
    Priority,
    Protected,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// `Default` selects the kernel's compiled Fair backend on a configuration request.
/// Inspection always reports the concrete backend. The kernel admits one Fair
/// backend at a time; requesting the other explicit backend is invalid.
pub enum FairBackend {
    Stride,
    RoundRobin,
    Default,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Per-thread policy. Budgets are not shared quotas for a process or whole VM.
pub enum Policy {
    Fair {
        weight: u16,
        quantum_ns: u64,
        backend: FairBackend,
    },
    /// Work-conserving entitlement; this is not a hard real-time reservation.
    Budget {
        budget_ns: u64,
        period_ns: u64,
        burst_ns: u64,
    },
    Fifo {
        priority: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    pub policy: Policy,
    /// Smaller numbers have higher preference; band is not a CPU reservation.
    pub band: u8,
    pub role: Role,
}

impl Parameters {
    pub(crate) fn encode(self) -> Result<hyper_abi::HyperNativeSchedulingParameters> {
        let mut raw = ZERO;
        raw.band = u32::from(self.band).to_le();
        raw.role = match self.role {
            Role::Ordinary => 0_u32,
            Role::Priority => 1,
            Role::Protected => 2,
        }
        .to_le();
        match self.policy {
            Policy::Fair {
                weight,
                quantum_ns,
                backend,
            } => {
                if weight == 0 || weight > 1024 || quantum_ns == 0 || quantum_ns > 1_000_000_000 {
                    return invalid();
                }
                raw.policy = 1_u32.to_le();
                raw.weight = u32::from(weight).to_le();
                raw.quantum_ns = quantum_ns.to_le();
                raw.fair_backend = match backend {
                    FairBackend::Stride => 0_u32,
                    FairBackend::RoundRobin => 1,
                    FairBackend::Default => 2,
                }
                .to_le();
            }
            Policy::Budget {
                budget_ns,
                period_ns,
                burst_ns,
            } => {
                if period_ns == 0
                    || period_ns > 1_000_000_000
                    || budget_ns == 0
                    || budget_ns > period_ns
                    || burst_ns == 0
                    || burst_ns > period_ns
                {
                    return invalid();
                }
                raw.policy = 2_u32.to_le();
                raw.budget_ns = budget_ns.to_le();
                raw.period_ns = period_ns.to_le();
                raw.burst_ns = burst_ns.to_le();
            }
            Policy::Fifo { priority } => {
                raw.policy = 3_u32.to_le();
                raw.fifo_priority = u32::from(priority).to_le();
            }
        }
        Ok(raw)
    }
    fn decode(raw: hyper_abi::HyperNativeSchedulingParameters) -> Result<Self> {
        let role = match u32::from_le(raw.role) {
            0 => Role::Ordinary,
            1 => Role::Priority,
            2 => Role::Protected,
            _ => return Err(Error::InvalidResponse),
        };
        let band = u8::try_from(u32::from_le(raw.band)).map_err(|_| Error::InvalidResponse)?;
        let policy = match u32::from_le(raw.policy) {
            1 => Policy::Fair {
                weight: u16::try_from(u32::from_le(raw.weight))
                    .map_err(|_| Error::InvalidResponse)?,
                quantum_ns: u64::from_le(raw.quantum_ns),
                backend: match u32::from_le(raw.fair_backend) {
                    0 => FairBackend::Stride,
                    1 => FairBackend::RoundRobin,
                    _ => return Err(Error::InvalidResponse),
                },
            },
            2 => Policy::Budget {
                budget_ns: u64::from_le(raw.budget_ns),
                period_ns: u64::from_le(raw.period_ns),
                burst_ns: u64::from_le(raw.burst_ns),
            },
            3 => Policy::Fifo {
                priority: u8::try_from(u32::from_le(raw.fifo_priority))
                    .map_err(|_| Error::InvalidResponse)?,
            },
            _ => return Err(Error::InvalidResponse),
        };
        let result = Self { policy, band, role };
        if result.encode().map_err(|_| Error::InvalidResponse)? != raw {
            return Err(Error::InvalidResponse);
        }
        Ok(result)
    }
}
fn invalid<T>() -> Result<T> {
    Err(Error::Status(Status::INVALID_ARGUMENT))
}
const ZERO: hyper_abi::HyperNativeSchedulingParameters =
    hyper_abi::HyperNativeSchedulingParameters {
        policy: 0,
        band: 0,
        role: 0,
        weight: 0,
        fifo_priority: 0,
        fair_backend: 0,
        quantum_ns: 0,
        budget_ns: 0,
        period_ns: 0,
        burst_ns: 0,
        reserved: 0,
    };

/// Inspects the calling thread through its process-local execution context.
pub fn current() -> Result<Parameters> {
    let mut raw = ZERO;
    // SAFETY: the output record remains writable for the call.
    Status::from_raw(unsafe { hyper_sys::thread_get_current_scheduling(&mut raw) })
        .into_result()?;
    Parameters::decode(raw)
}
/// Atomically changes the calling thread within its immutable creation limits.
/// Ordinary processes receive `SCHED_LOWER`; raising priority or changing policy
/// requires the corresponding explicitly delegated scheduling rights.
pub fn set_current(parameters: Parameters) -> Result<()> {
    let raw = parameters.encode()?;
    // SAFETY: the input record remains readable for the call.
    Status::from_raw(unsafe { hyper_sys::thread_set_current_scheduling(&raw) }).into_result()
}
/// Inspects a thread using a handle carrying `INSPECT`.
pub fn thread(thread: HandleRef<'_, ThreadObject>) -> Result<Parameters> {
    let mut raw = ZERO;
    // SAFETY: the live handle and output are borrowed until return.
    Status::from_raw(unsafe { hyper_sys::thread_get_scheduling(thread.raw().get(), &mut raw) })
        .into_result()?;
    Parameters::decode(raw)
}
/// Applies a complete configuration using only this handle's scheduling rights.
/// Possessing `WRITE` does not grant scheduling authority.
pub fn set_thread(thread: HandleRef<'_, ThreadObject>, parameters: Parameters) -> Result<()> {
    let raw = parameters.encode()?;
    // SAFETY: the live handle and input are borrowed until return.
    Status::from_raw(unsafe { hyper_sys::thread_set_scheduling(thread.raw().get(), &raw) })
        .into_result()
}
/// Inspects the host thread which executes this vCPU; requires `INSPECT`.
pub fn vcpu(vcpu: HandleRef<'_, VirtualCpuObject>) -> Result<Parameters> {
    let mut raw = ZERO;
    // SAFETY: the live handle and output are borrowed until return.
    Status::from_raw(unsafe { hyper_sys::virtual_cpu_get_scheduling(vcpu.raw().get(), &mut raw) })
        .into_result()?;
    Parameters::decode(raw)
}
/// Configures a vCPU's host thread using scheduling rights derived from its VM
/// creation authority. Device names and guest identities confer no priority.
pub fn set_vcpu(vcpu: HandleRef<'_, VirtualCpuObject>, parameters: Parameters) -> Result<()> {
    let raw = parameters.encode()?;
    // SAFETY: the live handle and input are borrowed until return.
    Status::from_raw(unsafe { hyper_sys::virtual_cpu_set_scheduling(vcpu.raw().get(), &raw) })
        .into_result()
}

#[cfg(test)]
#[path = "../tests/scheduling/records.rs"]
mod tests;
