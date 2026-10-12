// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Object-local snapshots gated by `INSPECT | INSPECT_DETAILS`.
//! Multi-record reads are weakly consistent; handles and KOIDs retain their
//! generations, but mappings can change between records.

use super::{Koid, ObjectInspector, ObjectKind, ThreadRole};
use crate::handle::{
    ByteChannelObject, CapabilityChannelObject, PhysicalDeviceObject, ThreadObject, TypedObject,
    VmarObject,
};
use crate::{Error, Result};
use core::num::NonZeroU64;
use hyper_abi as abi;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetailTarget {
    Object(Koid),
    Handle { process: Koid, handle: NonZeroU64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetailCursor(u64);
impl DetailCursor {
    pub const START: Self = Self(0);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectDetails {
    pub koid: Koid,
    pub object_kind: ObjectKind,
    pub record: DetailRecord,
    pub next: Option<DetailCursor>,
}

/// Mapping protection bits, distinct from capability rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPermissions(u8);
impl MappingPermissions {
    pub const fn readable(self) -> bool {
        self.0 & 1 != 0
    }
    pub const fn writable(self) -> bool {
        self.0 & 2 != 0
    }
    pub const fn executable(self) -> bool {
        self.0 & 4 != 0
    }
    fn decode(raw: u64) -> Result<Self> {
        if raw > 7 {
            return Err(Error::InvalidResponse);
        }
        Ok(Self(raw as u8))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserThreadPhase {
    Prepared,
    Dormant,
    Runnable,
    StopRequested,
    Detached,
}
impl UserThreadPhase {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Dormant => "dormant",
            Self::Runnable => "runnable",
            Self::StopRequested => "stop-requested",
            Self::Detached => "detached",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetailRecord {
    Empty,
    Thread {
        tid: Option<u64>,
        role: ThreadRole,
        phase: Option<UserThreadPhase>,
    },
    Vmar {
        base: u64,
        length: u64,
        live: bool,
    },
    Mapping {
        base: u64,
        length: u64,
        permissions: MappingPermissions,
        maximum_permissions: MappingPermissions,
    },
    Channel {
        peer: Option<Koid>,
        local_open: bool,
        peer_open: bool,
        queued: u64,
        bytes: u64,
        byte_queue: bool,
    },
    Device {
        profile: u32,
        device_id: u32,
        pci_identity: u32,
        irq_domain: u32,
        interrupt: u32,
        interrupt_count: u32,
        state: DeviceState,
        resource_count: u64,
    },
    DeviceResource {
        kind: u32,
        base: u64,
        length: u64,
        offset: u64,
        flags: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceState {
    Claimed,
    Attached,
    Active,
    Retired,
    Quarantined,
}
impl DeviceState {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Attached => "attached",
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Quarantined => "quarantined",
        }
    }
}

impl ObjectInspector {
    /// Reads one bounded detail record. Global KOID lookup requires system
    /// scope; handle lookup checks the containing process against the scope.
    /// Derived inspectors retain basic INSPECT only. Details never grant
    /// operational authority over the selected object.
    pub fn read_details(
        &self,
        target: DetailTarget,
        cursor: DetailCursor,
    ) -> Result<ObjectDetails> {
        let (process, value) = match target {
            DetailTarget::Object(koid) => (0, koid.get()),
            DetailTarget::Handle { process, handle } => (process.get(), handle.get()),
        };
        let mut record = abi::HyperNativeObjectDetails {
            koid: 0,
            object_kind: 0,
            record_kind: 0,
            next_cursor: 0,
            payload: [0; 64],
        };
        // SAFETY: the inspector remains borrowed and record is a complete,
        // writable ABI output. The kernel validates both diagnostic selectors.
        let result = unsafe {
            hyper_sys::object_inspector_read_details(
                self.handle.as_handle_ref().raw().get(),
                process,
                value,
                cursor.0,
                &mut record,
            )
        };
        crate::validate_info_result(result, abi::HYPER_NATIVE_OBJECT_DETAILS_MIN_SIZE)?;
        let details = decode(&record, cursor)?;
        if let DetailTarget::Object(expected) = target
            && details.koid != expected
        {
            return Err(Error::InvalidResponse);
        }
        Ok(details)
    }
}

fn word32(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::InvalidResponse)
}
fn boolean(value: u64) -> Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::InvalidResponse),
    }
}
fn range(base: u64, length: u64) -> Result<()> {
    if length == 0 || base.checked_add(length).is_none() {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}

fn decode(raw: &abi::HyperNativeObjectDetails, cursor: DetailCursor) -> Result<ObjectDetails> {
    let koid = Koid::from_raw(raw.koid)?;
    let kind = ObjectKind::from_kernel(raw.object_kind)?;
    if raw.next_cursor != 0 && raw.next_cursor <= cursor.0 {
        return Err(Error::InvalidResponse);
    }
    let mut w = [0u64; 8];
    for (word, chunk) in w.iter_mut().zip(raw.payload.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().map_err(|_| Error::InvalidResponse)?);
    }
    let (record, used) = match u64::from(raw.record_kind) {
        abi::HYPER_NATIVE_OBJECT_DETAIL_EMPTY if kind == VmarObject::KIND => {
            (DetailRecord::Empty, 0)
        }
        abi::HYPER_NATIVE_OBJECT_DETAIL_THREAD if kind == ThreadObject::KIND => {
            let role = ThreadRole::decode(word32(w[1])?)?;
            let phase = match w[2] {
                0 => None,
                1 => Some(UserThreadPhase::Prepared),
                2 => Some(UserThreadPhase::Dormant),
                3 => Some(UserThreadPhase::Runnable),
                4 => Some(UserThreadPhase::StopRequested),
                5 => Some(UserThreadPhase::Detached),
                _ => return Err(Error::InvalidResponse),
            };
            let present = boolean(w[3])?;
            if (!present && w[0] != 0) || raw.next_cursor != 0 {
                return Err(Error::InvalidResponse);
            }
            (
                DetailRecord::Thread {
                    tid: present.then_some(w[0]),
                    role,
                    phase,
                },
                4,
            )
        }
        abi::HYPER_NATIVE_OBJECT_DETAIL_VMAR if kind == VmarObject::KIND => {
            range(w[0], w[1])?;
            (
                DetailRecord::Vmar {
                    base: w[0],
                    length: w[1],
                    live: boolean(w[2])?,
                },
                3,
            )
        }
        abi::HYPER_NATIVE_OBJECT_DETAIL_MAPPING if kind == VmarObject::KIND => {
            range(w[0], w[1])?;
            let permissions = MappingPermissions::decode(w[2])?;
            let maximum_permissions = MappingPermissions::decode(w[3])?;
            if w[2] & !w[3] != 0 {
                return Err(Error::InvalidResponse);
            }
            (
                DetailRecord::Mapping {
                    base: w[0],
                    length: w[1],
                    permissions,
                    maximum_permissions,
                },
                4,
            )
        }
        abi::HYPER_NATIVE_OBJECT_DETAIL_CHANNEL
            if kind == ByteChannelObject::KIND || kind == CapabilityChannelObject::KIND =>
        {
            let peer = if w[0] == 0 {
                None
            } else {
                Some(Koid::from_raw(w[0])?)
            };
            let byte_queue = boolean(w[5])?;
            if byte_queue != (kind == ByteChannelObject::KIND)
                || (!byte_queue && w[4] != 0)
                || raw.next_cursor != 0
            {
                return Err(Error::InvalidResponse);
            }
            (
                DetailRecord::Channel {
                    peer,
                    local_open: boolean(w[1])?,
                    peer_open: boolean(w[2])?,
                    queued: w[3],
                    bytes: w[4],
                    byte_queue,
                },
                6,
            )
        }
        abi::HYPER_NATIVE_OBJECT_DETAIL_DEVICE if kind == PhysicalDeviceObject::KIND => {
            let state = match w[6] {
                1 => DeviceState::Claimed,
                2 => DeviceState::Attached,
                3 => DeviceState::Active,
                4 => DeviceState::Retired,
                5 => DeviceState::Quarantined,
                _ => return Err(Error::InvalidResponse),
            };
            (
                DetailRecord::Device {
                    profile: word32(w[0])?,
                    device_id: word32(w[1])?,
                    pci_identity: word32(w[2])?,
                    irq_domain: word32(w[3])?,
                    interrupt: word32(w[4])?,
                    interrupt_count: word32(w[5])?,
                    state,
                    resource_count: w[7],
                },
                8,
            )
        }
        abi::HYPER_NATIVE_OBJECT_DETAIL_DEVICE_RESOURCE if kind == PhysicalDeviceObject::KIND => {
            range(w[1], w[2])?;
            (
                DetailRecord::DeviceResource {
                    kind: word32(w[0])?,
                    base: w[1],
                    length: w[2],
                    offset: w[3],
                    flags: word32(w[4])?,
                },
                5,
            )
        }
        _ => return Err(Error::InvalidResponse),
    };
    if w[used..].iter().any(|v| *v != 0) {
        return Err(Error::InvalidResponse);
    }
    Ok(ObjectDetails {
        koid,
        object_kind: kind,
        record,
        next: NonZeroU64::new(raw.next_cursor).map(|n| DetailCursor(n.get())),
    })
}

#[cfg(test)]
#[path = "../../tests/inspect/details.rs"]
mod tests;
