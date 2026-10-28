// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! System-wide static tracepoints, independent of PMU sampling. Configuration
//! requires `SET_ATTRIBUTES`; records and names require `INSPECT_DETAILS`. Captures
//! have an enforced deadline and per-CPU overwrite/loss reporting.
use super::{CpuInspector, Koid};
use crate::{Error, Result};
pub use hyper_abi::{HyperNativeTraceConfig as TraceConfig, HyperNativeTraceInfo as TraceInfo};

/// Bit values accepted by `TraceConfig.categories` (zero and unknown bits fail).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum Category {
    Scheduler = 1,
    Ipc = 2,
    Syscall = 4,
    Io = 8,
    Memory = 16,
    Irq = 32,
    Vm = 64,
}
impl Category {
    pub const ALL: u64 = 127;
    pub const fn name(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::Ipc => "ipc",
            Self::Syscall => "syscall",
            Self::Io => "io",
            Self::Memory => "memory",
            Self::Irq => "irq",
            Self::Vm => "vm",
        }
    }
    pub fn decode(value: u64) -> Result<Self> {
        match value {
            1 => Ok(Self::Scheduler),
            2 => Ok(Self::Ipc),
            4 => Ok(Self::Syscall),
            8 => Ok(Self::Io),
            16 => Ok(Self::Memory),
            32 => Ok(Self::Irq),
            64 => Ok(Self::Vm),
            _ => Err(Error::InvalidResponse),
        }
    }
}
/// A batch owns metadata along with its records: ring eviction cannot invalidate
/// a later dictionary lookup. Strings are UTF-8 and contain no kernel addresses.
pub struct TraceBatch {
    raw: hyper_abi::HyperNativeTraceBatch,
}
impl TraceBatch {
    pub fn count(&self) -> usize {
        self.raw.count as usize
    }
    pub fn next(&self) -> u64 {
        self.raw.next
    }
    pub fn overwritten(&self) -> u64 {
        self.raw.overwritten
    }
    pub fn incomplete(&self) -> bool {
        self.raw.incomplete != 0
    }
    pub fn records(&self) -> impl Iterator<Item = Result<TraceRecord<'_>>> {
        self.raw
            .records
            .chunks_exact(328)
            .take(self.count())
            .map(TraceRecord::decode)
    }
}
pub struct TraceRecord<'a> {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub category: Category,
    pub name: &'a str,
    pub source: &'a str,
    pub line: u64,
    pub fields: [(&'a str, u64); 4],
    pub field_count: usize,
}
impl<'a> TraceRecord<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self> {
        let count = word(bytes, 24) as usize;
        if count > 4 {
            return Err(Error::InvalidResponse);
        }
        let mut fields = [("", 0); 4];
        for (index, field) in fields.iter_mut().enumerate().take(count) {
            *field = (
                string(&bytes[128 + index * 24..152 + index * 24])?,
                word(bytes, 32 + index * 8),
            );
        }
        Ok(Self {
            sequence: word(bytes, 0),
            timestamp_ns: word(bytes, 8),
            category: Category::decode(word(bytes, 16))?,
            name: string(&bytes[64..128])?,
            source: string(&bytes[224..320])?,
            line: word(bytes, 320),
            fields,
            field_count: count,
        })
    }
    pub fn value(&self, name: &str) -> Option<u64> {
        self.fields[..self.field_count]
            .iter()
            .find_map(|(key, value)| (*key == name).then_some(*value))
    }
}
fn word(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}
fn string(bytes: &[u8]) -> Result<&str> {
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or(Error::InvalidResponse)?;
    if bytes[end..].iter().any(|b| *b != 0) {
        return Err(Error::InvalidResponse);
    }
    core::str::from_utf8(&bytes[..end]).map_err(|_| Error::InvalidResponse)
}
impl CpuInspector {
    /// A zero CPU mask selects every online CPU. The four words cover 256 CPUs.
    /// `duration_ms` is 1..=300000; capacity is `64..=trace_info.maximum_capacity`.
    pub fn trace_start(&self, config: &TraceConfig) -> Result<u64> {
        // SAFETY: The initialized configuration and inspector live across the call.
        let result = unsafe {
            hyper_sys::cpu_inspector_trace_start(self.handle.as_handle_ref().raw().get(), config)
        };
        crate::Status::from_raw(result.status).into_result()?;
        if result.value0 == 0 || result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(result.value0)
    }
    /// Stop closes admission first. Retry BUSY to join the remaining short writer.
    pub fn trace_stop(&self, generation: u64) -> Result<()> {
        // SAFETY: The inspector remains live; the generation is a scalar token.
        let result = unsafe {
            hyper_sys::cpu_inspector_trace_stop(self.handle.as_handle_ref().raw().get(), generation)
        };
        crate::Status::from_raw(result.status).into_result()
    }
    /// Releases a stopped capture and invalidates its generation. Active captures return BUSY.
    pub fn trace_clear(&self, generation: u64) -> Result<()> {
        // SAFETY: The inspector remains live; the generation is a scalar token.
        let result = unsafe {
            hyper_sys::cpu_inspector_trace_clear(
                self.handle.as_handle_ref().raw().get(),
                generation,
            )
        };
        crate::Status::from_raw(result.status).into_result()
    }
    pub fn trace_info(&self) -> Result<TraceInfo> {
        let mut info = TraceInfo {
            generation: 0,
            started_ns: 0,
            deadline_ns: 0,
            categories: 0,
            cpu_count: 0,
            capacity: 0,
            maximum_capacity: 0,
            running: 0,
            cpu_mask: [0; 32],
            revision: [0; 64],
        };
        self.trace_read_raw(0, u64::MAX, 0, &mut info)?;
        if info.cpu_count == 0
            || info.cpu_count > 256
            || info.running > 1
            || info.categories & !127 != 0
        {
            return Err(Error::InvalidResponse);
        }
        Ok(info)
    }
    /// Returns a non-destructive, bounded batch. A zero count while running is
    /// not EOF. Cursors are local to the requested CPU and generation.
    pub fn trace_read(&self, generation: u64, cpu: u64, cursor: u64) -> Result<TraceBatch> {
        let mut raw = hyper_abi::HyperNativeTraceBatch {
            count: 0,
            next: 0,
            overwritten: 0,
            incomplete: 0,
            records: [0; 2624],
        };
        self.trace_read_raw(generation, cpu, cursor, &mut raw)?;
        if raw.count > 8 || raw.next < cursor || raw.incomplete > 1 {
            return Err(Error::InvalidResponse);
        }
        let batch = TraceBatch { raw };
        for (index, record) in batch.records().enumerate() {
            if record?.sequence
                != cursor
                    .checked_add(batch.overwritten())
                    .and_then(|n| n.checked_add(index as u64))
                    .ok_or(Error::InvalidResponse)?
            {
                return Err(Error::InvalidResponse);
            }
        }
        if batch.next()
            != cursor
                .checked_add(batch.overwritten())
                .and_then(|n| n.checked_add(batch.count() as u64))
                .ok_or(Error::InvalidResponse)?
        {
            return Err(Error::InvalidResponse);
        }
        Ok(batch)
    }
    /// Best-effort current name: a Thread that already retired may be `NOT_FOUND`.
    /// This ID grants observation only; it cannot address a scheduling operation.
    pub fn trace_thread_name(&self, generation: u64, thread: u64) -> Result<TraceThreadName> {
        let mut value = hyper_abi::HyperNativeTraceThread {
            thread: 0,
            name: [0; 64],
        };
        self.trace_read_raw(generation, u64::MAX - 1, thread, &mut value)?;
        if value.thread != thread {
            return Err(Error::InvalidResponse);
        }
        string(&value.name)?;
        Ok(TraceThreadName(value.name))
    }

    /// Resolves a live scheduler `ThreadId` to its canonical KOID and name.
    /// Both IDs are observations only. A retired Thread may be `NOT_FOUND`;
    /// kernels without this optional query may return `INVALID_ARGUMENT`.
    pub fn trace_thread_details(&self, generation: u64, thread: u64) -> Result<TraceThreadDetails> {
        let mut value = hyper_abi::HyperNativeTraceThreadDetails {
            thread: 0,
            koid: 0,
            name: [0; 64],
        };
        self.trace_read_raw(generation, u64::MAX - 2, thread, &mut value)?;
        TraceThreadDetails::decode(thread, value)
    }
    // Only instantiated with the padding-free fixed ABI records above.
    fn trace_read_raw<T>(
        &self,
        generation: u64,
        cpu: u64,
        cursor: u64,
        value: &mut T,
    ) -> Result<()> {
        // SAFETY: Private callers provide initialized, writable ABI records of
        // the exact selected query size; no reference fields can be overwritten.
        let result = unsafe {
            hyper_sys::cpu_inspector_trace_read(
                self.handle.as_handle_ref().raw().get(),
                generation,
                cpu,
                cursor,
                (value as *mut T).cast(),
                core::mem::size_of::<T>(),
            )
        };
        crate::validate_info_result(result, core::mem::size_of::<T>()).map(|_| ())
    }
}
pub struct TraceThreadName([u8; 64]);
impl TraceThreadName {
    pub fn as_str(&self) -> &str {
        string(&self.0).unwrap_or("")
    }
}

pub struct TraceThreadDetails {
    koid: Koid,
    name: [u8; 64],
}
impl TraceThreadDetails {
    fn decode(thread: u64, value: hyper_abi::HyperNativeTraceThreadDetails) -> Result<Self> {
        if value.thread != thread {
            return Err(Error::InvalidResponse);
        }
        string(&value.name)?;
        Ok(Self {
            koid: Koid::from_raw(value.koid)?,
            name: value.name,
        })
    }
    pub fn koid(&self) -> Koid {
        self.koid
    }
    pub fn name(&self) -> &str {
        string(&self.name).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn trace_identity_join_validates_both_namespaces() -> crate::Result<()> {
        let mut record = hyper_abi::HyperNativeTraceThreadDetails {
            thread: 0x0100_0001,
            koid: 7,
            name: [0; 64],
        };
        let observed = super::TraceThreadDetails::decode(record.thread, record)?;
        assert_eq!(observed.koid().get(), 7);
        assert!(matches!(
            super::TraceThreadDetails::decode(9, record),
            Err(crate::Error::InvalidResponse)
        ));
        record.koid = 0;
        assert!(matches!(
            super::TraceThreadDetails::decode(record.thread, record),
            Err(crate::Error::InvalidResponse)
        ));
        Ok(())
    }
    use super::*;
    #[test]
    fn records_reject_invalid_metadata_and_keep_full_width_ids() -> Result<()> {
        let mut bytes = [0u8; 328];
        bytes[16..24].copy_from_slice(&(Category::Scheduler as u64).to_le_bytes());
        bytes[24..32].copy_from_slice(&1u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[64..70].copy_from_slice(b"switch");
        bytes[128..134].copy_from_slice(b"thread");
        let record = TraceRecord::decode(&bytes)?;
        assert_eq!(record.value("thread"), Some(u64::MAX));
        assert_eq!(record.name, "switch");
        bytes[24] = 5;
        assert!(TraceRecord::decode(&bytes).is_err());
        bytes[24] = 1;
        bytes[16] = 128;
        assert!(TraceRecord::decode(&bytes).is_err());
        bytes[16] = 1;
        bytes[64] = 0xff;
        assert!(TraceRecord::decode(&bytes).is_err());
        assert!(string(b"no terminator").is_err());
        assert!(string(b"name\0tail").is_err());
        Ok(())
    }
}
