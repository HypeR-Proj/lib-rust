// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Bounded physical read plans. Descriptors cover a contiguous prefix of the
//! requested file range; volume-relative byte offsets permit inline tails.
//! A plan is valid only while its filesystem transaction remains serialized.

use super::{DATA_BYTES, get, put};

pub const MAX_READ_EXTENTS: usize = 64;
pub const EXTENT_PLAN_BYTES: usize = 16 + 16 * MAX_READ_EXTENTS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadExtent {
    pub offset: u64,
    pub length: u64,
}

/// A structurally validated plan. The receiver must additionally validate each
/// physical range against the exact block capability bound to this mount.
pub struct ReadExtentPlan<'a> {
    bytes: &'a [u8],
    length: usize,
}

impl<'a> ReadExtentPlan<'a> {
    pub fn decode(bytes: &'a [u8], requested: usize) -> Option<Self> {
        let length = usize::try_from(get(bytes, 0)?).ok()?;
        let count = usize::try_from(get(bytes, 8)?).ok()?;
        if count > MAX_READ_EXTENTS
            || bytes.len() != 16 + count * 16
            || length > requested.min(DATA_BYTES)
        {
            return None;
        }
        let mut sum = 0u64;
        for record in bytes[16..].chunks_exact(16) {
            let offset = get(record, 0)?;
            let n = get(record, 8)?;
            if n == 0 {
                return None;
            }
            offset.checked_add(n)?;
            sum = sum.checked_add(n)?;
        }
        (sum == length as u64).then_some(Self { bytes, length })
    }

    pub const fn length(&self) -> usize {
        self.length
    }

    pub fn extents(&self) -> impl Iterator<Item = ReadExtent> + '_ {
        self.bytes[16..].chunks_exact(16).map(|record| ReadExtent {
            // Validation above guarantees complete records.
            offset: get(record, 0).unwrap_or(0),
            length: get(record, 8).unwrap_or(0),
        })
    }
}

/// Writes metadata directly into the existing worker response buffer. Once
/// full, the caller returns this prefix and the kernel requests the remainder.
pub struct ReadExtentPlanBuilder<'a> {
    bytes: &'a mut [u8],
    count: usize,
    length: usize,
}

impl<'a> ReadExtentPlanBuilder<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Option<Self> {
        if bytes.len() < 32 {
            return None;
        }
        let length = bytes.len().min(EXTENT_PLAN_BYTES);
        Some(Self {
            bytes: &mut bytes[..length],
            count: 0,
            length: 0,
        })
    }

    /// `Some(false)` means the bounded plan is full; no bytes were appended.
    /// Zero-sized and overflowing ranges are malformed, never EOF markers.
    pub fn push(&mut self, offset: u64, length: usize) -> Option<bool> {
        if length == 0 {
            return None;
        }
        offset.checked_add(length as u64)?;
        let total = self.length.checked_add(length)?;
        if total > DATA_BYTES {
            return None;
        }
        if self.count != 0 {
            let previous = 16 + (self.count - 1) * 16;
            let start = get(self.bytes, previous)?;
            let old = get(self.bytes, previous + 8)?;
            if start.checked_add(old)? == offset {
                put(self.bytes, previous + 8, old.checked_add(length as u64)?);
                self.length = total;
                return Some(true);
            }
        }
        let index = 16 + self.count * 16;
        if index + 16 > self.bytes.len() {
            return Some(false);
        }
        put(self.bytes, index, offset);
        put(self.bytes, index + 8, length as u64);
        self.count += 1;
        self.length = total;
        Some(true)
    }

    pub const fn length(&self) -> usize {
        self.length
    }

    pub fn finish(self) -> usize {
        put(self.bytes, 0, self.length as u64);
        put(self.bytes, 8, self.count as u64);
        16 + self.count * 16
    }
}
