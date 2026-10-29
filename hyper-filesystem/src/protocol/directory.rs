// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Bounded directory batches. Checkpoints travel only between the kernel and
//! its filesystem worker; they are not application-controlled seek offsets.

use super::{
    DIRECTORY, Entry, FILE, NAME_BYTES, SYMLINK, get, get_time, put, put_time, valid_name,
};

pub const DIRECTORY_BATCH_BYTES: usize = 4096;
pub(super) const BATCH_HEADER_BYTES: usize = 48;
const RECORD_HEADER_BYTES: usize = 120;
/// Enough space for at least one maximum-length name, guaranteeing progress.
pub const DIRECTORY_MIN_BYTES: usize = BATCH_HEADER_BYTES + RECORD_HEADER_BYTES + NAME_BYTES;

/// Filesystem-private continuation, retained under the kernel directory
/// stream's identity and mutation fence. Zero starts a new scan.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct DirectoryCursor {
    pub words: [u64; 4],
}

impl DirectoryCursor {
    pub const START: Self = Self { words: [0; 4] };

    pub fn is_start(self) -> bool {
        self == Self::START
    }

    pub(super) fn encode(self, output: &mut [u8]) {
        for (index, word) in self.words.into_iter().enumerate() {
            put(output, index * 8, word);
        }
    }

    pub(super) fn decode(input: &[u8]) -> Option<Self> {
        Some(Self {
            words: [
                get(input, 0)?,
                get(input, 8)?,
                get(input, 16)?,
                get(input, 24)?,
            ],
        })
    }
}

/// Fully validated borrowed wire batch; iterating does not allocate name arrays.
pub struct DirectoryBatch<'a> {
    bytes: &'a [u8],
    count: usize,
    eof: bool,
    start: DirectoryCursor,
}

impl<'a> DirectoryBatch<'a> {
    pub fn decode(bytes: &'a [u8]) -> Option<Self> {
        if !(BATCH_HEADER_BYTES..=DIRECTORY_BATCH_BYTES).contains(&bytes.len()) {
            return None;
        }
        let count = usize::try_from(get(bytes, 0)?).ok()?;
        let eof = match get(bytes, 8)? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let start = DirectoryCursor::decode(bytes.get(16..48)?)?;
        if count == 0 && !eof {
            return None;
        }
        let mut remaining = &bytes[BATCH_HEADER_BYTES..];
        for _ in 0..count {
            let length = usize::try_from(get(remaining, 0)?).ok()?;
            let record = DirectoryRecord::decode(remaining.get(..length)?)?;
            let next = record.next_cursor();
            let consumed = bytes.len() - remaining.len();
            if next.is_start()
                || next == start
                || contains_cursor(&bytes[BATCH_HEADER_BYTES..consumed], next)?
            {
                return None;
            }
            remaining = remaining.get(length..)?;
        }
        if !remaining.is_empty() {
            return None;
        }
        Some(Self {
            bytes,
            count,
            eof,
            start,
        })
    }

    pub const fn len(&self) -> usize {
        self.count
    }
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub const fn eof(&self) -> bool {
        self.eof
    }
    pub const fn start_cursor(&self) -> DirectoryCursor {
        self.start
    }

    pub fn records(&self) -> impl Iterator<Item = DirectoryRecord<'a>> {
        let mut bytes = &self.bytes[BATCH_HEADER_BYTES..];
        (0..self.count).filter_map(move |_| {
            let length = usize::try_from(get(bytes, 0)?).ok()?;
            let (record, rest) = bytes.split_at(length);
            bytes = rest;
            Some(DirectoryRecord { bytes: record })
        })
    }
}

#[derive(Clone, Copy)]
pub struct DirectoryRecord<'a> {
    bytes: &'a [u8],
}

impl<'a> DirectoryRecord<'a> {
    fn decode(bytes: &'a [u8]) -> Option<Self> {
        let name_len = usize::try_from(get(bytes, 8)?).ok()?;
        if name_len == 0
            || name_len > NAME_BYTES
            || bytes.len() != RECORD_HEADER_BYTES + name_len
            || ![u64::from(FILE), u64::from(DIRECTORY), u64::from(SYMLINK)]
                .contains(&get(bytes, 16)?)
            || get(bytes, 24)? & !0o777 != 0
        {
            return None;
        }
        let name = bytes.get(RECORD_HEADER_BYTES..)?;
        if !valid_name(name) {
            return None;
        }
        get_time(bytes, 40)?;
        get_time(bytes, 56)?;
        get_time(bytes, 72)?;
        Some(Self { bytes })
    }

    pub fn name(self) -> &'a str {
        core::str::from_utf8(&self.bytes[RECORD_HEADER_BYTES..]).unwrap_or("")
    }
    pub fn next_cursor(self) -> DirectoryCursor {
        DirectoryCursor::decode(&self.bytes[88..120]).unwrap_or(DirectoryCursor::START)
    }
    pub fn entry_into(self, entry: &mut Entry) {
        let name = self.name().as_bytes();
        entry.name_len = name.len();
        entry.name[..name.len()].copy_from_slice(name);
        entry.kind = get(self.bytes, 16).unwrap_or(0) as u32;
        entry.mode = get(self.bytes, 24).unwrap_or(0) as u32;
        entry.size = get(self.bytes, 32).unwrap_or(0);
        entry.created = get_time(self.bytes, 40).flatten();
        entry.accessed = get_time(self.bytes, 56).flatten();
        entry.modified = get_time(self.bytes, 72).flatten();
    }
}

pub struct DirectoryBatchBuilder<'a> {
    output: &'a mut [u8],
    length: usize,
    count: usize,
    start: DirectoryCursor,
}

impl<'a> DirectoryBatchBuilder<'a> {
    pub fn new(output: &'a mut [u8], start: DirectoryCursor) -> Option<Self> {
        if !(DIRECTORY_MIN_BYTES..=DIRECTORY_BATCH_BYTES).contains(&output.len()) {
            return None;
        }
        output[..BATCH_HEADER_BYTES].fill(0);
        start.encode(&mut output[16..48]);
        Some(Self {
            output,
            length: BATCH_HEADER_BYTES,
            count: 0,
            start,
        })
    }

    /// Returns false without consuming the record when the batch is full.
    pub fn push(&mut self, entry: &Entry, next: DirectoryCursor) -> Option<bool> {
        let name = entry.name.get(..entry.name_len)?;
        if name.is_empty()
            || !valid_name(name)
            || !matches!(entry.kind, FILE | DIRECTORY | SYMLINK)
            || entry.mode & !0o777 != 0
            || next.is_start()
            || next == self.start
            || contains_cursor(&self.output[BATCH_HEADER_BYTES..self.length], next)?
        {
            return None;
        }
        let length = RECORD_HEADER_BYTES.checked_add(name.len())?;
        let Some(record) = self
            .output
            .get_mut(self.length..self.length.checked_add(length)?)
        else {
            return Some(false);
        };
        record.fill(0);
        put(record, 0, length as u64);
        put(record, 8, name.len() as u64);
        put(record, 16, u64::from(entry.kind));
        put(record, 24, u64::from(entry.mode));
        put(record, 32, entry.size);
        put_time(record, 40, entry.created);
        put_time(record, 56, entry.accessed);
        put_time(record, 72, entry.modified);
        next.encode(&mut record[88..120]);
        record[RECORD_HEADER_BYTES..].copy_from_slice(name);
        self.length += length;
        self.count += 1;
        Some(true)
    }

    pub fn finish(self, eof: bool) -> Option<usize> {
        if self.count == 0 && !eof {
            return None;
        }
        put(self.output, 0, self.count as u64);
        put(self.output, 8, u64::from(eof));
        Some(self.length)
    }
}

/// Inspect only the validated or builder-written prefix. At most 33 records
/// fit in a wire batch, bounding pairwise checks without another cursor index
/// on the kernel stack. Returning to any earlier cursor would replay a cycle.
fn contains_cursor(mut records: &[u8], cursor: DirectoryCursor) -> Option<bool> {
    while !records.is_empty() {
        let length = usize::try_from(get(records, 0)?).ok()?;
        let record = records.get(..length)?;
        if DirectoryCursor::decode(record.get(88..120)?)? == cursor {
            return Some(true);
        }
        records = records.get(length..)?;
    }
    Some(false)
}
