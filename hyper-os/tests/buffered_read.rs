// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::panic)]

use super::*;
use alloc::vec;
use std::cell::Cell;

struct Source {
    length: u64,
    lengths: Cell<usize>,
    reads: RefCell<Vec<(u64, usize)>>,
    fail_at: Cell<Option<u64>>,
}

impl Source {
    fn new(length: u64) -> Self {
        Self {
            length,
            lengths: Cell::new(0),
            reads: RefCell::new(Vec::new()),
            fail_at: Cell::new(None),
        }
    }
}

fn byte_at(offset: u64) -> u8 {
    (offset % 251) as u8
}

impl ReadAt for Source {
    type Error = &'static str;

    fn length(&self) -> Result<u64, Self::Error> {
        self.lengths.set(self.lengths.get() + 1);
        Ok(self.length)
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        self.reads.borrow_mut().push((offset, output.len()));
        if offset + output.len() as u64 > self.length {
            return Err("read past EOF");
        }
        if self.fail_at.get() == Some(offset) {
            let partial = output.len() / 2;
            output[..partial].fill(0xff);
            return Err("injected partial read failure");
        }
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = byte_at(offset + index as u64);
        }
        Ok(())
    }
}

fn check_read(
    source: &BufferedReader<Source>,
    offset: u64,
    length: usize,
) -> Result<(), Error<&'static str>> {
    let mut output = vec![0; length];
    source.read_exact_at(offset, &mut output)?;
    for (index, byte) in output.into_iter().enumerate() {
        assert_eq!(byte, byte_at(offset + index as u64));
    }
    Ok(())
}

#[test]
fn sparse_metadata_reads_reuse_pages_and_query_length_once() -> Result<(), Error<&'static str>> {
    let source = BufferedReader::new(Source::new(48 * 1024 * 1024))?;
    for _ in 0..100 {
        for offset in [13, 8 * 1024 * 1024 + 3, 40 * 1024 * 1024 + 7] {
            check_read(&source, offset, 4)?;
            check_read(&source, offset + 4, 65)?;
        }
        assert_eq!(source.length()?, 48 * 1024 * 1024);
    }
    assert_eq!(source.source.lengths.get(), 1);
    assert_eq!(source.source.reads.borrow().len(), 3);
    assert!(
        source
            .source
            .reads
            .borrow()
            .iter()
            .all(|&(offset, length)| offset % PAGE_BYTES as u64 == 0 && length == PAGE_BYTES)
    );
    Ok(())
}

#[test]
fn crosses_pages_and_clips_read_ahead_at_eof() -> Result<(), Error<&'static str>> {
    let length = PAGE_BYTES as u64 + 17;
    let source = BufferedReader::new(Source::new(length))?;
    check_read(&source, PAGE_BYTES as u64 - 3, 20)?;
    assert_eq!(
        source.source.reads.borrow().as_slice(),
        &[(0, PAGE_BYTES), (PAGE_BYTES as u64, 17)]
    );
    source.read_exact_at(length, &mut [])?;
    source.read_exact_at(u64::MAX, &mut [])?;
    assert!(matches!(
        source.read_exact_at(u64::MAX, &mut [0; 2]),
        Err(Error::InvalidRange)
    ));
    assert!(matches!(
        source.read_exact_at(length - 1, &mut [0; 2]),
        Err(Error::InvalidRange)
    ));
    assert!(matches!(
        source.read_exact_at(length, &mut [0; 1]),
        Err(Error::InvalidRange)
    ));
    assert_eq!(source.source.reads.borrow().len(), 2);
    Ok(())
}

#[test]
fn eviction_and_multi_page_reads_preserve_contents() -> Result<(), Error<&'static str>> {
    let source = BufferedReader::new(Source::new(8 * PAGE_BYTES as u64))?;
    for page in [0, 1, 2, 3, 4, 0, 5, 2, 7, 1] {
        check_read(&source, page * PAGE_BYTES as u64 + 11, 97)?;
    }
    check_read(&source, 7, 7 * PAGE_BYTES)?;
    assert!(source.source.reads.borrow().len() > CACHE_PAGES);
    assert_eq!(source.cache.borrow().pages.len(), CACHE_PAGES);
    Ok(())
}

#[test]
fn failed_refill_cannot_publish_partial_data_or_corrupt_a_cached_page()
-> Result<(), Error<&'static str>> {
    let source = BufferedReader::new(Source::new(8 * PAGE_BYTES as u64))?;
    for page in 0..CACHE_PAGES as u64 {
        check_read(&source, page * PAGE_BYTES as u64, 16)?;
    }
    let failed_offset = CACHE_PAGES as u64 * PAGE_BYTES as u64;
    source.source.fail_at.set(Some(failed_offset));
    for _ in 0..2 {
        assert!(matches!(
            source.read_exact_at(failed_offset, &mut [0; 16]),
            Err(Error::Source("injected partial read failure"))
        ));
    }
    source.source.fail_at.set(None);
    for page in 0..CACHE_PAGES as u64 {
        check_read(&source, page * PAGE_BYTES as u64, PAGE_BYTES)?;
    }
    check_read(&source, failed_offset, PAGE_BYTES)?;
    Ok(())
}
