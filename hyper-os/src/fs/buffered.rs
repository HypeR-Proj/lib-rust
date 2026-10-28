// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Bounded buffering of sparse positioned reads.
//!
//! This is a per-reader view, not the coherent kernel page cache. It avoids
//! repeated syscall/copy overhead for small reads. Create a fresh reader after
//! mutations, or hold content protection for a stable view. Large sequential
//! transfers should recover the source with `BufferedReader::into_inner`.

use super::ReadAt;
use alloc::vec::Vec;
use core::cell::RefCell;

const PAGE_BYTES: usize = 4096;
const CACHE_PAGES: usize = 4;

#[derive(Debug)]
pub enum Error<E> {
    Source(E),
    Allocation,
    InvalidRange,
    ReentrantRead,
}

struct Page {
    offset: Option<u64>,
    bytes: [u8; PAGE_BYTES],
}

struct Cache {
    pages: Vec<Page>,
    next: usize,
}

/// A bounded read buffer tied to one source. It neither freezes content nor
/// establishes cache coherence with concurrent writes. All returned bytes are
/// copied out; no buffer borrow escapes a read.
pub struct BufferedReader<S> {
    source: S,
    length: u64,
    cache: RefCell<Cache>,
}

impl<S: ReadAt> BufferedReader<S> {
    pub fn new(source: S) -> Result<Self, Error<S::Error>> {
        let length = source.length().map_err(Error::Source)?;
        // Reserve on the heap without constructing a 16 KiB stack temporary.
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(CACHE_PAGES)
            .map_err(|_| Error::Allocation)?;
        for _ in 0..CACHE_PAGES {
            pages.push(Page {
                offset: None,
                bytes: [0; PAGE_BYTES],
            });
        }
        Ok(Self {
            source,
            length,
            cache: RefCell::new(Cache { pages, next: 0 }),
        })
    }

    pub fn into_inner(self) -> S {
        self.source
    }
}

impl<S: ReadAt> ReadAt for BufferedReader<S> {
    type Error = Error<S::Error>;

    fn length(&self) -> Result<u64, Self::Error> {
        Ok(self.length)
    }

    fn read_exact_at(&self, mut offset: u64, mut output: &mut [u8]) -> Result<(), Self::Error> {
        if output.is_empty() {
            return Ok(());
        }
        let length = u64::try_from(output.len()).map_err(|_| Error::InvalidRange)?;
        let end = offset.checked_add(length).ok_or(Error::InvalidRange)?;
        if end > self.length {
            return Err(Error::InvalidRange);
        }
        let mut cache = self
            .cache
            .try_borrow_mut()
            .map_err(|_| Error::ReentrantRead)?;
        while !output.is_empty() {
            let within = (offset % PAGE_BYTES as u64) as usize;
            let page_offset = offset - within as u64;
            let slot = match cache
                .pages
                .iter()
                .position(|page| page.offset == Some(page_offset))
            {
                Some(slot) => slot,
                None => {
                    let slot = cache.next;
                    cache.next = (slot + 1) % CACHE_PAGES;
                    let page = &mut cache.pages[slot];
                    // A failed read may have overwritten part of the victim.
                    // Neither its old nor new offset may expose those bytes.
                    page.offset = None;
                    let length = (self.length - page_offset).min(PAGE_BYTES as u64) as usize;
                    self.source
                        .read_exact_at(page_offset, &mut page.bytes[..length])
                        .map_err(Error::Source)?;
                    page.offset = Some(page_offset);
                    slot
                }
            };
            let count = output.len().min(PAGE_BYTES - within);
            output[..count].copy_from_slice(&cache.pages[slot].bytes[within..within + count]);
            offset += count as u64;
            output = &mut output[count..];
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/buffered_read.rs"]
mod tests;
