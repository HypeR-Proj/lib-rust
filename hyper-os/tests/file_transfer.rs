// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::panic)]

use super::*;
use copy_range as copy;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[test]
fn copies_unaligned_payload_with_aligned_bounded_read_ahead() {
    let offset = 13;
    let length = (BATCH_BYTES * 3 + 17) as u64;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let mut copied = 0;
    let result = copy(
        offset,
        length,
        move |at, bytes| {
            observed
                .lock()
                .map_err(|_| io::Error::other("lock"))?
                .push((at, bytes.len()));
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = ((at + index as u64) % 251) as u8;
            }
            Ok(())
        },
        |at, bytes| -> Result<(), ()> {
            assert_eq!(at, copied);
            for (index, byte) in bytes.iter().enumerate() {
                assert_eq!(*byte, ((offset + at + index as u64) % 251) as u8);
            }
            copied += bytes.len() as u64;
            Ok(())
        },
    );
    assert!(result.is_ok());
    assert_eq!(copied, length);
    let calls = match calls.lock() {
        Ok(calls) => calls,
        Err(_) => panic!("lock"),
    };
    assert_eq!(calls.len(), 4);
    for (at, length) in calls.iter().skip(1) {
        assert_eq!(at % BATCH_BYTES as u64, 0);
        assert!(*length <= BATCH_BYTES);
    }
}

#[test]
fn consumer_failure_joins_and_bounds_speculation_to_two_buffers() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let result = copy(
        0,
        (BATCH_BYTES * 8) as u64,
        move |_, _| {
            observed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        |_, _| Err(7),
    );
    assert!(matches!(result, Err(Error::Write(7))));
    assert!((1..=2).contains(&calls.load(Ordering::Relaxed)));
}

#[test]
fn reader_failure_returns_after_the_completed_prefix() {
    let mut written = 0;
    let result = copy(
        0,
        (BATCH_BYTES * 3) as u64,
        |offset, _| {
            if offset == 0 {
                Ok(())
            } else {
                Err(io::Error::other("injected read error"))
            }
        },
        |_, bytes| -> Result<(), ()> {
            written += bytes.len();
            Ok(())
        },
    );
    assert!(matches!(result, Err(Error::Read(_))));
    assert_eq!(written, BATCH_BYTES);
}

#[test]
fn empty_and_overflowing_ranges_do_not_start_io() {
    let read = |_, _: &mut [u8]| -> io::Result<()> { panic!("unexpected read") };
    let write = |_, _: &[u8]| -> Result<(), ()> { panic!("unexpected write") };
    assert!(copy(0, 0, read, write).is_ok());
    assert!(matches!(
        copy(u64::MAX, 1, read, write),
        Err(Error::InvalidRange)
    ));
}

#[test]
fn reader_progress_overlaps_the_consumer() -> io::Result<()> {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (read_tx, read_rx) = mpsc::channel();
    copy(
        0,
        (BATCH_BYTES * 2) as u64,
        move |offset, _| {
            if offset != 0 {
                entered_rx
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(io::Error::other)?;
                read_tx.send(()).map_err(io::Error::other)?;
            }
            Ok(())
        },
        |offset, _| -> io::Result<()> {
            if offset == 0 {
                entered_tx.send(()).map_err(io::Error::other)?;
                read_rx
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(io::Error::other)?;
            }
            Ok(())
        },
    )
    .map_err(io::Error::from)
}

#[test]
fn panicking_consumer_disconnects_before_scope_joins() -> io::Result<()> {
    // Keep a regression from hanging the entire host test process.
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(|| {
            copy(
                0,
                (BATCH_BYTES * 8) as u64,
                |_, _| Ok(()),
                |_, _| -> Result<(), ()> { panic!("injected consumer panic") },
            )
        });
        let _ = tx.send(outcome.is_err());
    });
    let caught = rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(io::Error::other)?;
    thread
        .join()
        .map_err(|_| io::Error::other("test thread panicked"))?;
    assert!(caught);
    Ok(())
}

#[test]
fn panicking_reader_is_joined_and_reported() {
    let result = copy(
        0,
        (BATCH_BYTES * 3) as u64,
        |_, _| -> io::Result<()> { panic!("injected reader panic") },
        |_, _| -> Result<(), ()> { Ok(()) },
    );
    assert!(matches!(result, Err(Error::WorkerStopped)));
}
