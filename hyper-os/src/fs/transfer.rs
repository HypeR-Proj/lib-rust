// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Bounded transfer between a positioned reader and an arbitrary consumer.
//! Exactly two buffers circulate between them; closing either channel cancels further work, and joining
//! the scoped reader retires every buffer before the source can disappear.

use alloc::vec::Vec;
use std::io;
use std::sync::mpsc;
use std::time::Duration;

const BATCH_BYTES: usize = 512 * 1024;

#[derive(Debug)]
pub enum Error<E> {
    Read(io::Error),
    Write(E),
    Thread(io::Error),
    WorkerStopped,
    Allocation,
    InvalidRange,
}

#[derive(Default)]
pub struct Statistics {
    pub read: Duration,
    pub write: Duration,
}

/// Copies an exact range while overlapping read and consumer work. At most two
/// 512-KiB buffers and one scoped reader are live; small ranges run inline.
/// `read` must fill its complete slice or report an error. `write` receives
/// offsets relative to the range and must finish using its slice before return.
/// No source or destination position is maintained by this function.
///
/// Failure returns after the worker has stopped, including an in-progress read.
/// A written prefix is not rolled back. The reader may run ahead by one buffer,
/// but never outside the requested range. Source consistency is caller-owned.
pub fn copy_range<R, W, E>(
    source_offset: u64,
    length: u64,
    read: R,
    write: W,
) -> Result<(), Error<E>>
where
    R: FnMut(u64, &mut [u8]) -> io::Result<()> + Send,
    W: FnMut(u64, &[u8]) -> Result<(), E>,
{
    copy::<false, _, _, _>(source_offset, length, read, write).map(|_| ())
}

/// Like [`copy_range`], with time spent reading and consuming each batch.
/// Durations overlap and must not be summed to derive elapsed wall time.
pub fn copy_range_profiled<R, W, E>(
    source_offset: u64,
    length: u64,
    read: R,
    write: W,
) -> Result<Statistics, Error<E>>
where
    R: FnMut(u64, &mut [u8]) -> io::Result<()> + Send,
    W: FnMut(u64, &[u8]) -> Result<(), E>,
{
    copy::<true, _, _, _>(source_offset, length, read, write)
}

impl<E: core::fmt::Display> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read(error) => write!(f, "file read: {error}"),
            Self::Write(error) => write!(f, "transfer consumer: {error}"),
            Self::Thread(error) => write!(f, "file reader thread: {error}"),
            Self::WorkerStopped => f.write_str("file reader stopped"),
            Self::Allocation => f.write_str("transfer buffer allocation failed"),
            Self::InvalidRange => f.write_str("invalid transfer range"),
        }
    }
}

impl From<Error<io::Error>> for io::Error {
    fn from(error: Error<io::Error>) -> Self {
        match error {
            Error::Read(error) | Error::Write(error) | Error::Thread(error) => error,
            Error::Allocation => io::ErrorKind::OutOfMemory.into(),
            Error::InvalidRange => io::ErrorKind::InvalidInput.into(),
            Error::WorkerStopped => io::Error::other("file reader stopped"),
        }
    }
}

struct Batch {
    offset: u64,
    length: usize,
    bytes: Vec<u8>,
}

fn buffer(length: usize) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| ())?;
    bytes.resize(length, 0);
    Ok(bytes)
}

/// `write` receives offsets relative to the selected range, never absolute file offsets.
/// A consumer failure cancels read-ahead and waits for an already-started read;
/// cancellation does not authorize reuse of a kernel-owned I/O buffer.
// Keep the constant guards at the call sites. An opaque helper in a shared
// SDK library would retain calls and duration arithmetic even for PROFILE=false.
fn copy<const PROFILE: bool, R, W, E>(
    source_offset: u64,
    length: u64,
    mut read: R,
    mut write: W,
) -> Result<Statistics, Error<E>>
where
    R: FnMut(u64, &mut [u8]) -> io::Result<()> + Send,
    W: FnMut(u64, &[u8]) -> Result<(), E>,
{
    source_offset
        .checked_add(length)
        .ok_or(Error::InvalidRange)?;
    if length == 0 {
        return Ok(Statistics::default());
    }
    let mut first =
        buffer(length.min(BATCH_BYTES as u64) as usize).map_err(|_| Error::Allocation)?;
    if length <= BATCH_BYTES as u64 {
        let start = if PROFILE {
            Some(std::time::Instant::now())
        } else {
            None
        };
        read(source_offset, &mut first).map_err(Error::Read)?;
        let read = if PROFILE {
            elapsed(start)
        } else {
            Duration::ZERO
        };
        let start = if PROFILE {
            Some(std::time::Instant::now())
        } else {
            None
        };
        write(0, &first).map_err(Error::Write)?;
        return Ok(Statistics {
            read,
            write: if PROFILE {
                elapsed(start)
            } else {
                Duration::ZERO
            },
        });
    }
    let second = buffer(BATCH_BYTES).map_err(|_| Error::Allocation)?;
    let (free_tx, free_rx) = mpsc::sync_channel(2);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    free_tx.send(first).map_err(|_| Error::WorkerStopped)?;
    free_tx.send(second).map_err(|_| Error::WorkerStopped)?;
    // Own both consumer endpoints inside the scope. Unwinding a consumer must
    // close them before scope waits for its reader, including a reader blocked
    // waiting for a reusable buffer.
    std::thread::scope(move |scope| {
        let worker = std::thread::Builder::new()
            .name("file-reader".into())
            .stack_size(128 * 1024)
            .spawn_scoped(scope, move || {
                let mut total = Duration::ZERO;
                let mut completed = 0;
                while completed < length {
                    let Ok(mut bytes) = free_rx.recv() else { break };
                    let offset = source_offset + completed;
                    // After the first batch, file requests start at a batch
                    // boundary. This avoids two extra sector reads on every
                    // unaligned range transfer.
                    let capacity = BATCH_BYTES - (offset % BATCH_BYTES as u64) as usize;
                    let count = (length - completed).min(capacity as u64) as usize;
                    let start = if PROFILE {
                        Some(std::time::Instant::now())
                    } else {
                        None
                    };
                    let result = read(offset, &mut bytes[..count]);
                    if PROFILE {
                        total += elapsed(start);
                    }
                    if let Err(error) = result {
                        let _ = ready_tx.send(Err(error));
                        break;
                    }
                    if ready_tx
                        .send(Ok(Batch {
                            offset: completed,
                            length: count,
                            bytes,
                        }))
                        .is_err()
                    {
                        break;
                    }
                    completed += count as u64;
                }
                total
            })
            .map_err(Error::Thread)?;
        let mut written = Duration::ZERO;
        let result = (|| {
            let mut completed = 0;
            while completed < length {
                let batch = ready_rx
                    .recv()
                    .map_err(|_| Error::WorkerStopped)?
                    .map_err(Error::Read)?;
                if batch.offset != completed
                    || batch.length == 0
                    || batch.length as u64 > length - completed
                {
                    return Err(Error::InvalidRange);
                }
                let start = if PROFILE {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                write(completed, &batch.bytes[..batch.length]).map_err(Error::Write)?;
                if PROFILE {
                    written += elapsed(start);
                }
                completed += batch.length as u64;
                // A finished reader may already have dropped its receiver.
                // The final ready batch or its error still belongs to ready_rx.
                let _ = free_tx.send(batch.bytes);
            }
            Ok(())
        })();
        drop(ready_rx);
        drop(free_tx);
        let reader = worker.join();
        result?;
        let read = reader.map_err(|_| Error::WorkerStopped)?;
        Ok(Statistics {
            read,
            write: written,
        })
    })
}

fn elapsed(start: Option<std::time::Instant>) -> Duration {
    start.map_or(Duration::ZERO, |start| start.elapsed())
}

#[cfg(test)]
#[path = "../../tests/file_transfer.rs"]
mod tests;
