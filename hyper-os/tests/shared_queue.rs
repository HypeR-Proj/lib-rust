// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::protocol::{CLOSED, Cursor, HEAD, HEADER_WORDS, TAIL, Words};
use super::*;
use core::result::Result;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::vec::Vec;

struct Backing(Vec<AtomicU64>);

impl Backing {
    fn new(words: usize) -> Self {
        Self((0..words).map(|_| AtomicU64::new(0)).collect())
    }

    fn set(&self, index: usize, value: u64) {
        self.0[index].store(value, Ordering::SeqCst);
    }

    fn get(&self, index: usize) -> u64 {
        self.0[index].load(Ordering::SeqCst)
    }
}

impl Words for Backing {
    fn load(&self, index: usize, order: Ordering) -> crate::Result<u64> {
        self.0
            .get(index)
            .map(|word| word.load(order))
            .ok_or(crate::Error::InvalidMemoryRange)
    }

    fn store(&self, index: usize, value: u64, order: Ordering) -> crate::Result<()> {
        self.0
            .get(index)
            .ok_or(crate::Error::InvalidMemoryRange)?
            .store(value, order);
        Ok(())
    }
}

fn backing(config: Config) -> (Backing, Backing) {
    (
        Backing::new(HEADER_WORDS + config.slots * config.slot_words()),
        Backing::new(HEADER_WORDS),
    )
}

#[test]
fn invalid_geometry_is_rejected_before_mapping() {
    assert!(Config::new(0, 8).is_err());
    assert!(Config::new(1, 0).is_err());
    assert!(Config::new(usize::MAX, 8).is_err());
    assert!(Config::new(1, usize::MAX).is_err());
}

#[test]
fn single_slot_preserves_empty_full_and_zero_length_messages() -> Result<(), QueueError> {
    let config = Config::new(1, 9)?;
    let (data, control) = backing(config);
    let mut producer = Cursor::new(config);
    let mut consumer = Cursor::new(config);
    let mut output = [0xa5; 16];
    assert!(matches!(
        consumer.pop(&data, &control, &mut output),
        Err(QueueError::Empty)
    ));
    producer.push(&data, &control, b"123456789")?;
    assert!(matches!(
        producer.push(&data, &control, b"x"),
        Err(QueueError::Full)
    ));
    assert_eq!(consumer.pop(&data, &control, &mut output)?, 9);
    assert_eq!(&output[..9], b"123456789");
    assert_eq!(&output[9..], &[0xa5; 7]);
    producer.push(&data, &control, &[])?;
    assert_eq!(consumer.pop(&data, &control, &mut output)?, 0);
    assert_eq!(data.get(HEAD), 2);
    assert_eq!(control.get(TAIL), 2);
    assert!(matches!(
        consumer.pop(&data, &control, &mut output),
        Err(QueueError::Empty)
    ));
    Ok(())
}

#[test]
fn insufficient_output_preserves_message_and_rejects_oversize_input() -> Result<(), QueueError> {
    let config = Config::new(2, 16)?;
    let (data, control) = backing(config);
    let mut producer = Cursor::new(config);
    let mut consumer = Cursor::new(config);
    assert!(matches!(
        producer.push(&data, &control, &[0; 17]),
        Err(QueueError::MessageTooLarge { maximum: 16 })
    ));
    assert_eq!(data.get(HEAD), 0);
    producer.push(&data, &control, b"message")?;
    let mut short = [0xa5; 3];
    assert!(matches!(
        consumer.pop(&data, &control, &mut short),
        Err(QueueError::BufferTooSmall { required: 7 })
    ));
    assert_eq!(short, [0xa5; 3]);
    assert_eq!(control.get(TAIL), 0);
    let mut output = [0; 16];
    assert_eq!(consumer.pop(&data, &control, &mut output)?, 7);
    assert_eq!(&output[..7], b"message");
    Ok(())
}

#[test]
fn malicious_lengths_and_cursors_never_escape_local_geometry() -> Result<(), QueueError> {
    let config = Config::new(2, 8)?;
    let (data, control) = backing(config);
    let mut consumer = Cursor::new(config);
    let mut output = [0xa5; 8];
    data.set(HEAD, 1);
    for length in [9, u64::MAX] {
        data.set(HEADER_WORDS, length);
        assert!(matches!(
            consumer.pop(&data, &control, &mut output),
            Err(QueueError::InvalidPeer)
        ));
        assert_eq!(output, [0xa5; 8]);
        assert_eq!(control.get(TAIL), 0);
    }
    data.set(HEAD, 3);
    assert!(matches!(
        consumer.readable(&data),
        Err(QueueError::InvalidPeer)
    ));
    let mut producer = Cursor::new(config);
    control.set(TAIL, 1);
    assert!(matches!(
        producer.writable(&control),
        Err(QueueError::InvalidPeer)
    ));
    Ok(())
}

#[test]
fn peer_cursor_rollback_is_rejected_after_valid_progress() -> Result<(), QueueError> {
    let config = Config::new(2, 8)?;
    let (data, control) = backing(config);
    let mut producer = Cursor::new(config);
    let mut consumer = Cursor::new(config);
    producer.push(&data, &control, b"a")?;
    producer.push(&data, &control, b"b")?;
    let mut output = [0; 8];
    consumer.pop(&data, &control, &mut output)?;
    data.set(HEAD, 1);
    assert!(matches!(
        consumer.readable(&data),
        Err(QueueError::InvalidPeer)
    ));
    data.set(HEAD, 2);
    producer.push(&data, &control, b"c")?;
    control.set(TAIL, 0);
    assert!(matches!(
        producer.writable(&control),
        Err(QueueError::InvalidPeer)
    ));
    Ok(())
}

#[test]
fn graceful_close_drains_published_prefix_before_eof() -> Result<(), QueueError> {
    let config = Config::new(2, 8)?;
    let (data, control) = backing(config);
    let mut producer = Cursor::new(config);
    let mut consumer = Cursor::new(config);
    producer.push(&data, &control, b"one")?;
    producer.push(&data, &control, b"two")?;
    data.set(CLOSED, 1);
    let mut output = [0; 8];
    for expected in [b"one", b"two"] {
        assert_eq!(consumer.pop(&data, &control, &mut output)?, 3);
        assert_eq!(&output[..3], expected);
    }
    assert!(matches!(consumer.readable(&data), Err(QueueError::Closed)));
    data.set(CLOSED, 2);
    assert!(matches!(
        consumer.readable(&data),
        Err(QueueError::InvalidPeer)
    ));
    Ok(())
}

#[test]
fn close_rechecks_head_after_observing_closed_marker() -> Result<(), QueueError> {
    struct PublishBeforeCloseRead(Backing, AtomicBool);
    impl Words for PublishBeforeCloseRead {
        fn load(&self, index: usize, order: Ordering) -> crate::Result<u64> {
            if index == CLOSED && !self.1.swap(true, Ordering::SeqCst) {
                self.0.set(HEAD, 1);
                self.0.set(CLOSED, 1);
            }
            self.0.load(index, order)
        }
        fn store(&self, index: usize, value: u64, order: Ordering) -> crate::Result<()> {
            self.0.store(index, value, order)
        }
    }
    let config = Config::new(1, 8)?;
    let (data, control) = backing(config);
    let data = PublishBeforeCloseRead(data, AtomicBool::new(false));
    data.0.set(HEADER_WORDS, 1);
    data.0
        .set(HEADER_WORDS + 1, u64::from_le_bytes(*b"x\0\0\0\0\0\0\0"));
    let mut consumer = Cursor::new(config);
    assert!(consumer.readable(&data)?);
    let mut output = [0; 8];
    assert_eq!(consumer.pop(&data, &control, &mut output)?, 1);
    assert_eq!(output[0], b'x');
    assert!(matches!(consumer.readable(&data), Err(QueueError::Closed)));
    Ok(())
}

#[test]
fn final_counter_value_is_consumable_but_never_wraps() -> Result<(), QueueError> {
    let config = Config::new(1, 8)?;
    let (data, control) = backing(config);
    let mut producer = Cursor::new(config);
    let mut consumer = Cursor::new(config);
    producer.position = u64::MAX - 1;
    consumer.position = u64::MAX - 1;
    control.set(TAIL, u64::MAX - 1);
    producer.push(&data, &control, b"last")?;
    let mut output = [0; 8];
    assert_eq!(consumer.pop(&data, &control, &mut output)?, 4);
    assert_eq!(&output[..4], b"last");
    assert_eq!(control.get(TAIL), u64::MAX);
    assert!(matches!(
        producer.push(&data, &control, b"again"),
        Err(QueueError::CounterExhausted)
    ));
    assert_eq!(data.get(HEAD), u64::MAX);
    data.set(CLOSED, 1);
    assert!(matches!(consumer.readable(&data), Err(QueueError::Closed)));
    Ok(())
}

#[test]
fn publication_and_arm_recheck_have_no_lost_wake_in_sc_order() {
    // Producer: publish cursor, load armed, conditionally set event.
    // Sleeper: clear event, arm, reread cursor, then decide whether to sleep.
    // Enumerate all interleavings preserving each participant's program order.
    #[derive(Clone, Copy, Default)]
    struct State {
        writer: u8,
        reader: u8,
        cursor: bool,
        armed: bool,
        saw_armed: bool,
        event: bool,
        saw_cursor: bool,
    }
    fn visit(state: State, count: &mut usize) {
        if state.writer == 3 && state.reader == 3 {
            assert!(
                state.saw_cursor || state.event,
                "publication stranded a waiter"
            );
            *count += 1;
            return;
        }
        if state.writer < 3 {
            let mut next = state;
            next.writer += 1;
            next.cursor |= state.writer == 0;
            if state.writer == 1 {
                next.saw_armed = state.armed;
            }
            next.event |= state.writer == 2 && state.saw_armed;
            visit(next, count);
        }
        if state.reader < 3 {
            let mut next = state;
            next.reader += 1;
            next.armed |= state.reader == 1;
            if state.reader == 0 {
                next.event = false;
            }
            if state.reader == 2 {
                next.saw_cursor = state.cursor;
            }
            visit(next, count);
        }
    }
    let mut count = 0;
    visit(State::default(), &mut count);
    assert_eq!(count, 20);
}

#[test]
fn concurrent_spsc_preserves_fifo_through_repeated_slot_reuse() -> Result<(), QueueError> {
    let config = Config::new(3, 8)?;
    let (data, control) = backing(config);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| -> Result<(), QueueError> {
            let mut producer = Cursor::new(config);
            for value in 0u64..2000 {
                loop {
                    match producer.push(&data, &control, &value.to_le_bytes()) {
                        Ok(()) => break,
                        Err(QueueError::Full) if std::time::Instant::now() < deadline => {
                            std::thread::yield_now()
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            data.set(CLOSED, 1);
            Ok(())
        });
        let reader = scope.spawn(|| -> Result<(), QueueError> {
            let mut consumer = Cursor::new(config);
            for expected in 0u64..2000 {
                let mut bytes = [0; 8];
                loop {
                    match consumer.pop(&data, &control, &mut bytes) {
                        Ok(length) => {
                            assert_eq!(length, 8);
                            assert_eq!(u64::from_le_bytes(bytes), expected);
                            break;
                        }
                        Err(QueueError::Empty) if std::time::Instant::now() < deadline => {
                            std::thread::yield_now()
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            Ok(())
        });
        writer.join().map_err(|_| QueueError::InvalidPeer)??;
        reader.join().map_err(|_| QueueError::InvalidPeer)??;
        Ok(())
    })
}

#[test]
fn notification_failure_preserves_send_commit_prefix() -> Result<(), QueueError> {
    let config = Config::new(1, 8)?;
    let (data, control) = backing(config);
    let mut producer = Cursor::new(config);
    let failure = QueueError::System(crate::Error::Status(crate::Status::ACCESS_DENIED));
    let mut notified = 0;
    let outcome = protocol::send_batch(&mut producer, &data, &control, &[b"one", b"two"], || {
        notified += 1;
        Err(failure)
    });
    assert_eq!(
        outcome,
        BatchOutcome {
            completed: 1,
            stop: Some(failure)
        }
    );
    assert!(failure.terminal());
    assert_eq!(notified, 1);
    assert_eq!(data.get(HEAD), 1);
    let mut consumer = Cursor::new(config);
    let mut output = [0; 8];
    assert_eq!(consumer.pop(&data, &control, &mut output)?, 3);
    assert_eq!(&output[..3], b"one");
    assert!(matches!(
        consumer.pop(&data, &control, &mut output),
        Err(QueueError::Empty)
    ));
    Ok(())
}

#[test]
fn notification_failure_preserves_consumed_slots_and_tail() -> Result<(), QueueError> {
    let config = Config::new(2, 8)?;
    let (data, control) = backing(config);
    let mut producer = Cursor::new(config);
    producer.push(&data, &control, b"one")?;
    let mut consumer = Cursor::new(config);
    let mut first = [0; 8];
    let mut second = [0; 8];
    let mut output = [ReceiveSlot::new(&mut first), ReceiveSlot::new(&mut second)];
    let failure = QueueError::System(crate::Error::Status(crate::Status::ACCESS_DENIED));
    let outcome =
        protocol::receive_batch(&mut consumer, &data, &control, &mut output, false, || {
            Err(failure)
        });
    assert_eq!(
        outcome,
        BatchOutcome {
            completed: 1,
            stop: Some(failure)
        }
    );
    assert_eq!(output[0].message(), Some(b"one".as_slice()));
    assert_eq!(output[1].message(), None);
    assert_eq!(control.get(TAIL), 1);
    let mut unexpected_notifications = 0;
    let outcome =
        protocol::receive_batch(&mut consumer, &data, &control, &mut output, false, || {
            unexpected_notifications += 1;
            Ok(())
        });
    assert_eq!(
        outcome,
        BatchOutcome {
            completed: 0,
            stop: Some(QueueError::Empty)
        }
    );
    assert_eq!(unexpected_notifications, 0);
    assert!(output.iter().all(|slot| slot.message().is_none()));
    Ok(())
}

#[test]
fn peer_death_returns_published_prefix_without_claiming_clean_eof() -> Result<(), QueueError> {
    let config = Config::new(2, 8)?;
    let (data, control) = backing(config);
    let mut producer = Cursor::new(config);
    producer.push(&data, &control, b"one")?;
    producer.push(&data, &control, b"two")?;
    let mut consumer = Cursor::new(config);
    let mut buffers = [[0; 8]; 3];
    let mut output: Vec<_> = buffers
        .iter_mut()
        .map(|bytes| ReceiveSlot::new(bytes))
        .collect();
    let mut notified = 0;
    let outcome =
        protocol::receive_batch(&mut consumer, &data, &control, &mut output, true, || {
            notified += 1;
            Ok(())
        });
    assert_eq!(
        outcome,
        BatchOutcome {
            completed: 2,
            stop: Some(QueueError::PeerDied)
        }
    );
    assert_eq!(notified, 1);
    assert_eq!(output[0].message(), Some(b"one".as_slice()));
    assert_eq!(output[1].message(), Some(b"two".as_slice()));
    assert_eq!(output[2].message(), None);
    assert_eq!(control.get(TAIL), 2);
    Ok(())
}

#[test]
fn graceful_marker_is_distinct_from_lifetime_peer_death() -> Result<(), QueueError> {
    let config = Config::new(1, 8)?;
    let (data, control) = backing(config);
    let mut producer = Cursor::new(config);
    producer.push(&data, &control, b"last")?;
    data.set(CLOSED, 1);
    let mut consumer = Cursor::new(config);
    let mut buffers = [[0; 8]; 2];
    let mut output: Vec<_> = buffers
        .iter_mut()
        .map(|bytes| ReceiveSlot::new(bytes))
        .collect();
    let outcome =
        protocol::receive_batch(&mut consumer, &data, &control, &mut output, true, || Ok(()));
    assert_eq!(
        outcome,
        BatchOutcome {
            completed: 1,
            stop: Some(QueueError::Closed)
        }
    );
    assert_eq!(output[0].message(), Some(b"last".as_slice()));
    assert_eq!(output[1].message(), None);
    Ok(())
}

#[test]
fn empty_batches_never_notify_or_advance_cursors() -> Result<(), QueueError> {
    let config = Config::new(1, 8)?;
    let (data, control) = backing(config);
    let mut producer = Cursor::new(config);
    let mut consumer = Cursor::new(config);
    let mut notified = 0;
    let sent = protocol::send_batch(&mut producer, &data, &control, &[], || {
        notified += 1;
        Ok(())
    });
    let received = protocol::receive_batch(&mut consumer, &data, &control, &mut [], true, || {
        notified += 1;
        Ok(())
    });
    assert_eq!(
        sent,
        BatchOutcome {
            completed: 0,
            stop: None
        }
    );
    assert_eq!(
        received,
        BatchOutcome {
            completed: 0,
            stop: None
        }
    );
    assert_eq!(notified, 0);
    assert_eq!(data.get(HEAD), 0);
    assert_eq!(control.get(TAIL), 0);
    Ok(())
}

#[test]
fn short_buffer_batch_exposes_only_committed_prefix() -> Result<(), QueueError> {
    let config = Config::new(2, 8)?;
    let (data, control) = backing(config);
    let mut producer = Cursor::new(config);
    producer.push(&data, &control, b"a")?;
    producer.push(&data, &control, b"second")?;
    let mut consumer = Cursor::new(config);
    let mut first = [0; 8];
    let mut short = [0xa5; 2];
    let mut output = [ReceiveSlot::new(&mut first), ReceiveSlot::new(&mut short)];
    let outcome = protocol::receive_batch(
        &mut consumer,
        &data,
        &control,
        &mut output,
        false,
        || Ok(()),
    );
    assert_eq!(
        outcome,
        BatchOutcome {
            completed: 1,
            stop: Some(QueueError::BufferTooSmall { required: 6 })
        }
    );
    assert_eq!(output[0].message(), Some(b"a".as_slice()));
    assert_eq!(output[1].message(), None);
    assert_eq!(control.get(TAIL), 1);
    assert_eq!(short, [0xa5; 2]);
    let mut retry = [0; 8];
    assert_eq!(consumer.pop(&data, &control, &mut retry)?, 6);
    assert_eq!(&retry[..6], b"second");
    Ok(())
}
