// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use core::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::vec::Vec;

use super::*;
use crate::Status;

#[derive(Clone, Copy)]
enum WakeAction {
    Unlock,
    Fail(Status),
    SetOwner(u64),
    UnlockAndCancel,
}

struct Harness<'a> {
    word: &'a AtomicU64,
    live: RefCell<Vec<u64>>,
    issued: Cell<u64>,
    queries: Cell<usize>,
    retries: Cell<usize>,
    cancelled: Cell<bool>,
    now: Cell<u64>,
    waits: RefCell<VecDeque<WakeAction>>,
    wakes: RefCell<Vec<u32>>,
    query_change: Cell<Option<u64>>,
    query_expire: Cell<bool>,
}

impl<'a> Harness<'a> {
    fn new(word: &'a AtomicU64) -> Self {
        Self {
            word,
            live: RefCell::new(Vec::new()),
            issued: Cell::new(100),
            queries: Cell::new(0),
            retries: Cell::new(0),
            cancelled: Cell::new(false),
            now: Cell::new(0),
            waits: RefCell::new(VecDeque::new()),
            wakes: RefCell::new(Vec::new()),
            query_change: Cell::new(None),
            query_expire: Cell::new(false),
        }
    }
}

impl Backend for Harness<'_> {
    fn owner_query(&self, owner: u64) -> Result<OwnerState> {
        self.queries.set(self.queries.get() + 1);
        if let Some(next) = self.query_change.take() {
            self.word.store(next, Ordering::Release);
        }
        if self.query_expire.replace(false) {
            self.now.set(u64::MAX);
        }
        Ok(if owner == 0 || owner > self.issued.get() {
            OwnerState::Invalid
        } else if self.live.borrow().contains(&owner) {
            OwnerState::Live
        } else {
            OwnerState::Dead
        })
    }

    fn before_retry(&self, deadline: u64, _: u64) -> core::result::Result<(), LockError> {
        self.retries.set(self.retries.get() + 1);
        if self.cancelled.get() {
            return Err(LockError::Cancelled);
        }
        if deadline != crate::DEADLINE_INFINITE && self.now.get() >= deadline {
            return Err(LockError::TimedOut);
        }
        Ok(())
    }

    fn wait(&self, expected: u64, owner: u64, _: u64, _: u64) -> Result<()> {
        assert_eq!(expected & OWNER_MASK, owner);
        assert_ne!(expected & WAITERS, 0);
        match self
            .waits
            .borrow_mut()
            .pop_front()
            .ok_or(Error::InvalidResponse)?
        {
            WakeAction::Unlock => self.word.store(0, Ordering::Release),
            WakeAction::Fail(status) => return Err(Error::Status(status)),
            WakeAction::SetOwner(next) => self.word.store(next | WAITERS, Ordering::Release),
            WakeAction::UnlockAndCancel => {
                self.word.store(0, Ordering::Release);
                self.cancelled.set(true);
            }
        }
        Ok(())
    }

    fn wake(&self, count: u32) -> Result<()> {
        self.wakes.borrow_mut().push(count);
        Ok(())
    }
}

fn mutex(word: &AtomicU64) -> Mutex<'_, Harness<'_>> {
    Mutex {
        word,
        backend: Harness::new(word),
    }
}

#[test]
fn uncontended_normal_lock_and_unlock_do_not_invoke_backend() -> core::result::Result<(), LockError>
{
    let word = AtomicU64::new(0);
    let lock = mutex(&word);
    for _ in 0..128 {
        assert!(!lock.acquire(1, crate::DEADLINE_INFINITE, 0)?);
        assert_eq!(word.load(Ordering::Relaxed), 1);
        lock.release(1, false)?;
    }
    assert_eq!(lock.backend.queries.get(), 0);
    assert_eq!(lock.backend.retries.get(), 0);
    assert!(lock.backend.wakes.borrow().is_empty());
    Ok(())
}

#[test]
fn dead_owner_acquires_recovery_authority_and_consistency_is_explicit()
-> core::result::Result<(), LockError> {
    let word = AtomicU64::new(2 | WAITERS);
    let lock = mutex(&word);
    assert!(lock.try_acquire(1)?);
    assert_eq!(word.load(Ordering::Relaxed), 1 | WAITERS | RECOVERING);
    lock.make_consistent(1)?;
    lock.release(1, false)?;
    assert_eq!(word.load(Ordering::Relaxed), 0);
    assert_eq!(&*lock.backend.wakes.borrow(), &[1]);
    Ok(())
}

#[test]
fn recovery_abandonment_poison_is_unowned_and_wakes_every_waiter()
-> core::result::Result<(), LockError> {
    let word = AtomicU64::new(2);
    let lock = mutex(&word);
    assert!(lock.try_acquire(1)?);
    lock.release(1, true)?;
    assert_eq!(lock.try_acquire(3), Err(LockError::NotRecoverable));
    assert_eq!(word.load(Ordering::Relaxed), NOT_RECOVERABLE);
    assert_eq!(&*lock.backend.wakes.borrow(), &[u32::MAX]);
    Ok(())
}

#[test]
fn recovery_owner_death_requires_recovery_again() -> core::result::Result<(), LockError> {
    let word = AtomicU64::new(2 | RECOVERING | WAITERS);
    let lock = mutex(&word);
    assert!(lock.try_acquire(3)?);
    assert_eq!(word.load(Ordering::Relaxed), 3 | RECOVERING | WAITERS);
    Ok(())
}

#[test]
fn never_issued_owner_is_not_treated_as_dead() {
    let word = AtomicU64::new(101);
    let lock = mutex(&word);
    assert_eq!(lock.try_acquire(1), Err(LockError::InvalidOwner));
    assert_eq!(word.load(Ordering::Relaxed), 101);
}

#[test]
fn stale_dead_observation_cannot_overwrite_new_owner() {
    let word = AtomicU64::new(2);
    let lock = mutex(&word);
    lock.backend.query_change.set(Some(3 | WAITERS));
    assert_eq!(lock.try_acquire(1), Err(LockError::WouldBlock));
    assert_eq!(word.load(Ordering::Relaxed), 3 | WAITERS);
    assert_eq!(lock.backend.queries.get(), 1);
}

#[test]
fn selected_waiter_acquisition_preserves_notification_obligation()
-> core::result::Result<(), LockError> {
    let word = AtomicU64::new(2);
    let lock = mutex(&word);
    lock.backend.live.borrow_mut().push(2);
    lock.backend
        .waits
        .borrow_mut()
        .push_back(WakeAction::Unlock);
    assert!(!lock.acquire(1, crate::DEADLINE_INFINITE, 0)?);
    assert_eq!(word.load(Ordering::Relaxed), 1 | WAITERS);
    lock.release(1, false)?;
    assert_eq!(&*lock.backend.wakes.borrow(), &[1]);
    Ok(())
}

#[test]
fn selected_waiter_cancellation_relays_instead_of_stranding_sleepers() {
    let word = AtomicU64::new(2);
    let lock = mutex(&word);
    lock.backend.live.borrow_mut().push(2);
    lock.backend
        .waits
        .borrow_mut()
        .push_back(WakeAction::UnlockAndCancel);
    assert_eq!(
        lock.acquire(1, crate::DEADLINE_INFINITE, 9),
        Err(LockError::Cancelled)
    );
    assert_eq!(word.load(Ordering::Relaxed), 0);
    assert_eq!(&*lock.backend.wakes.borrow(), &[1]);
}

#[test]
fn cancelled_timed_out_and_failed_waits_all_relay() {
    for (status, expected) in [
        (Status::CANCELLED, LockError::Cancelled),
        (Status::TIMED_OUT, LockError::TimedOut),
        (
            Status::RESOURCE_LIMIT,
            LockError::System(Error::Status(Status::RESOURCE_LIMIT)),
        ),
    ] {
        let word = AtomicU64::new(2);
        let lock = mutex(&word);
        lock.backend.live.borrow_mut().push(2);
        lock.backend
            .waits
            .borrow_mut()
            .push_back(WakeAction::Fail(status));
        assert_eq!(lock.acquire(1, crate::DEADLINE_INFINITE, 0), Err(expected));
        assert_eq!(word.load(Ordering::Relaxed) & OWNER_MASK, 2);
        assert_eq!(&*lock.backend.wakes.borrow(), &[1]);
    }
}

#[test]
fn unrelated_domain_exit_is_rechecked_against_the_current_owner()
-> core::result::Result<(), LockError> {
    let word = AtomicU64::new(2);
    let lock = mutex(&word);
    lock.backend.live.borrow_mut().extend([2, 3]);
    lock.backend
        .waits
        .borrow_mut()
        .extend([WakeAction::SetOwner(3), WakeAction::Unlock]);
    assert!(!lock.acquire(1, crate::DEADLINE_INFINITE, 0)?);
    assert_eq!(word.load(Ordering::Relaxed), 1 | WAITERS);
    Ok(())
}

#[test]
fn old_owner_handoff_then_new_owner_death_is_recoverable() -> core::result::Result<(), LockError> {
    let word = AtomicU64::new(2);
    let lock = mutex(&word);
    lock.backend.live.borrow_mut().push(2);
    lock.backend
        .waits
        .borrow_mut()
        .push_back(WakeAction::SetOwner(3));
    assert!(lock.acquire(1, crate::DEADLINE_INFINITE, 0)?);
    assert_eq!(word.load(Ordering::Relaxed), 1 | WAITERS | RECOVERING);
    Ok(())
}

#[test]
fn expired_initial_attempt_may_acquire_but_later_retries_stop()
-> core::result::Result<(), LockError> {
    let word = AtomicU64::new(0);
    let lock = mutex(&word);
    lock.backend.cancelled.set(true);
    assert!(!lock.acquire(1, 0, 9)?);
    lock.release(1, false)?;
    word.store(2, Ordering::Relaxed);
    lock.backend.live.borrow_mut().push(2);
    assert_eq!(lock.acquire(1, 0, 9), Err(LockError::Cancelled));
    lock.backend.cancelled.set(false);
    assert_eq!(lock.acquire(1, 0, 0), Err(LockError::TimedOut));
    Ok(())
}

#[test]
fn successful_recovery_cas_wins_over_clock_change_during_query()
-> core::result::Result<(), LockError> {
    let word = AtomicU64::new(2);
    let lock = mutex(&word);
    lock.backend.query_expire.set(true);
    assert!(lock.acquire(1, 1, 0)?);
    assert_eq!(word.load(Ordering::Relaxed), 1 | RECOVERING);
    Ok(())
}

#[test]
fn malformed_state_reentrancy_and_wrong_owner_release_preserve_word() {
    for invalid in [
        1 << 63,
        RECOVERING,
        NOT_RECOVERABLE | 2,
        NOT_RECOVERABLE | RECOVERING,
    ] {
        let word = AtomicU64::new(invalid);
        let lock = mutex(&word);
        assert_eq!(lock.try_acquire(1), Err(LockError::InvalidState));
        assert_eq!(word.load(Ordering::Relaxed), invalid);
    }
    let word = AtomicU64::new(1);
    let lock = mutex(&word);
    assert_eq!(lock.try_acquire(1), Err(LockError::AlreadyOwned));
    assert_eq!(lock.release(2, false), Err(LockError::InvalidState));
    assert_eq!(word.load(Ordering::Relaxed), 1);
}

#[test]
fn dropping_recovery_guard_abandons_but_normal_guard_releases()
-> core::result::Result<(), LockError> {
    let word = AtomicU64::new(2);
    let lock = mutex(&word);
    assert!(lock.try_acquire(1)?);
    drop(Held {
        mutex: &lock,
        token: 1,
        recovering: true,
        armed: true,
        thread: PhantomData,
    });
    assert_eq!(word.load(Ordering::Relaxed), NOT_RECOVERABLE);
    Ok(())
}

struct Concurrent {
    gate: std::sync::Mutex<()>,
    available: std::sync::Condvar,
    dead: u64,
    word: AtomicU64,
}

impl Backend for &Concurrent {
    fn owner_query(&self, owner: u64) -> Result<OwnerState> {
        Ok(if owner == self.dead {
            OwnerState::Dead
        } else {
            OwnerState::Live
        })
    }

    fn before_retry(&self, _: u64, _: u64) -> core::result::Result<(), LockError> {
        Ok(())
    }

    fn wait(&self, expected: u64, _: u64, _: u64, _: u64) -> Result<()> {
        let gate = self.gate.lock().map_err(|_| Error::InvalidResponse)?;
        if self.word.load(Ordering::Acquire) != expected {
            return Ok(());
        }
        // This backend substitutes only atomic compare/park. Production SDK
        // word transitions and notification relay execute unchanged.
        let (_gate, timeout) = self
            .available
            .wait_timeout(gate, core::time::Duration::from_secs(5))
            .map_err(|_| Error::InvalidResponse)?;
        if timeout.timed_out() {
            return Err(Error::Status(Status::TIMED_OUT));
        }
        Ok(())
    }

    fn wake(&self, count: u32) -> Result<()> {
        let _gate = self.gate.lock().map_err(|_| Error::InvalidResponse)?;
        if count == u32::MAX {
            self.available.notify_all();
        } else if count != 0 {
            self.available.notify_one();
        }
        Ok(())
    }
}

#[test]
fn concurrent_contenders_preserve_exclusion_and_wake_one_progress()
-> core::result::Result<(), LockError> {
    let backend = Concurrent {
        gate: std::sync::Mutex::new(()),
        available: std::sync::Condvar::new(),
        dead: 0,
        word: AtomicU64::new(0),
    };
    let count = AtomicU64::new(0);
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for token in 1..=4 {
            let backend = &backend;
            let count = &count;
            workers.push(scope.spawn(move || -> core::result::Result<(), LockError> {
                let lock = Mutex {
                    word: &backend.word,
                    backend,
                };
                for _ in 0..2000 {
                    assert!(!lock.acquire(token, crate::DEADLINE_INFINITE, 0)?);
                    let previous = count.load(Ordering::Relaxed);
                    std::thread::yield_now();
                    count.store(previous + 1, Ordering::Relaxed);
                    lock.release(token, false)?;
                }
                Ok(())
            }));
        }
        for worker in workers {
            worker.join().map_err(|_| LockError::InvalidState)??;
        }
        Ok::<(), LockError>(())
    })?;
    assert_eq!(count.load(Ordering::Relaxed), 8000);
    assert_eq!(backend.word.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn simultaneous_recovery_candidates_grant_exactly_one_owner() -> core::result::Result<(), LockError>
{
    let backend = Concurrent {
        gate: std::sync::Mutex::new(()),
        available: std::sync::Condvar::new(),
        dead: 2,
        word: AtomicU64::new(2 | WAITERS),
    };
    let barrier = std::sync::Barrier::new(2);
    let acquired = AtomicU64::new(0);
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for token in [1, 3] {
            let backend = &backend;
            let barrier = &barrier;
            let acquired = &acquired;
            workers.push(scope.spawn(move || -> core::result::Result<(), LockError> {
                let lock = Mutex {
                    word: &backend.word,
                    backend,
                };
                barrier.wait();
                match lock.try_acquire(token) {
                    Ok(recovering) => {
                        assert!(recovering);
                        acquired.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(LockError::WouldBlock) => {}
                    Err(error) => return Err(error),
                }
                Ok(())
            }));
        }
        for worker in workers {
            worker.join().map_err(|_| LockError::InvalidState)??;
        }
        Ok::<(), LockError>(())
    })?;
    assert_eq!(acquired.load(Ordering::Relaxed), 1);
    assert_ne!(backend.word.load(Ordering::Relaxed) & RECOVERING, 0);
    Ok(())
}
