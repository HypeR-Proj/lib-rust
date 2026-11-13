// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! The shared mutex algorithm. Tests execute this same protocol with deterministic
//! wait and death observations; only the capability transport is substituted.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{LockError, OwnerState};
use crate::{Error, Result};

pub(super) const OWNER_MASK: u64 = hyper_abi::HYPER_NATIVE_SYNC_OWNER_TOKEN_MAX;
pub(super) const WAITERS: u64 = hyper_abi::HYPER_NATIVE_SYNC_MUTEX_WAITERS;
pub(super) const RECOVERING: u64 = hyper_abi::HYPER_NATIVE_SYNC_MUTEX_RECOVERING;
pub(super) const NOT_RECOVERABLE: u64 = hyper_abi::HYPER_NATIVE_SYNC_MUTEX_NOT_RECOVERABLE;
const ALLOWED: u64 = OWNER_MASK | WAITERS | RECOVERING | NOT_RECOVERABLE;

pub(super) trait Backend {
    fn owner_query(&self, owner: u64) -> Result<OwnerState>;
    fn before_retry(&self, deadline: u64, cancellation: u64)
    -> core::result::Result<(), LockError>;
    fn wait(&self, expected: u64, owner: u64, deadline: u64, cancellation: u64) -> Result<()>;
    fn wake(&self, count: u32) -> Result<()>;
}

pub(super) struct Mutex<'word, B> {
    pub word: &'word AtomicU64,
    pub backend: B,
}

enum Attempt {
    Acquired { recovering: bool },
    Blocked { observed: u64 },
}

fn decode(value: u64) -> core::result::Result<u64, LockError> {
    let owner = value & OWNER_MASK;
    if value & !ALLOWED != 0 || (value & RECOVERING != 0 && owner == 0) {
        return Err(LockError::InvalidState);
    }
    if value & NOT_RECOVERABLE != 0 {
        if owner != 0 {
            return Err(LockError::InvalidState);
        }
        return Err(LockError::NotRecoverable);
    }
    Ok(owner)
}

impl<B: Backend> Mutex<'_, B> {
    fn attempt(&self, token: u64, slow: bool) -> core::result::Result<Attempt, LockError> {
        // The snapshot only selects a CAS/query; it never authorizes payload
        // access. Acquisition's successful CAS supplies the ordering edge.
        let observed = self.word.load(Ordering::Relaxed);
        let owner = decode(observed)?;
        if owner == token {
            return Err(LockError::AlreadyOwned);
        }
        let recovering = if owner == 0 {
            false
        } else {
            match self.backend.owner_query(owner).map_err(LockError::System)? {
                OwnerState::Live => return Ok(Attempt::Blocked { observed }),
                OwnerState::Dead => true,
                OwnerState::Invalid => return Err(LockError::InvalidOwner),
            }
        };
        let flags = (observed & WAITERS)
            | if slow { WAITERS } else { 0 }
            | if recovering { RECOVERING } else { 0 };
        // Normal acquisition observes the previous owner's Release unlock.
        // Recovery additionally relies on owner_query's Acquire observation of
        // kernel death publication: the dead owner did not perform an unlock.
        match self.word.compare_exchange(
            observed,
            token | flags,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => Ok(Attempt::Acquired { recovering }),
            Err(observed) => Ok(Attempt::Blocked { observed }),
        }
    }

    pub fn try_acquire(&self, token: u64) -> core::result::Result<bool, LockError> {
        match self.attempt(token, false)? {
            Attempt::Acquired { recovering } => Ok(recovering),
            Attempt::Blocked { .. } => Err(LockError::WouldBlock),
        }
    }

    pub fn acquire(
        &self,
        token: u64,
        deadline: u64,
        cancellation: u64,
    ) -> core::result::Result<bool, LockError> {
        // One nonblocking attempt is permitted even at an expired deadline.
        // Once CAS succeeds, ownership wins over a concurrent timeout/cancel.
        if let Attempt::Acquired { recovering } = self.attempt(token, false)? {
            return Ok(recovering);
        }
        let result = self.acquire_slow(token, deadline, cancellation);
        if result.is_err() {
            // The selected wake-one recipient may decline acquisition due to
            // timeout/cancel/error. Pass its notification opportunity onward.
            self.notify_or_exit(1);
        }
        result
    }

    fn acquire_slow(
        &self,
        token: u64,
        deadline: u64,
        cancellation: u64,
    ) -> core::result::Result<bool, LockError> {
        loop {
            self.backend.before_retry(deadline, cancellation)?;
            let observed = match self.attempt(token, true)? {
                Attempt::Acquired { recovering } => return Ok(recovering),
                Attempt::Blocked { observed } => observed,
            };
            let owner = decode(observed)?;
            if owner == 0 {
                continue;
            }
            let armed = observed | WAITERS;
            if self
                .word
                .compare_exchange(observed, armed, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            // The kernel compares the exact word while publishing all wait
            // sources; death, cancellation and unlock cannot fall between the
            // compare and queue admission. Any result requires a fresh CAS.
            self.backend
                .wait(armed, owner, deadline, cancellation)
                .map_err(LockError::from_wait)?;
        }
    }

    pub fn make_consistent(&self, token: u64) -> core::result::Result<(), LockError> {
        let mut observed = self.word.load(Ordering::Relaxed);
        loop {
            if decode(observed)? != token || observed & RECOVERING == 0 {
                return Err(LockError::InvalidState);
            }
            match self.word.compare_exchange(
                observed,
                observed & !RECOVERING,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => observed = current,
            }
        }
    }

    pub fn release(&self, token: u64, recovering: bool) -> core::result::Result<(), LockError> {
        let mut observed = self.word.load(Ordering::Relaxed);
        loop {
            if decode(observed)? != token || (observed & RECOVERING != 0) != recovering {
                return Err(LockError::InvalidState);
            }
            let next = if recovering { NOT_RECOVERABLE } else { 0 };
            match self
                .word
                .compare_exchange(observed, next, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => {
                    if recovering {
                        self.notify_or_exit(u32::MAX);
                    } else if observed & WAITERS != 0 {
                        self.notify_or_exit(1);
                    }
                    return Ok(());
                }
                Err(current) => observed = current,
            }
        }
    }

    fn notify_or_exit(&self, count: u32) {
        if self.backend.wake(count).is_err() {
            // A failed notification after committed release cannot be reported
            // as a reversible error. Termination publishes domain death and
            // prevents silently leaving waiters stranded behind a live owner.
            crate::handle::ownership_invariant();
        }
    }
}

/// Internal linear ownership. Both normal and recovering guards stay on their
/// joining Thread. It retains the mutex view through all notification work.
pub(super) struct Held<'mutex, 'word, B: Backend> {
    pub mutex: &'mutex Mutex<'word, B>,
    pub token: u64,
    pub recovering: bool,
    pub armed: bool,
    pub thread: PhantomData<*mut ()>,
}

impl<B: Backend> Drop for Held<'_, '_, B> {
    fn drop(&mut self) {
        if self.armed && self.mutex.release(self.token, self.recovering).is_err() {
            // Shared state corruption must not manufacture a successful unlock.
            crate::handle::ownership_invariant();
        }
    }
}

impl From<Error> for LockError {
    fn from(value: Error) -> Self {
        Self::System(value)
    }
}

#[cfg(test)]
#[path = "../../tests/sync_protocol.rs"]
mod tests;
