// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Process-shared non-recursive mutexes with explicit owner-death recovery.
//!
//! The kernel observes participant lifetime; acquisition and release remain
//! userspace atomic operations when uncontended. Recovery grants exclusion, not
//! payload validity: these guards deliberately never expose a reference to an
//! arbitrary Rust `T`. Shared payloads need independently validated, crash-valid
//! layouts and must not contain process-local references.

use core::marker::PhantomData;

use crate::handle::{HandleRef, Koid, OwnedHandle, SyncDomainObject, VmoObject};
use crate::{Error, Result, Status};

mod mapping;
mod native;
mod protocol;
pub use mapping::SharedMutexRegion;
use native::NativeWord;

/// Owner identity observation, never authority to control a Thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerState {
    Invalid,
    Live,
    /// The Thread has stopped executing. Completed writes are visible through
    /// the kernel's Acquire death-observation contract, but may be inconsistent.
    Dead,
}

/// An acquisition failure. Every variant means that no mutex was acquired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockError {
    WouldBlock,
    TimedOut,
    Cancelled,
    NotRecoverable,
    /// The calling Thread already owns this non-recursive mutex.
    AlreadyOwned,
    /// A reserved bit or impossible state combination was observed.
    InvalidState,
    /// A lock word named a token that this domain never issued.
    InvalidOwner,
    /// The participant and mutex belong to different kernel domains.
    DomainMismatch,
    System(Error),
}

impl LockError {
    fn from_wait(error: Error) -> Self {
        match error {
            Error::Status(Status::TIMED_OUT) => Self::TimedOut,
            Error::Status(Status::CANCELLED) => Self::Cancelled,
            error => Self::System(error),
        }
    }
}

impl core::fmt::Display for LockError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for LockError {}

/// Scoped participant identities and fixed shared-memory attribution.
///
/// A domain can bind multiple RAM ranges. Closing the last domain handle does
/// not remove bindings from still-live backings. No call tracks held mutexes.
pub struct SyncDomain {
    handle: OwnedHandle<SyncDomainObject>,
    identity: Koid,
}

impl SyncDomain {
    pub fn create() -> Result<Self> {
        let result = native::create();
        Status::from_raw(result.status).into_result()?;
        // SAFETY: creation returns a unique output capability with no inputs.
        let handle = unsafe {
            crate::handle::adopt_produced_handle_excluding::<SyncDomainObject>(result.value0, &[])?
        };
        if result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Self::from_handle(handle)
    }

    /// Retains an imported domain and caches its identity using INSPECT authority.
    /// Duplicated handles for the same domain therefore share participant identity
    /// without an additional syscall on the mutex acquisition path.
    pub fn from_handle(handle: OwnedHandle<SyncDomainObject>) -> Result<Self> {
        let identity = handle.basic_info()?.koid;
        Ok(Self { handle, identity })
    }

    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, SyncDomainObject> {
        self.handle.as_handle_ref()
    }

    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<SyncDomainObject> {
        self.handle
    }

    /// Attributes a nonempty aligned range to this domain. Both capabilities
    /// require `SYNC_CONFIGURE`; ordinary WRITE authority cannot rebind memory.
    /// Overlap with the same domain is allowed; conflicting domains are rejected.
    /// Attribution remains fixed until backing retirement, independent of handles.
    pub fn bind(&self, vmo: HandleRef<'_, VmoObject>, offset: u64, length: u64) -> Result<()> {
        native::bind(
            self.as_handle_ref().raw().get(),
            vmo.raw().get(),
            offset,
            length,
        )
    }

    /// Registers this calling Thread once. Dropping the returned local view does
    /// not declare a live Thread dead. A later join returns the same live token.
    pub fn join(&self) -> Result<Participant<'_>> {
        let result = native::join(self.as_handle_ref().raw().get());
        Status::from_raw(result.status).into_result()?;
        if result.value0 == 0 || result.value0 > protocol::OWNER_MASK || result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(Participant {
            domain: self,
            token: result.value0,
            thread: PhantomData,
        })
    }

    pub fn owner_query(&self, token: u64) -> Result<OwnerState> {
        native::owner_query(self.as_handle_ref().raw().get(), token)
    }
}

/// Calling-Thread registration. This value and every derived guard are neither
/// Send nor Sync: using another live Thread's token would misattribute its death.
///
/// ```compile_fail
/// fn transferable<T: Send>() {}
/// transferable::<hyper_os::sync::Participant<'static>>();
/// ```
/// ```compile_fail
/// fn shared<T: Sync>() {}
/// shared::<hyper_os::sync::Participant<'static>>();
/// ```
pub struct Participant<'domain> {
    domain: &'domain SyncDomain,
    token: u64,
    thread: PhantomData<*mut ()>,
}

impl Participant<'_> {
    /// Observation identity only; not a capability or a transferable registration.
    #[must_use]
    pub const fn token(&self) -> u64 {
        self.token
    }
}

/// One-shot cancellation shared by any number of contended acquisitions.
/// Cancellation is a persistent Event level; it never polls or periodically
/// interrupts a parked wait. There is deliberately no reset operation.
pub struct Cancellation {
    event: crate::event::Event,
}

impl Cancellation {
    pub fn new() -> Result<Self> {
        Ok(Self {
            event: crate::event::Event::create()?,
        })
    }

    pub fn cancel(&self) -> Result<()> {
        self.event.signal(0, crate::event::Event::SIGNALED)
    }

    pub fn is_cancelled(&self) -> Result<bool> {
        native::cancelled(self.raw())
    }

    fn raw(&self) -> u64 {
        self.event.as_handle_ref().raw().get()
    }
}

/// A validated control word within a retained mapping. It owns no payload and
/// its destructor never resets shared state or revokes another participant.
pub struct SharedMutex<'word> {
    core: protocol::Mutex<'word, NativeWord<'word>>,
}

impl<'word> SharedMutex<'word> {
    fn check_participant(
        &self,
        participant: &Participant<'_>,
    ) -> core::result::Result<(), LockError> {
        if self.core.backend.domain.identity != participant.domain.identity {
            return Err(LockError::DomainMismatch);
        }
        Ok(())
    }

    /// A bounded nonblocking attempt. Owner-death observation may invoke the
    /// kernel once, but this operation never parks or loops waiting for a lock.
    pub fn try_lock<'lock>(
        &'lock self,
        participant: &'lock Participant<'_>,
    ) -> core::result::Result<Acquisition<'lock, 'word>, LockError> {
        self.check_participant(participant)?;
        let recovering = self.core.try_acquire(participant.token)?;
        Ok(self.acquired(participant.token, recovering))
    }

    pub fn lock<'lock>(
        &'lock self,
        participant: &'lock Participant<'_>,
    ) -> core::result::Result<Acquisition<'lock, 'word>, LockError> {
        self.lock_until(participant, crate::DEADLINE_INFINITE, None)
    }

    /// Acquires before an absolute monotonic blocking/retry deadline. One initial
    /// nonblocking attempt is allowed even if already expired or cancelled.
    /// Every subsequent retry checks both. A successful ownership CAS commits
    /// acquisition even if deadline/cancellation races the preceding check.
    ///
    /// `OwnerDied` owns recovery authority; it is never an unowned error.
    pub fn lock_until<'lock>(
        &'lock self,
        participant: &'lock Participant<'_>,
        deadline: u64,
        cancellation: Option<&Cancellation>,
    ) -> core::result::Result<Acquisition<'lock, 'word>, LockError> {
        self.check_participant(participant)?;
        let recovering = self.core.acquire(
            participant.token,
            deadline,
            cancellation.map_or(0, Cancellation::raw),
        )?;
        Ok(self.acquired(participant.token, recovering))
    }

    fn acquired(&self, token: u64, recovering: bool) -> Acquisition<'_, 'word> {
        let held = protocol::Held {
            mutex: &self.core,
            token,
            recovering,
            armed: true,
            thread: PhantomData,
        };
        if recovering {
            Acquisition::OwnerDied(RecoveryGuard { held })
        } else {
            Acquisition::Acquired(Guard { held })
        }
    }
}

/// Both outcomes own the mutex. Only the application can validate recovered data.
#[must_use]
pub enum Acquisition<'lock, 'word> {
    Acquired(Guard<'lock, 'word>),
    OwnerDied(RecoveryGuard<'lock, 'word>),
}

/// Exclusive normal ownership; Drop performs Release unlock and wake-one if needed.
/// Unexpected irreversible notification failure terminates the current process
/// so domain death notification cannot leave sleepers silently stranded.
///
/// ```compile_fail
/// fn transferable<T: Send>() {}
/// transferable::<hyper_os::sync::Guard<'static, 'static>>();
/// ```
pub struct Guard<'lock, 'word> {
    held: protocol::Held<'lock, 'word, NativeWord<'word>>,
}

impl Guard<'_, '_> {
    pub fn unlock(self) {
        drop(self);
    }

    #[must_use]
    pub fn owner_token(&self) -> u64 {
        self.held.token
    }
}

/// Exclusive recovery authority. Drop without `mark_consistent` permanently
/// marks this mutex unrecoverable and wakes all waiters. It cannot dereference
/// unvalidated payload. If this Thread dies, a later owner can attempt recovery.
///
/// ```compile_fail
/// fn transferable<T: Send>() {}
/// transferable::<hyper_os::sync::RecoveryGuard<'static, 'static>>();
/// ```
/// ```compile_fail
/// fn typed_payload(guard: &mut hyper_os::sync::RecoveryGuard<'_, '_>) {
///     let _: &mut u64 = &mut **guard;
/// }
/// ```
pub struct RecoveryGuard<'lock, 'word> {
    held: protocol::Held<'lock, 'word, NativeWord<'word>>,
}

impl<'lock, 'word> RecoveryGuard<'lock, 'word> {
    /// Declares application repair complete; no kernel validates business data.
    /// Failure returns the still-owned recovery guard instead of losing it.
    pub fn mark_consistent(
        mut self,
    ) -> core::result::Result<Guard<'lock, 'word>, RecoveryFailure<'lock, 'word>> {
        if let Err(error) = self.held.mutex.make_consistent(self.held.token) {
            return Err(RecoveryFailure { error, guard: self });
        }
        self.held.recovering = false;
        Ok(Guard { held: self.held })
    }

    pub fn abandon(self) {
        drop(self);
    }

    #[must_use]
    pub fn owner_token(&self) -> u64 {
        self.held.token
    }
}

/// A failed consistency transition still owns recovery authority.
pub struct RecoveryFailure<'lock, 'word> {
    pub error: LockError,
    pub guard: RecoveryGuard<'lock, 'word>,
}
