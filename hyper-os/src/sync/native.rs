// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Capability transport for the userspace mutex protocol.

use super::{LockError, OwnerState, SyncDomain, protocol::Backend};
use crate::handle::{HandleRef, VmoObject};
use crate::{Error, Result, Status};

pub(super) struct NativeWord<'owner> {
    pub domain: &'owner SyncDomain,
    pub vmo: HandleRef<'owner, VmoObject>,
    pub offset: u64,
}

pub(super) fn create() -> hyper_sys::CallResult {
    // SAFETY: SyncDomain::create adopts the returned owner on success.
    unsafe { hyper_sys::sync_domain_create(0) }
}

pub(super) fn bind(domain: u64, vmo: u64, offset: u64, length: u64) -> Result<()> {
    let record = hyper_abi::HyperNativeSyncDomainBinding {
        options: 0,
        vmo,
        offset,
        length,
        reserved: 0,
    };
    // SAFETY: SyncDomain::bind retains both capabilities and this stack record.
    Status::from_raw(unsafe {
        hyper_sys::sync_domain_bind(domain, &record, core::mem::size_of_val(&record))
    })
    .into_result()
}

pub(super) fn join(domain: u64) -> hyper_sys::CallResult {
    // SAFETY: SyncDomain::join retains its borrowed owner throughout the call.
    unsafe { hyper_sys::sync_domain_join(domain, 0) }
}

pub(super) fn owner_query(domain: u64, token: u64) -> Result<OwnerState> {
    // SAFETY: SyncDomain or NativeWord retains domain; token grants no authority.
    let result = unsafe { hyper_sys::sync_domain_owner_query(domain, token, 0) };
    Status::from_raw(result.status).into_result()?;
    if result.value1 != 0 {
        return Err(Error::InvalidResponse);
    }
    match result.value0 {
        hyper_abi::HYPER_NATIVE_SYNC_OWNER_INVALID => Ok(OwnerState::Invalid),
        hyper_abi::HYPER_NATIVE_SYNC_OWNER_LIVE => Ok(OwnerState::Live),
        hyper_abi::HYPER_NATIVE_SYNC_OWNER_DEAD => Ok(OwnerState::Dead),
        _ => Err(Error::InvalidResponse),
    }
}

pub(super) fn cancelled(cancellation: u64) -> Result<bool> {
    // SAFETY: Cancellation privately retains an Event that can only be set, not
    // cleared. Deadline zero observes its level without entering a parked wait.
    let result =
        unsafe { hyper_sys::object_wait_one(cancellation, crate::event::Event::SIGNALED, 0) };
    match Status::from_raw(result.status) {
        Status::TIMED_OUT => Ok(false),
        Status::OK if result.value0 & crate::event::Event::SIGNALED != 0 && result.value1 == 0 => {
            Ok(true)
        }
        Status::OK => Err(Error::InvalidResponse),
        status => Err(Error::Status(status)),
    }
}

pub(super) fn validate_word(word: &NativeWord<'_>) -> Result<()> {
    // Wait authority is needed even by a view which is initially uncontended.
    let domain = word.domain.as_handle_ref().info()?;
    let required = crate::Rights::SYNC_WAIT
        .union(crate::Rights::SYNC_WAKE)
        .union(crate::Rights::INSPECT);
    if !domain.rights.contains(required) {
        return Err(Error::Status(Status::ACCESS_DENIED));
    }
    let vmo = word.vmo.info()?;
    if !vmo
        .rights
        .contains(crate::Rights::READ.union(crate::Rights::WRITE))
    {
        return Err(Error::Status(Status::ACCESS_DENIED));
    }
    word.wake(0)
}

impl Backend for NativeWord<'_> {
    fn owner_query(&self, owner: u64) -> Result<OwnerState> {
        owner_query(self.domain.as_handle_ref().raw().get(), owner)
    }

    fn before_retry(
        &self,
        deadline: u64,
        cancellation: u64,
    ) -> core::result::Result<(), LockError> {
        if cancellation != 0 && cancelled(cancellation).map_err(LockError::System)? {
            return Err(LockError::Cancelled);
        }
        if deadline != crate::DEADLINE_INFINITE
            && crate::time::monotonic_now()
                .map_err(LockError::System)?
                .as_nanoseconds()
                >= deadline
        {
            return Err(LockError::TimedOut);
        }
        Ok(())
    }

    fn wait(&self, expected: u64, owner: u64, deadline: u64, cancellation: u64) -> Result<()> {
        let record = hyper_abi::HyperNativeSyncDomainWait {
            options: 0,
            vmo: self.vmo.raw().get(),
            offset: self.offset,
            expected,
            owner,
            deadline,
            cancellation,
            reserved: 0,
        };
        // SAFETY: the mapping retains the aligned shared atomic and handles;
        // lock_until retains optional cancellation through this blocking call.
        let result = unsafe {
            hyper_sys::sync_domain_wait_u64(
                self.domain.as_handle_ref().raw().get(),
                &record,
                core::mem::size_of_val(&record),
            )
        };
        Status::from_raw(result.status).into_result()?;
        match (result.value0, result.value1) {
            (hyper_abi::HYPER_NATIVE_SYNC_WAIT_RECHECK, 0) => Ok(()),
            (hyper_abi::HYPER_NATIVE_SYNC_WAIT_OWNER_EXITED, token) if token == owner => Ok(()),
            _ => Err(Error::InvalidResponse),
        }
    }

    fn wake(&self, count: u32) -> Result<()> {
        // SAFETY: the word view retains its validated domain and VMO capabilities.
        let result = unsafe {
            hyper_sys::sync_domain_wake_u64(
                self.domain.as_handle_ref().raw().get(),
                self.vmo.raw().get(),
                self.offset,
                count,
                0,
            )
        };
        Status::from_raw(result.status).into_result()?;
        if result.value0 > u64::from(count) || result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }
}
