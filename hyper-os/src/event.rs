// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Owned, manually signalled Events with independently attenuable authority.
//!
//! Use [`crate::wait::ObjectSignals::SIGNALED`] with an Event handle in a
//! [`crate::wait::WaitSet`] or ordinary object wait. Events retain a level, not
//! a notification count. Shared-memory protocols must provide their own atomic
//! publication ordering and recheck their condition before blocking.

use crate::handle::{AnyObject, EventObject, HandleRef, OwnedHandle};
use crate::{Error, Result, Status};

/// One Event capability. Waiting and signalling require their respective rights.
///
/// Duplicate or transfer an attenuated handle through [`Self::as_handle_ref`]
/// or [`Self::into_handle`]; constructing this wrapper never grants rights.
pub struct Event {
    handle: OwnedHandle<EventObject>,
}

impl Event {
    /// The single application-controlled Event signal.
    pub const SIGNALED: u64 = hyper_abi::HYPER_NATIVE_SIGNAL_EVENT_SIGNALED;

    /// Creates an initially clear Event with WAIT, SIGNAL, INSPECT, DUPLICATE
    /// and TRANSFER rights.
    pub fn create() -> Result<Self> {
        Self::adopt(raw_ops::create())
    }

    fn adopt(result: hyper_sys::CallResult) -> Result<Self> {
        Status::from_raw(result.status).into_result()?;
        // SAFETY: successful creation transfers one fresh owner. Adopt before
        // checking metadata so malformed success still closes its output.
        let handle = unsafe {
            crate::handle::adopt_produced_handle_excluding::<AnyObject>(result.value0, &[])?
        };
        if result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        let handle = handle
            .downcast::<EventObject>()
            .map_err(|failure| failure.error())?;
        Ok(Self::from_handle(handle))
    }

    /// Retains an existing Event capability, including attenuated capabilities.
    pub const fn from_handle(handle: OwnedHandle<EventObject>) -> Self {
        Self { handle }
    }

    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, EventObject> {
        self.handle.as_handle_ref()
    }

    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<EventObject> {
        self.handle
    }

    /// Atomically clears and asserts signals using SIGNAL authority.
    ///
    /// Masks may contain only [`Self::SIGNALED`]; overlap is invalid. Repeatedly
    /// asserting an already asserted level does not queue another notification.
    /// A handle with only WAIT rights can still be wrapped, but this operation
    /// reports `ACCESS_DENIED`. Errors preserve both ownership and signal state.
    pub fn signal(&self, clear: u64, set: u64) -> Result<()> {
        Status::from_raw(raw_ops::signal(
            self.as_handle_ref().raw().get(),
            clear,
            set,
        ))
        .into_result()
    }
}

#[cfg(not(test))]
mod raw_ops {
    pub(super) fn create() -> hyper_sys::CallResult {
        // SAFETY: Event::adopt assumes the unique output owner on success.
        unsafe { hyper_sys::event_create() }
    }

    pub(super) fn signal(handle: u64, clear: u64, set: u64) -> hyper_abi::HyperNativeStatus {
        // SAFETY: Event::signal retains its owned Event throughout this call.
        unsafe { hyper_sys::event_signal(handle, clear, set) }
    }
}

#[cfg(test)]
#[path = "../tests/event.rs"]
mod tests;

#[cfg(test)]
use tests::raw_ops;
