// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) mod raw_ops {
    use core::cell::Cell;

    std::thread_local! {
        static CALL: Cell<Option<(u64, u64, u64)>> = const { Cell::new(None) };
        static STATUS: Cell<hyper_abi::HyperNativeStatus> = const { Cell::new(0) };
    }

    pub(crate) fn create() -> hyper_sys::CallResult {
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_OK,
            value0: u64::from(hyper_abi::HYPER_NATIVE_OBJECT_EVENT),
            value1: 0,
        }
    }

    pub(crate) fn signal(handle: u64, clear: u64, set: u64) -> hyper_abi::HyperNativeStatus {
        CALL.set(Some((handle, clear, set)));
        STATUS.get()
    }

    pub(super) fn result(status: hyper_abi::HyperNativeStatus) {
        STATUS.set(status);
    }

    pub(super) fn call() -> Option<(u64, u64, u64)> {
        CALL.get()
    }
}

#[test]
fn owner_round_trip_and_signal_masks_preserve_authority() -> Result<()> {
    let event = Event::create()?;
    let raw = event.as_handle_ref().raw().get();
    let event = Event::from_handle(event.into_handle());
    event.signal(0, Event::SIGNALED)?;
    assert_eq!(raw_ops::call(), Some((raw, 0, Event::SIGNALED)));
    event.signal(Event::SIGNALED, 0)?;
    assert_eq!(raw_ops::call(), Some((raw, Event::SIGNALED, 0)));
    assert!(crate::wait::ObjectSignals::<EventObject>::SIGNALED.is_present_in(Event::SIGNALED));
    assert!(!crate::wait::ObjectSignals::<EventObject>::SIGNALED.is_present_in(0));
    Ok(())
}

#[test]
fn rejected_signal_preserves_owner_and_kernel_error() -> Result<()> {
    let event = Event::create()?;
    let raw = event.as_handle_ref().raw();
    raw_ops::result(hyper_abi::HYPER_NATIVE_STATUS_ACCESS_DENIED);
    assert_eq!(
        event.signal(0, Event::SIGNALED),
        Err(Error::Status(Status::ACCESS_DENIED))
    );
    assert_eq!(event.as_handle_ref().raw(), raw);
    raw_ops::result(hyper_abi::HYPER_NATIVE_STATUS_INVALID_ARGUMENT);
    assert_eq!(
        event.signal(Event::SIGNALED, Event::SIGNALED),
        Err(Error::Status(Status::INVALID_ARGUMENT))
    );
    raw_ops::result(hyper_abi::HYPER_NATIVE_STATUS_OK);
    Ok(())
}

#[test]
fn creation_rejects_bad_output_and_does_not_adopt_error_results() {
    let mut result = raw_ops::create();
    result.value0 = 0;
    assert!(matches!(Event::adopt(result), Err(Error::InvalidResponse)));
    result = raw_ops::create();
    result.value1 = 1;
    assert!(matches!(Event::adopt(result), Err(Error::InvalidResponse)));
    result = raw_ops::create();
    result.value0 = u64::from(hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL);
    assert!(matches!(
        Event::adopt(result),
        Err(Error::UnexpectedObjectKind { .. })
    ));
    result.status = hyper_abi::HYPER_NATIVE_STATUS_NO_MEMORY;
    result.value0 = 0;
    assert!(matches!(
        Event::adopt(result),
        Err(Error::Status(Status::NO_MEMORY))
    ));
}
