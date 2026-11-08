// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) mod raw_ops {
    use core::cell::Cell;
    std::thread_local! {
        static CALL: Cell<Option<[u64; 4]>> = const { Cell::new(None) };
    }
    pub(crate) unsafe fn wait(
        handle: u64,
        offset: u64,
        expected: u32,
        deadline: u64,
    ) -> hyper_abi::HyperNativeStatus {
        CALL.set(Some([handle, offset, u64::from(expected), deadline]));
        hyper_abi::HYPER_NATIVE_STATUS_TIMED_OUT
    }
    pub(crate) fn wake(handle: u64, offset: u64, count: u32) -> hyper_sys::CallResult {
        CALL.set(Some([handle, offset, u64::from(count), 0]));
        hyper_sys::CallResult {
            status: 0,
            value0: u64::from(count),
            value1: 0,
        }
    }
    pub(super) fn take_call() -> Option<[u64; 4]> {
        CALL.take()
    }
}

fn vmo() -> Result<WritableVmo> {
    // SAFETY: the test handle backend owns this synthetic VMO without a syscall.
    let handle = unsafe { crate::handle::adopt_produced_handle_excluding(10, &[])? };
    Ok(WritableVmo {
        handle,
        size: crate::memory::PAGE_SIZE,
    })
}

#[test]
fn typed_wait_preserves_absolute_deadline_and_error() -> Result<()> {
    let vmo = vmo()?;
    let deadline = 0x9123_4567_89ab_cdef;
    // SAFETY: the mock does not touch memory and there are no concurrent aliases.
    let result = unsafe { vmo.wait_u32(12, u32::MAX, deadline) };
    assert_eq!(result, Err(Error::Status(Status::TIMED_OUT)));
    assert_eq!(
        raw_ops::take_call(),
        Some([10, 12, u64::from(u32::MAX), deadline])
    );
    assert_eq!(vmo.wake_u32(12, 0)?, 0);
    assert_eq!(raw_ops::take_call(), Some([10, 12, 0, 0]));
    Ok(())
}

#[test]
fn invalid_offsets_never_invoke_and_wake_counts_are_bounded() -> Result<()> {
    let vmo = vmo()?;
    for offset in [1, vmo.size(), u64::MAX - 3] {
        assert!(vmo.wake_u32(offset, 1).is_err());
    }
    assert_eq!(raw_ops::take_call(), None);
    let result = |value0, value1| hyper_sys::CallResult {
        status: 0,
        value0,
        value1,
    };
    assert_eq!(decode_wake(result(2, 0), 2), Ok(2));
    assert_eq!(decode_wake(result(3, 0), 2), Err(Error::InvalidResponse));
    assert_eq!(decode_wake(result(0, 1), 2), Err(Error::InvalidResponse));
    assert_eq!(
        decode_wake(result(u64::MAX, 0), u32::MAX),
        Err(Error::InvalidResponse)
    );
    assert_eq!(
        decode_wake(
            hyper_sys::CallResult {
                status: hyper_abi::HYPER_NATIVE_STATUS_ACCESS_DENIED,
                value0: u64::MAX,
                value1: u64::MAX
            },
            2
        ),
        Err(Error::Status(Status::ACCESS_DENIED))
    );
    Ok(())
}
