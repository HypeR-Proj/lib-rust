// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use std::sync::Mutex;

static CALL: Mutex<[u64; 8]> = Mutex::new([0; 8]);

#[unsafe(no_mangle)]
extern "C" fn hyper_native_object_factory() -> u64 {
    0x1234
}

#[unsafe(no_mangle)]
extern "C" fn hyper_native_invoke6(
    target: u64,
    operation: u64,
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
) -> hyper_sys::CallResult {
    if let Ok(mut call) = CALL.lock() {
        *call = [target, operation, a, b, c, d, e, f];
    }
    hyper_sys::CallResult {
        status: -2,
        value0: 0x4321,
        value1: 0,
    }
}

#[test]
fn event_wrappers_preserve_full_width_masks_and_zero_reserved_registers() -> Result<(), String> {
    // SAFETY: this test provides the local veneers and no actual handles escape.
    let result = unsafe { hyper_sys::event_create() };
    assert_eq!(result.status, -2);
    assert_eq!(result.value0, 0x4321);
    assert_eq!(
        *CALL.lock().map_err(|error| error.to_string())?,
        [
            0x1234,
            hyper_sys::abi::HYPER_NATIVE_OP_EVENT_CREATE,
            0,
            0,
            0,
            0,
            0,
            0
        ]
    );
    // SAFETY: the local veneer records the invocation without dereferencing handles.
    let status = unsafe { hyper_sys::event_signal(0x123, 1 << 63, 7) };
    assert_eq!(status, -2);
    assert_eq!(
        *CALL.lock().map_err(|error| error.to_string())?,
        [
            0x123,
            hyper_sys::abi::HYPER_NATIVE_OP_EVENT_SIGNAL,
            1 << 63,
            7,
            0,
            0,
            0,
            0
        ]
    );
    Ok(())
}
