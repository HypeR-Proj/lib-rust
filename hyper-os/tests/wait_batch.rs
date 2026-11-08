// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn record(id: u64, signals: u64, sequence: u64) -> [u8; 24] {
    let mut bytes = [0; 24];
    bytes[..8].copy_from_slice(&id.to_le_bytes());
    bytes[8..16].copy_from_slice(&signals.to_le_bytes());
    bytes[16..].copy_from_slice(&sequence.to_le_bytes());
    bytes
}

fn result(count: u64) -> hyper_sys::CallResult {
    hyper_sys::CallResult {
        status: 0,
        value0: count,
        value1: 0,
    }
}

#[test]
fn successful_prefix_ignores_partial_or_stale_tail() -> Result<()> {
    let records = [record(8, 2, 5), record(0, u64::MAX, 9), record(12, 4, 7)];
    let stale = Notification::decode(&records[2])?;
    let mut output = [Some(stale); 3];
    assert_eq!(decode_batch(result(1), &records, &mut output)?, 1);
    assert_eq!(output[0], Some(Notification::decode(&records[0])?));
    assert_eq!(output[1..], [None, None]);
    Ok(())
}

#[test]
fn full_batch_preserves_registration_sequence_and_order() -> Result<()> {
    let records = [record(u64::MAX, 1, 42), record(2, 4, u64::MAX)];
    let mut output = [None; 2];
    assert_eq!(decode_batch(result(2), &records, &mut output)?, 2);
    for (actual, bytes) in output.iter().zip(&records) {
        assert_eq!(*actual, Some(Notification::decode(bytes)?));
    }
    Ok(())
}

#[test]
fn malformed_count_and_records_never_expose_a_partial_decoded_batch() -> Result<()> {
    let records = [record(1, 1, 2), record(0, 1, 2)];
    let stale = Notification::decode(&records[0])?;
    let mut output = [Some(stale); 2];
    for count in [0, 2, 3, u64::MAX] {
        assert_eq!(
            decode_batch(result(count), &records, &mut output),
            Err(Error::InvalidResponse)
        );
        assert_eq!(output, [None; 2]);
    }
    let mut reserved = result(1);
    reserved.value1 = 1;
    assert_eq!(
        decode_batch(reserved, &records, &mut output),
        Err(Error::InvalidResponse)
    );
    let missing_signals = [record(1, 0, 5)];
    assert_eq!(
        decode_batch(result(1), &missing_signals, &mut output),
        Err(Error::InvalidResponse)
    );
    Ok(())
}

#[test]
fn failure_does_not_expose_output_or_auxiliary_results() -> Result<()> {
    let records = [record(1, 1, 2)];
    let mut output = [Some(Notification::decode(&records[0])?)];
    let mut failed = result(1);
    failed.status = hyper_abi::HYPER_NATIVE_STATUS_TIMED_OUT;
    assert_eq!(
        decode_batch(failed, &records, &mut output),
        Err(Error::Status(Status::TIMED_OUT))
    );
    assert_eq!(output, [None]);
    Ok(())
}
