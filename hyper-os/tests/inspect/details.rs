// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn raw(kind: ObjectKind, tag: u64, words: [u64; 8]) -> abi::HyperNativeObjectDetails {
    let mut result = abi::HyperNativeObjectDetails {
        koid: 1,
        object_kind: kind.as_raw(),
        record_kind: tag as u32,
        next_cursor: 0,
        payload: [0; 64],
    };
    for (chunk, word) in result.payload.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    result
}

#[test]
fn bootstrap_tid_zero_is_present_and_distinct_from_unassigned() {
    let mut value = raw(
        ThreadObject::KIND,
        abi::HYPER_NATIVE_OBJECT_DETAIL_THREAD,
        [0, 1, 0, 1, 0, 0, 0, 0],
    );
    assert!(matches!(
        decode(&value, DetailCursor::START),
        Ok(ObjectDetails {
            record: DetailRecord::Thread { tid: Some(0), .. },
            ..
        })
    ));
    value.payload[24] = 0;
    assert!(matches!(
        decode(&value, DetailCursor::START),
        Ok(ObjectDetails {
            record: DetailRecord::Thread { tid: None, .. },
            ..
        })
    ));
}

#[test]
fn rejects_bad_tags_reserved_words_and_nonadvancing_cursors() {
    let mut value = raw(
        VmarObject::KIND,
        abi::HYPER_NATIVE_OBJECT_DETAIL_VMAR,
        [0x1000, 0x1000, 1, 0, 0, 0, 0, 0],
    );
    assert!(decode(&value, DetailCursor::START).is_ok());
    value.next_cursor = 2;
    assert_eq!(decode(&value, DetailCursor(2)), Err(Error::InvalidResponse));
    value.next_cursor = 0;
    value.payload[63] = 1;
    assert_eq!(
        decode(&value, DetailCursor::START),
        Err(Error::InvalidResponse)
    );
    value.payload[63] = 0;
    value.object_kind = ThreadObject::KIND.as_raw();
    assert_eq!(
        decode(&value, DetailCursor::START),
        Err(Error::InvalidResponse)
    );
}

#[test]
fn rejects_invalid_mapping_protections_and_address_overflow() {
    for words in [
        [0x1000, 0x1000, 3, 1, 0, 0, 0, 0],
        [0x1000, 0x1000, 8, 8, 0, 0, 0, 0],
        [u64::MAX, 0x1000, 1, 1, 0, 0, 0, 0],
    ] {
        assert_eq!(
            decode(
                &raw(
                    VmarObject::KIND,
                    abi::HYPER_NATIVE_OBJECT_DETAIL_MAPPING,
                    words
                ),
                DetailCursor::START
            ),
            Err(Error::InvalidResponse)
        );
    }
}

#[test]
fn channel_counters_match_endpoint_kind() {
    let value = raw(
        ByteChannelObject::KIND,
        abi::HYPER_NATIVE_OBJECT_DETAIL_CHANNEL,
        [2, 1, 1, 3, 64, 1, 0, 0],
    );
    assert!(decode(&value, DetailCursor::START).is_ok());
    let wrong = raw(
        CapabilityChannelObject::KIND,
        abi::HYPER_NATIVE_OBJECT_DETAIL_CHANNEL,
        [2, 1, 1, 3, 64, 1, 0, 0],
    );
    assert_eq!(
        decode(&wrong, DetailCursor::START),
        Err(Error::InvalidResponse)
    );
}
