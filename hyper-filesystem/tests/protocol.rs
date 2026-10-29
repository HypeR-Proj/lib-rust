// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use hyper_filesystem::protocol::*;

fn request() -> Request<'static> {
    Request {
        window_token: 0,
        cursor: hyper_filesystem::protocol::DirectoryCursor::START,
        sequence: 17,
        operation: Operation::Rename,
        offset: 0,
        length: 0,
        path: "dir/file",
        target: "renamed",
        accessed: None,
        modified: None,
    }
}
#[test]
fn request_validates_exact_frame_paths_and_sequence() -> Result<(), &'static str> {
    let mut bytes = [0; REQUEST_BYTES];
    let length = request().encode(&mut bytes).ok_or("valid request")?;
    let decoded = Request::decode(&bytes[..length]).ok_or("valid frame")?;
    assert_eq!(decoded.path, "dir/file");
    assert!(Request::decode(&bytes[..length + 1]).is_none());
    for path in ["../escape", "/root", "a//b", "a/./b", "nul\0"] {
        assert!(Request { path, ..request() }.encode(&mut bytes).is_none());
    }
    assert!(
        Request {
            sequence: 0,
            ..request()
        }
        .encode(&mut bytes)
        .is_none()
    );
    Ok(())
}
#[test]
fn response_rejects_mismatched_transaction_and_malformed_metadata() {
    let mut bytes = [0; RESPONSE_BYTES];
    let mut response = Response {
        sequence: 17,
        operation: Operation::Stat,
        result: Ok(0),
        entry: Entry::empty(),
    };
    assert!(response.encode(&mut bytes).is_some());
    assert!(Response::decode(&bytes, 17, Operation::Stat).is_some());
    assert!(Response::decode(&bytes, 18, Operation::Stat).is_none());
    assert!(Response::decode(&bytes, 17, Operation::Read).is_none());
    assert!(Response::decode(&bytes[..RESPONSE_BYTES - 1], 17, Operation::Stat).is_none());
    bytes[56..64].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(Response::decode(&bytes, 17, Operation::Stat).is_none());
    response.entry.name_len = usize::MAX;
    assert!(response.encode(&mut bytes).is_none());
    response.entry = Entry::empty();
    response.entry.kind = 999;
    assert!(response.encode(&mut bytes).is_none());
    response.entry = Entry::empty();
    response.result = Ok(1);
    assert!(response.encode(&mut bytes).is_none());
}

#[test]
fn borrowed_response_fills_existing_metadata_without_an_owned_name_copy() -> Result<(), &'static str>
{
    assert!(core::mem::size_of::<ResponseRef<'_>>() <= 160);
    let mut response = Response {
        sequence: 17,
        operation: Operation::Stat,
        result: Ok(0),
        entry: Entry::empty(),
    };
    response.entry.name.fill(b'x');
    response.entry.name_len = NAME_BYTES;
    response.entry.kind = FILE;
    response.entry.mode = 0o640;
    response.entry.size = 123;
    response.entry.created = hyper_filesystem::Timestamp::new(1, 2);
    response.entry.accessed = hyper_filesystem::Timestamp::new(3, 4);
    response.entry.modified = hyper_filesystem::Timestamp::new(5, 6);
    let mut bytes = [0; RESPONSE_BYTES];
    let mut output = Entry::empty();
    for name_len in [NAME_BYTES, 3, 0] {
        response.entry.name_len = name_len;
        response.encode(&mut bytes).ok_or("encode")?;
        let view = ResponseRef::decode(&bytes, 17, Operation::Stat).ok_or("decode")?;
        assert_eq!(view.result(), Ok(0));
        view.entry_into(&mut output);
        assert_eq!(output.name_len, name_len);
        assert!(output.name[..name_len].iter().all(|b| *b == b'x'));
        assert!(output.name[name_len..].iter().all(|b| *b == 0));
        assert_eq!((output.kind, output.mode, output.size), (FILE, 0o640, 123));
        assert_eq!(output.created, response.entry.created);
        assert_eq!(output.accessed, response.entry.accessed);
        assert_eq!(output.modified, response.entry.modified);
    }
    Ok(())
}

#[test]
fn borrowed_response_validates_metadata_even_for_scalar_and_error_replies()
-> Result<(), &'static str> {
    for result in [Ok(0), Err(Error::Missing)] {
        let response = Response {
            sequence: 17,
            operation: Operation::Sync,
            result,
            entry: Entry::empty(),
        };
        let mut valid = [0; RESPONSE_BYTES];
        response.encode(&mut valid).ok_or("encode")?;
        assert_eq!(
            ResponseRef::decode(&valid, 17, Operation::Sync)
                .ok_or("decode")?
                .result(),
            result
        );
        assert!(ResponseRef::decode(&valid, 18, Operation::Sync).is_none());
        assert!(ResponseRef::decode(&valid, 17, Operation::Stat).is_none());
        assert!(ResponseRef::decode(&valid[..RESPONSE_BYTES - 1], 17, Operation::Sync).is_none());
        for (offset, value) in [
            (32, 99),
            (40, 0o1000),
            (56, NAME_BYTES as u64 + 1),
            (72, u64::MAX),
        ] {
            let mut malformed = valid;
            malformed[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(ResponseRef::decode(&malformed, 17, Operation::Sync).is_none());
        }
        let mut malformed = valid;
        malformed[56..64].copy_from_slice(&1u64.to_le_bytes());
        malformed[112] = b'/';
        assert!(ResponseRef::decode(&malformed, 17, Operation::Sync).is_none());
    }
    Ok(())
}

#[test]
fn symlink_metadata_and_bounded_readlink_replies_round_trip() {
    let mut response = Response {
        sequence: 29,
        operation: Operation::ReadLink,
        result: Ok(12),
        entry: Entry::empty(),
    };
    response.entry.kind = SYMLINK;
    response.entry.size = 12;
    let mut bytes = [0; RESPONSE_BYTES];
    assert!(response.encode(&mut bytes).is_some());
    let decoded = Response::decode(&bytes, 29, Operation::ReadLink);
    assert!(decoded.is_some_and(|value| value.entry.kind == SYMLINK && value.result == Ok(12)));
    bytes[24..32].copy_from_slice(&(PATH_BYTES as u64 + 1).to_le_bytes());
    assert!(Response::decode(&bytes, 29, Operation::ReadLink).is_none());
    response.result = Ok(PATH_BYTES as u64 + 1);
    assert!(response.encode(&mut bytes).is_none());
}

#[test]
fn directory_batches_preserve_attributes_checkpoints_and_eof() -> Result<(), &'static str> {
    let start = DirectoryCursor {
        words: [3, 2, 1, 0],
    };
    let mut bytes = [0; DIRECTORY_BATCH_BYTES];
    let mut builder = DirectoryBatchBuilder::new(&mut bytes, start).ok_or("builder")?;
    let mut entry = Entry::empty();
    entry.name[..4].copy_from_slice(b"file");
    entry.name_len = 4;
    entry.kind = FILE;
    entry.size = 1234;
    entry.modified = hyper_filesystem::Timestamp::new(123, 456);
    let mut count = 0;
    loop {
        let next = DirectoryCursor {
            words: [8, count + 1, 0, 1],
        };
        if !builder.push(&entry, next).ok_or("record")? {
            break;
        }
        count += 1;
    }
    let length = builder.finish(false).ok_or("finish")?;
    let batch = DirectoryBatch::decode(&bytes[..length]).ok_or("decode")?;
    assert_eq!(batch.start_cursor(), start);
    assert_eq!(batch.len(), count as usize);
    assert!(!batch.eof());
    let mut result = Entry::empty();
    for (index, record) in batch.records().enumerate() {
        assert_eq!(record.name(), "file");
        assert_eq!(record.next_cursor().words, [8, index as u64 + 1, 0, 1]);
        record.entry_into(&mut result);
        assert_eq!(result.size, entry.size);
        assert_eq!(result.modified, entry.modified);
    }
    assert!(DirectoryBatch::decode(&bytes[..length - 1]).is_none());
    // A corrupt timestamp must not be accepted as an opaque cursor field.
    bytes[48 + 80..48 + 88].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(DirectoryBatch::decode(&bytes[..length]).is_none());
    let builder = DirectoryBatchBuilder::new(&mut bytes, start).ok_or("empty")?;
    assert!(builder.finish(false).is_none());
    let builder = DirectoryBatchBuilder::new(&mut bytes, start).ok_or("eof")?;
    let length = builder.finish(true).ok_or("empty eof")?;
    let batch = DirectoryBatch::decode(&bytes[..length]).ok_or("empty decode")?;
    assert!(batch.is_empty() && batch.eof());
    bytes[8] = 0;
    assert!(DirectoryBatch::decode(&bytes[..length]).is_none());
    Ok(())
}

#[test]
fn directory_cursor_request_is_not_accepted_by_unrelated_operations() -> Result<(), &'static str> {
    let cursor = DirectoryCursor {
        words: [1, 2, 3, 4],
    };
    let request = Request {
        operation: Operation::ReadDirectory,
        cursor,
        ..request()
    };
    let mut bytes = [0; REQUEST_BYTES];
    let length = request.encode(&mut bytes).ok_or("directory request")?;
    assert_eq!(
        Request::decode(&bytes[..length]).ok_or("decode")?.cursor,
        cursor
    );
    bytes[8..16].copy_from_slice(&(Operation::Stat as u64).to_le_bytes());
    assert!(Request::decode(&bytes[..length]).is_none());
    Ok(())
}

#[test]
fn directory_builder_rejects_cycles_without_consuming_records() -> Result<(), &'static str> {
    let start = DirectoryCursor {
        words: [17, 0, 0, 0],
    };
    let cursors = [1, 2, 3].map(|position| DirectoryCursor {
        words: [position, 0, 0, 0],
    });
    let mut entry = Entry::empty();
    entry.name[0] = b'x';
    entry.name_len = 1;
    let mut bytes = [0; DIRECTORY_BATCH_BYTES];
    let mut builder = DirectoryBatchBuilder::new(&mut bytes, start).ok_or("builder")?;
    assert_eq!(builder.push(&entry, start), None);
    assert_eq!(builder.push(&entry, cursors[0]), Some(true));
    assert_eq!(builder.push(&entry, cursors[1]), Some(true));
    // Reject the starting point, a nonadjacent cursor, and the latest cursor.
    for repeated in [start, cursors[0], cursors[1], DirectoryCursor::START] {
        assert_eq!(builder.push(&entry, repeated), None);
    }
    assert_eq!(builder.push(&entry, cursors[2]), Some(true));
    let length = builder.finish(false).ok_or("finish")?;
    let batch = DirectoryBatch::decode(&bytes[..length]).ok_or("decode")?;
    assert_eq!(batch.len(), cursors.len());
    assert!(
        batch
            .records()
            .map(|record| record.next_cursor())
            .eq(cursors)
    );
    Ok(())
}

#[test]
fn directory_decoder_rejects_forged_nonadjacent_and_start_cycles() -> Result<(), &'static str> {
    let start = DirectoryCursor {
        words: [17, 0, 0, 0],
    };
    let cursors = [1, 2, 3].map(|position| DirectoryCursor {
        words: [position, 0, 0, 0],
    });
    let mut entry = Entry::empty();
    entry.name[0] = b'x';
    entry.name_len = 1;
    let mut bytes = [0; DIRECTORY_BATCH_BYTES];
    let mut builder = DirectoryBatchBuilder::new(&mut bytes, start).ok_or("builder")?;
    for cursor in cursors {
        assert_eq!(builder.push(&entry, cursor), Some(true));
    }
    let length = builder.finish(false).ok_or("finish")?;
    assert!(DirectoryBatch::decode(&bytes[..length]).is_some());
    // Bypass the checked builder: replace the third record's checkpoint in
    // otherwise valid wire bytes. A worker can supply this malformed reply.
    let third_cursor = 48 + 2 * (120 + entry.name_len) + 88;
    for repeated in [start, cursors[0], cursors[1], DirectoryCursor::START] {
        let mut forged = bytes;
        for (index, word) in repeated.words.into_iter().enumerate() {
            let offset = third_cursor + index * 8;
            forged[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
        }
        assert!(DirectoryBatch::decode(&forged[..length]).is_none());
    }
    Ok(())
}

#[test]
fn compact_entry_round_trip_preserves_times_and_rejects_trailing_bytes() -> Result<(), &'static str>
{
    let mut entry = Entry::empty();
    entry.name[..3].copy_from_slice(b"abc");
    entry.name_len = 3;
    entry.created = hyper_filesystem::Timestamp::new(-100, 999999999);
    let mut bytes = [0; 2048];
    let length = entry_encode_into(&entry, &mut bytes).ok_or("encode")?;
    let mut result = Entry::empty();
    assert_eq!(
        entry_decode_into(&bytes[..length], &mut result),
        Some(length)
    );
    assert_eq!(result.name(), "abc");
    assert_eq!(result.created, entry.created);
    assert!(entry_decode_into(&bytes[..length + 1], &mut result).is_none());
    Ok(())
}

#[test]
fn read_extent_plans_merge_prefixes_and_reject_malformed_ranges() -> Result<(), &'static str> {
    let mut bytes = [0; 48];
    let mut plan = ReadExtentPlanBuilder::new(&mut bytes).ok_or("builder")?;
    assert_eq!(plan.push(4096, 512), Some(true));
    assert_eq!(plan.push(4608, 512), Some(true));
    assert_eq!(plan.push(8195, 7), Some(true));
    assert_eq!(plan.push(16384, 512), Some(false));
    let count = plan.finish();
    let decoded = ReadExtentPlan::decode(&bytes[..count], 1031).ok_or("plan")?;
    assert_eq!(decoded.length(), 1031);
    assert_eq!(
        decoded.extents().collect::<Vec<_>>(),
        [
            ReadExtent {
                offset: 4096,
                length: 1024
            },
            ReadExtent {
                offset: 8195,
                length: 7
            },
        ]
    );
    assert!(ReadExtentPlan::decode(&bytes[..count], 1030).is_none());
    assert!(ReadExtentPlan::decode(&bytes[..count - 1], 1031).is_none());
    bytes[24..32].copy_from_slice(&0u64.to_le_bytes());
    assert!(ReadExtentPlan::decode(&bytes[..count], 1031).is_none());
    bytes[24..32].copy_from_slice(&1024u64.to_le_bytes());
    bytes[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(ReadExtentPlan::decode(&bytes[..count], 1031).is_none());
    let length = ReadExtentPlanBuilder::new(&mut bytes)
        .ok_or("empty builder")?
        .finish();
    assert_eq!(
        ReadExtentPlan::decode(&bytes[..length], 512)
            .ok_or("EOF")?
            .length(),
        0
    );
    Ok(())
}

#[test]
fn write_accepts_buffered_or_window_modes_but_other_operations_reject_tokens()
-> Result<(), &'static str> {
    let mut bytes = [0; REQUEST_BYTES];
    let mut write = Request {
        operation: Operation::Write,
        target: "",
        length: 512,
        window_token: 77,
        ..request()
    };
    let length = write.encode(&mut bytes).ok_or("window write")?;
    assert_eq!(
        Request::decode(&bytes[..length])
            .ok_or("decode")?
            .window_token,
        77
    );
    bytes[112..120].fill(0);
    assert_eq!(
        Request::decode(&bytes[..length])
            .ok_or("buffered write")?
            .window_token,
        0
    );
    write.window_token = 0;
    assert!(write.encode(&mut bytes).is_some());
    write.operation = Operation::ReadExtents;
    assert!(write.encode(&mut bytes).is_some());
    write.window_token = 77;
    assert!(write.encode(&mut bytes).is_none());
    Ok(())
}
