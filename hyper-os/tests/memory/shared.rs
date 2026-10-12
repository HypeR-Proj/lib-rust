// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn copies_updated_shared_bytes_and_rejects_out_of_range_without_partial_output() -> Result<()> {
    let backing = [AtomicU8::new(1), AtomicU8::new(2), AtomicU8::new(3)];
    // This test owns an ordinary atomic allocation instead of a kernel VMAR;
    // it outlives the view and requires no unmap on destruction.
    let mapping = core::mem::ManuallyDrop::new(SharedReadMapping {
        region: None,
        address: backing.as_ptr().expose_provenance(),
        size: backing.len(),
        mapped: false,
    });
    let mut output = [0; 2];
    mapping.read_exact_at(1, &mut output)?;
    assert_eq!(output, [2, 3]);
    backing[1].store(9, Ordering::Relaxed);
    mapping.read_exact_at(0, &mut output)?;
    assert_eq!(output, [1, 9]);
    assert!(mapping.read_exact_at(2, &mut output).is_err());
    assert!(mapping.read_exact_at(u64::MAX, &mut output).is_err());
    assert_eq!(output, [1, 9]);
    assert!(mapping.read_exact_at(3, &mut []).is_ok());
    assert!(mapping.read_exact_at(4, &mut []).is_err());
    Ok(())
}
