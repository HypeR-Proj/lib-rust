// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Periodic ownership negotiation uses nanoseconds. Zero is a separate wire
//! sentinel for providers which do not delegate periodic writeback.

pub const MIN_WRITEBACK_INTERVAL_NS: u64 = 1_000_000_000;
pub const MAX_WRITEBACK_INTERVAL_NS: u64 = 3_600_000_000_000;

pub const fn valid_writeback_interval_ns(value: u64) -> bool {
    value >= MIN_WRITEBACK_INTERVAL_NS && value <= MAX_WRITEBACK_INTERVAL_NS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_range_excludes_the_nonperiodic_sentinel() {
        for value in [
            0,
            500_000_000,
            MIN_WRITEBACK_INTERVAL_NS - 1,
            MAX_WRITEBACK_INTERVAL_NS + 1,
            u64::MAX,
        ] {
            assert!(!valid_writeback_interval_ns(value));
        }
        assert!(valid_writeback_interval_ns(MIN_WRITEBACK_INTERVAL_NS));
        assert!(valid_writeback_interval_ns(MAX_WRITEBACK_INTERVAL_NS));
    }
}
