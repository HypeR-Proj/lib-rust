// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Periodic ownership negotiation uses nanoseconds. Zero is a separate wire
//! sentinel for providers which do not delegate periodic writeback.

pub const MIN_WRITEBACK_INTERVAL_NS: u64 = 1_000_000_000;
pub const MAX_WRITEBACK_INTERVAL_NS: u64 = 3_600_000_000_000;

pub const fn valid_writeback_interval_ns(value: u64) -> bool {
    value >= MIN_WRITEBACK_INTERVAL_NS && value <= MAX_WRITEBACK_INTERVAL_NS
}

/// Both count and bytes are bounded: each batch accepts at most `DATA_BYTES`.
pub const MAX_WRITEBACK_BATCHES: usize = 2;
pub const WRITEBACK_COMPLETION_BYTES: usize = 24;

/// Acknowledged input and its final data-writeback outcome. `accepted` is the
/// input prefix accepted at submission, not a physical completed-byte count.
/// Success completes that entire prefix; failure may have partial device effects.
/// This is not a filesystem durability/checkpoint fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WritebackCompletion {
    pub batch: u64,
    pub accepted: u64,
    pub result: Result<(), super::Error>,
}

impl WritebackCompletion {
    pub fn encode(self, output: &mut [u8]) -> Option<()> {
        if self.batch == 0 || !(1..=super::DATA_BYTES as u64).contains(&self.accepted) {
            return None;
        }
        let output = output.get_mut(..WRITEBACK_COMPLETION_BYTES)?;
        super::put(output, 0, self.batch);
        super::put(output, 8, self.accepted);
        super::put(
            output,
            16,
            self.result.err().map_or(0, |error| error as u64),
        );
        Some(())
    }

    pub fn decode(input: &[u8]) -> Option<Self> {
        if input.len() != WRITEBACK_COMPLETION_BYTES {
            return None;
        }
        let batch = super::get(input, 0)?;
        let accepted = super::get(input, 8)?;
        if batch == 0 || !(1..=super::DATA_BYTES as u64).contains(&accepted) {
            return None;
        }
        let result = match super::get(input, 16)? {
            0 => Ok(()),
            status => Err(super::Error::decode(status)?),
        };
        Some(Self {
            batch,
            accepted,
            result,
        })
    }
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
