// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Monotonic clock observation and checked finite deadline construction.
//!
//! Reading the system monotonic clock conveys no mutable authority, so the
//! Native ABI deliberately exposes this one ambient observation. Clocks with
//! virtualized or adjustable policy can remain capability objects later.

use core::time::Duration;

use crate::{Error, Result, Status};

/// UTC timestamp with a normalized fractional second, including before 1970.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timestamp {
    seconds: i64,
    nanoseconds: u32,
}
impl Timestamp {
    #[must_use]
    pub const fn new(seconds: i64, nanoseconds: u32) -> Option<Self> {
        if nanoseconds < 1_000_000_000 {
            Some(Self {
                seconds,
                nanoseconds,
            })
        } else {
            None
        }
    }
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }
    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }
}
/// One absolute observation in the kernel monotonic clock domain.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicInstant(u64);

impl MonotonicInstant {
    /// Returns the absolute monotonic value in nanoseconds.
    #[must_use]
    pub const fn as_nanoseconds(self) -> u64 {
        self.0
    }

    /// Adds a duration while excluding the ABI's infinite-deadline sentinel.
    #[must_use]
    pub fn checked_deadline_after(self, duration: Duration) -> Option<FiniteDeadline> {
        let delta = u64::try_from(duration.as_nanos()).ok()?;
        let raw = self.0.checked_add(delta)?;
        FiniteDeadline::from_raw(raw)
    }
}

/// An absolute monotonic deadline which cannot alias `DEADLINE_INFINITE`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FiniteDeadline(u64);

impl FiniteDeadline {
    fn from_raw(raw: u64) -> Option<Self> {
        (raw != hyper_abi::HYPER_NATIVE_DEADLINE_INFINITE).then_some(Self(raw))
    }

    /// Returns the machine ABI value accepted by Native wait operations.
    #[must_use]
    pub const fn as_raw(self) -> u64 {
        self.0
    }
}

/// Reads the current absolute value of the kernel monotonic clock.
pub fn monotonic_now() -> Result<MonotonicInstant> {
    let result = raw_ops::clock_get_monotonic();
    Status::from_raw(result.status).into_result()?;
    if result.value1 != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(MonotonicInstant(result.value0))
}

/// Constructs a finite absolute deadline relative to one clock observation.
pub fn deadline_after(duration: Duration) -> Result<FiniteDeadline> {
    monotonic_now()?
        .checked_deadline_after(duration)
        .ok_or(Error::DeadlineOverflow)
}

#[cfg(not(test))]
mod raw_ops {
    pub(super) fn clock_get_monotonic() -> hyper_sys::CallResult {
        // SAFETY: `hyper-os` is linked only into Native processes through the
        // matching runtime and this syscall has no pointer or handle inputs.
        unsafe { hyper_sys::clock_get_monotonic() }
    }
}

#[cfg(test)]
mod raw_ops {
    pub(super) const fn clock_get_monotonic() -> hyper_sys::CallResult {
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_OK,
            value0: 1_000_000,
            value1: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::{FiniteDeadline, MonotonicInstant, deadline_after, monotonic_now};
    use crate::Error;

    #[test]
    fn observes_absolute_monotonic_nanoseconds() {
        assert_eq!(
            monotonic_now().map(MonotonicInstant::as_nanoseconds),
            Ok(1_000_000)
        );
    }

    #[test]
    fn constructs_a_checked_finite_deadline() {
        let deadline = deadline_after(Duration::from_millis(2));
        assert_eq!(deadline.map(FiniteDeadline::as_raw), Ok(3_000_000));
    }

    #[test]
    fn rejects_integer_overflow_and_the_infinite_sentinel() {
        let near_end = MonotonicInstant(u64::MAX - 2);
        assert_eq!(
            near_end.checked_deadline_after(Duration::from_nanos(1)),
            Some(FiniteDeadline(u64::MAX - 1))
        );
        assert_eq!(
            near_end.checked_deadline_after(Duration::from_nanos(2)),
            None
        );
        assert_eq!(
            near_end.checked_deadline_after(Duration::from_nanos(3)),
            None
        );
        assert_eq!(
            MonotonicInstant(0).checked_deadline_after(Duration::MAX),
            None
        );
        let result = MonotonicInstant(u64::MAX)
            .checked_deadline_after(Duration::ZERO)
            .ok_or(Error::DeadlineOverflow);
        assert_eq!(result, Err(Error::DeadlineOverflow));
    }
}

/// Reads UTC time when a platform clock has supplied a valid epoch anchor.
pub fn realtime_now() -> Result<Timestamp> {
    // SAFETY: this observation has no borrowed pointers or authority inputs.
    let result = unsafe { hyper_sys::clock_get_realtime() };
    Status::from_raw(result.status).into_result()?;
    let nanos = u32::try_from(result.value1).map_err(|_| Error::InvalidResponse)?;
    Timestamp::new(result.value0 as i64, nanos).ok_or(Error::InvalidResponse)
}
