// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

/// Validated UTC timestamp crossing a filesystem service boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    seconds: i64,
    nanoseconds: u32,
}
impl Timestamp {
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
    pub const fn seconds(self) -> i64 {
        self.seconds
    }
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }
}
