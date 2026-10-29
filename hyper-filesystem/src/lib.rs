// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Bounded, filesystem-independent Native filesystem service protocol.
#![no_std]
mod time;
pub use time::Timestamp;

pub mod protocol;
