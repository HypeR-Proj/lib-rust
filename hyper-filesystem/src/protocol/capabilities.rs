// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Optional operations are advertised independently of writeback ownership.
//! Unknown bits remain available for future protocol extensions.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities(u64);

impl Capabilities {
    pub const NONE: Self = Self(0);
    /// The provider can describe some file ranges as physical read extents.
    /// An individual range may still return Unsupported and require ordinary Read.
    pub const READ_EXTENTS: Self = Self(1);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn supports_read_extents(self) -> bool {
        self.0 & Self::READ_EXTENTS.0 != 0
    }
}

/// Features of the serving protocol, distinct from backend filesystem abilities.
/// A zero trailer is a legacy reply: sending new operation numbers is unsafe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseFeatures(u64);

impl ResponseFeatures {
    pub const NONE: Self = Self(0);
    pub const CAPABILITY_QUERY: Self = Self(1);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn supports_capability_query(self) -> bool {
        self.0 & Self::CAPABILITY_QUERY.0 != 0
    }
}
