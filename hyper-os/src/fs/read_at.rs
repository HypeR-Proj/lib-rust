// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Positioned exact reads independent of a file cursor or parser.

/// Random-access byte source used without requiring an allocation policy.
pub trait ReadAt {
    type Error;

    fn length(&self) -> Result<u64, Self::Error>;
    /// Fills the entire output from `offset`, or reports a source error.
    ///
    /// A short read, including premature EOF, must not be reported as success.
    /// On error the output may already contain a partially copied prefix.
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error>;
}

impl ReadAt for super::File {
    type Error = crate::Error;
    fn length(&self) -> Result<u64, Self::Error> {
        self.size()
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        self.read_exact_at(offset, output)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    type Error = T::Error;
    fn length(&self) -> Result<u64, Self::Error> {
        (**self).length()
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        (**self).read_exact_at(offset, output)
    }
}
