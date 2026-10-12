// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! SDK-owned argument encoding; the kernel transports these bytes opaquely.

use crate::{Error, Result, Status};
use alloc::{string::String, vec::Vec};

pub(crate) struct LaunchData {
    arguments: Vec<String>,
    environment: Vec<String>,
    bytes: usize,
}

impl LaunchData {
    pub(crate) const fn new() -> Self {
        Self {
            arguments: Vec::new(),
            environment: Vec::new(),
            bytes: 8,
        }
    }

    pub(crate) fn append(&mut self, value: &str, environment: bool) -> Result<()> {
        let entries = if environment {
            &mut self.environment
        } else {
            &mut self.arguments
        };
        let total = self
            .bytes
            .checked_add(value.len())
            .and_then(|n| n.checked_add(5))
            .filter(|n| *n <= hyper_abi::HYPER_NATIVE_PROCESS_STARTUP_DATA_MAX_BYTES as usize)
            .ok_or(Error::Status(Status::RESOURCE_LIMIT))?;
        if entries.len() == 64 {
            return Err(Error::Status(Status::RESOURCE_LIMIT));
        }
        entries
            .try_reserve(1)
            .map_err(|_| Error::Status(Status::NO_MEMORY))?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| Error::Status(Status::NO_MEMORY))?;
        owned.push_str(value);
        entries.push(owned);
        self.bytes = total;
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if self.arguments.is_empty() {
            return Err(Error::InvalidProcessArgument);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.bytes)
            .map_err(|_| Error::Status(Status::NO_MEMORY))?;
        bytes.extend_from_slice(&(self.arguments.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.environment.len() as u32).to_le_bytes());
        let mut offset = 8 + 4 * (self.arguments.len() + self.environment.len());
        for string in self.arguments.iter().chain(&self.environment) {
            bytes.extend_from_slice(&(offset as u32).to_le_bytes());
            offset += string.len() + 1;
        }
        for string in self.arguments.iter().chain(&self.environment) {
            bytes.extend_from_slice(string.as_bytes());
            bytes.push(0);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaved_arguments_and_environment_encode_in_separate_vectors() -> Result<()> {
        let mut data = LaunchData::new();
        data.append("A=1", true)?;
        data.append("app", false)?;
        data.append("", false)?;
        data.append("B=two", true)?;
        let bytes = data.encode()?;
        assert_eq!(&bytes[..8], &[2, 0, 0, 0, 2, 0, 0, 0]);
        for (i, expected) in ["app", "", "A=1", "B=two"].iter().enumerate() {
            let index = 8 + i * 4;
            let offset = u32::from_le_bytes([
                bytes[index],
                bytes[index + 1],
                bytes[index + 2],
                bytes[index + 3],
            ]) as usize;
            assert_eq!(&bytes[offset..offset + expected.len()], expected.as_bytes());
            assert_eq!(bytes[offset + expected.len()], 0);
        }
        Ok(())
    }

    #[test]
    fn rejected_append_preserves_the_encoded_payload() -> Result<()> {
        let mut data = LaunchData::new();
        assert_eq!(data.encode(), Err(Error::InvalidProcessArgument));
        for _ in 0..64 {
            data.append("arg", false)?;
        }
        let before = data.encode()?;
        assert_eq!(
            data.append("overflow", false),
            Err(Error::Status(Status::RESOURCE_LIMIT))
        );
        assert_eq!(data.encode()?, before);
        assert_eq!(
            data.append(&"x".repeat(16 * 1024), true),
            Err(Error::Status(Status::RESOURCE_LIMIT))
        );
        assert_eq!(data.encode()?, before);
        Ok(())
    }
}
