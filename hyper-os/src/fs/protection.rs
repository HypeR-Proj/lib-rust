// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Process-local content protection. This retains authority, not file pages.

use super::File;
use crate::handle::{AnyObject, FileProtectionObject, HandleRef, OwnedHandle, Rights};
use crate::{Error, Result, Status};

/// An active content protection acquired with the File's `PROTECT` right.
///
/// This object cannot be duplicated or transferred to another process. Closing
/// it releases this reference, while existing protected mappings keep their own
/// references until unmap or process teardown. It does not retain a snapshot or
/// prevent cache reclamation. Ordinary file handles do not inherit this guard.
pub struct FileProtection {
    handle: OwnedHandle<FileProtectionObject>,
    byte_size: u64,
}

impl File {
    /// Prevent content writes and size changes before reading file metadata.
    ///
    /// Other holders may acquire independent protections. The returned length
    /// is sampled after protection takes effect; names and other metadata can
    /// still change. Process teardown releases protections once its threads
    /// stop. VMAR handles held elsewhere cannot prolong content protection.
    pub fn protect(&self) -> Result<FileProtection> {
        let source = self.as_handle_ref();
        // SAFETY: the file remains borrowed; success transfers one token owner.
        let result = unsafe { hyper_sys::file_protect(source.raw().get()) };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: success owns a fresh token, distinct from the borrowed File.
        let owner = unsafe {
            crate::handle::adopt_produced_handle_excluding::<AnyObject>(
                result.value0,
                &[source.raw()],
            )?
        };
        if owner.info()?.rights != Rights::MAP.union(Rights::INSPECT) {
            return Err(Error::InvalidResponse);
        }
        let handle = owner
            .downcast::<FileProtectionObject>()
            .map_err(|failure| failure.error())?;
        Ok(FileProtection {
            handle,
            byte_size: result.value1,
        })
    }
}

impl FileProtection {
    #[must_use]
    pub const fn byte_size(&self) -> u64 {
        self.byte_size
    }

    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, FileProtectionObject> {
        self.handle.as_handle_ref()
    }
}
