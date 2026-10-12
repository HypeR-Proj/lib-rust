// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Extended filesystem contracts independent of language-runtime path policy.

use super::{Directory, DirectoryRights, File, FileRights, NodeId, NodeLocation, validate_path};
use crate::{Error, Result, Status};

pub use crate::time::Timestamp;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkBehavior {
    Follow,
    NoFollow,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenMode {
    Existing,
    Create,
    CreateNew,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncScope {
    Data,
    Full,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockMode {
    Shared,
    Exclusive,
}

/// One coherent metadata observation. Missing times are unknown, not the epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    pub location: NodeLocation,
    pub size: u64,
    pub mode: u32,
    pub kind: super::DirectoryEntryKind,
    pub accessed: Option<Timestamp>,
    pub modified: Option<Timestamp>,
    pub created: Option<Timestamp>,
    pub changed: Option<Timestamp>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetadataUpdate {
    pub mode: Option<u32>,
    pub accessed: Option<Timestamp>,
    pub modified: Option<Timestamp>,
}
impl MetadataUpdate {
    fn raw(self) -> hyper_abi::HyperNativeFileMetadataUpdate {
        let mut raw = EMPTY_UPDATE;
        if let Some(mode) = self.mode {
            raw.mask |= 1;
            raw.mode = mode;
        }
        if let Some(time) = self.accessed {
            raw.mask |= 2;
            raw.accessed_seconds = time.seconds();
            raw.accessed_nanoseconds = time.nanoseconds();
        }
        if let Some(time) = self.modified {
            raw.mask |= 4;
            raw.modified_seconds = time.seconds();
            raw.modified_nanoseconds = time.nanoseconds();
        }
        raw
    }
}
fn decode_time(
    mask: u32,
    bit: u32,
    seconds: i64,
    nanos: u32,
    reserved: u32,
) -> Result<Option<Timestamp>> {
    if reserved != 0 {
        return Err(Error::InvalidResponse);
    }
    if mask & bit == 0 {
        return if seconds == 0 && nanos == 0 {
            Ok(None)
        } else {
            Err(Error::InvalidResponse)
        };
    }
    Timestamp::new(seconds, nanos)
        .map(Some)
        .ok_or(Error::InvalidResponse)
}
fn decode(raw: hyper_abi::HyperNativeFileMetadata) -> Result<FileMetadata> {
    if raw.reserved != 0 || raw.valid_times & !15 != 0 {
        return Err(Error::InvalidResponse);
    }
    let kind = match raw.kind {
        1 => super::DirectoryEntryKind::File,
        2 => super::DirectoryEntryKind::Directory,
        3 => super::DirectoryEntryKind::Symlink,
        4 => super::DirectoryEntryKind::Other,
        _ => return Err(Error::InvalidResponse),
    };
    Ok(FileMetadata {
        location: super::decode_location(raw.filesystem_id, raw.mount_id, raw.node_id)?,
        size: raw.size,
        mode: raw.mode,
        kind,
        accessed: decode_time(
            raw.valid_times,
            1,
            raw.accessed_seconds,
            raw.accessed_nanoseconds,
            raw.accessed_reserved,
        )?,
        modified: decode_time(
            raw.valid_times,
            2,
            raw.modified_seconds,
            raw.modified_nanoseconds,
            raw.modified_reserved,
        )?,
        created: decode_time(
            raw.valid_times,
            4,
            raw.created_seconds,
            raw.created_nanoseconds,
            raw.created_reserved,
        )?,
        changed: decode_time(
            raw.valid_times,
            8,
            raw.changed_seconds,
            raw.changed_nanoseconds,
            raw.changed_reserved,
        )?,
    })
}
fn metadata_status(result: hyper_sys::CallResult) -> Result<()> {
    crate::validate_info_result(result, hyper_abi::HYPER_NATIVE_FILE_METADATA_MIN_SIZE).map(|_| ())
}
fn status(result: hyper_sys::CallResult) -> Result<()> {
    Status::from_raw(result.status).into_result()
}
impl Directory {
    /// Creates a cursor at `start` bounded by this directory's current location.
    /// Both source authorities must grant every requested right.
    pub fn scope_at(&self, start: &Self, rights: DirectoryRights) -> Result<Self> {
        let root = self.as_handle_ref();
        let start = start.as_handle_ref();
        // SAFETY: both owned directory capabilities remain live.
        let result = unsafe {
            hyper_sys::directory_scope_create(
                root.raw().get(),
                start.raw().get(),
                rights.as_rights().bits(),
            )
        };
        status(result)?;
        // SAFETY: successful scope creation returns a distinct owned Directory.
        let handle = unsafe {
            crate::handle::adopt_produced_handle_excluding(
                result.value0,
                &[root.raw(), start.raw()],
            )?
        };
        Ok(Self { handle })
    }
    pub fn metadata(&self, path: &str, links: LinkBehavior) -> Result<FileMetadata> {
        validate_path(path)?;
        let mut raw = EMPTY_METADATA;
        // SAFETY: path and initialized output remain borrowed throughout.
        metadata_status(unsafe {
            hyper_sys::directory_get_metadata(
                self.as_handle_ref().raw().get(),
                path.as_ptr(),
                path.len(),
                u32::from(links == LinkBehavior::NoFollow),
                &mut raw,
                core::mem::size_of::<hyper_abi::HyperNativeFileMetadata>(),
            )
        })?;
        decode(raw)
    }
    pub fn self_metadata(&self) -> Result<FileMetadata> {
        let mut raw = EMPTY_METADATA;
        // SAFETY: the capability stays owned and output is exclusive.
        metadata_status(unsafe {
            hyper_sys::directory_get_self_metadata(
                self.as_handle_ref().raw().get(),
                &mut raw,
                core::mem::size_of::<hyper_abi::HyperNativeFileMetadata>(),
            )
        })?;
        decode(raw)
    }
    pub fn set_metadata(
        &self,
        path: &str,
        links: LinkBehavior,
        update: MetadataUpdate,
    ) -> Result<()> {
        validate_path(path)?;
        let raw = update.raw();
        // SAFETY: all borrowed input storage and the capability remain live.
        status(unsafe {
            hyper_sys::directory_set_metadata(
                self.as_handle_ref().raw().get(),
                path.as_ptr(),
                path.len(),
                u32::from(links == LinkBehavior::NoFollow),
                &raw,
                core::mem::size_of_val(&raw),
            )
        })
    }
    pub fn open_with_options(
        &self,
        path: &str,
        rights: FileRights,
        mode: OpenMode,
        truncate: bool,
        permissions: u32,
    ) -> Result<File> {
        validate_path(path)?;
        let directory = self.as_handle_ref();
        let options = match mode {
            OpenMode::Existing => 0,
            OpenMode::Create => 1,
            OpenMode::CreateNew => 2,
        } | if truncate { 4 } else { 0 };
        // SAFETY: the source capability and path storage remain live.
        let result = unsafe {
            hyper_sys::directory_open_file_with_options(
                directory.raw().get(),
                path.as_ptr(),
                path.len(),
                rights.as_rights().bits(),
                options,
                permissions,
            )
        };
        status(result)?;
        // SAFETY: successful open returns one distinct File owner.
        let handle = unsafe {
            crate::handle::adopt_produced_handle_excluding(result.value0, &[directory.raw()])?
        };
        Ok(File { handle })
    }
    pub fn open_directory_nofollow(&self, path: &str, rights: DirectoryRights) -> Result<Self> {
        validate_path(path)?;
        let directory = self.as_handle_ref();
        // SAFETY: the source capability and path storage remain live.
        let result = unsafe {
            hyper_sys::directory_open_directory_nofollow(
                directory.raw().get(),
                path.as_ptr(),
                path.len(),
                rights.as_rights().bits(),
            )
        };
        status(result)?;
        // SAFETY: success returns a distinct owned Directory.
        let handle = unsafe {
            crate::handle::adopt_produced_handle_excluding(result.value0, &[directory.raw()])?
        };
        Ok(Self { handle })
    }
    pub fn rename(&self, path: &str, destination: &Self, new_path: &str) -> Result<()> {
        validate_path(path)?;
        validate_path(new_path)?;
        // SAFETY: both capabilities and input byte ranges remain live.
        status(unsafe {
            hyper_sys::directory_rename(
                self.as_handle_ref().raw().get(),
                path.as_ptr(),
                path.len(),
                destination.as_handle_ref().raw().get(),
                new_path.as_ptr(),
                new_path.len(),
            )
        })
    }
    /// Adds a regular-file name without following the source's final symlink.
    pub fn hard_link(&self, path: &str, destination: &Self, new_path: &str) -> Result<()> {
        validate_path(path)?;
        validate_path(new_path)?;
        // SAFETY: both capabilities and input byte ranges remain live.
        status(unsafe {
            hyper_sys::directory_link(
                self.as_handle_ref().raw().get(),
                path.as_ptr(),
                path.len(),
                destination.as_handle_ref().raw().get(),
                new_path.as_ptr(),
                new_path.len(),
            )
        })
    }
    pub fn symlink(&self, target: &str, path: &str) -> Result<()> {
        validate_path(path)?;
        validate_path(target)?;
        // SAFETY: the capability and both byte ranges remain borrowed.
        status(unsafe {
            hyper_sys::directory_symlink(
                self.as_handle_ref().raw().get(),
                path.as_ptr(),
                path.len(),
                target.as_ptr(),
                target.len(),
            )
        })
    }
    pub fn read_link(&self, path: &str, output: &mut [u8]) -> Result<usize> {
        self.path_output(path, output, false)
    }
    pub fn canonicalize(&self, path: &str, output: &mut [u8]) -> Result<usize> {
        self.path_output(path, output, true)
    }
    fn path_output(&self, path: &str, output: &mut [u8], canonical: bool) -> Result<usize> {
        validate_path(path)?;
        // SAFETY: source bytes remain readable and output is exclusively borrowed.
        let result = unsafe {
            if canonical {
                hyper_sys::directory_canonicalize(
                    self.as_handle_ref().raw().get(),
                    path.as_ptr(),
                    path.len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            } else {
                hyper_sys::directory_read_link(
                    self.as_handle_ref().raw().get(),
                    path.as_ptr(),
                    path.len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            }
        };
        status(result)?;
        let count = usize::try_from(result.value0).map_err(|_| Error::InvalidResponse)?;
        if count > output.len() {
            return Err(Error::InvalidResponse);
        }
        Ok(count)
    }
    /// Removes only the observed node; a replaced name returns Busy.
    /// The node identity is relative to this directory's filesystem.
    pub fn remove_if(&self, path: &str, directory: bool, expected: NodeId) -> Result<()> {
        validate_path(path)?;
        // SAFETY: the parent capability and path remain live; identity is not authority.
        status(unsafe {
            hyper_sys::directory_remove_if(
                self.as_handle_ref().raw().get(),
                path.as_ptr(),
                path.len(),
                u32::from(directory),
                expected.get(),
            )
        })
    }
}
impl File {
    pub fn metadata(&self) -> Result<FileMetadata> {
        let mut raw = EMPTY_METADATA;
        // SAFETY: the capability stays live and output is exclusive.
        metadata_status(unsafe {
            hyper_sys::file_get_metadata(
                self.as_handle_ref().raw().get(),
                &mut raw,
                core::mem::size_of::<hyper_abi::HyperNativeFileMetadata>(),
            )
        })?;
        decode(raw)
    }
    pub fn set_metadata(&self, update: MetadataUpdate) -> Result<()> {
        let raw = update.raw();
        // SAFETY: the capability and initialized update remain live.
        status(unsafe {
            hyper_sys::file_set_metadata(
                self.as_handle_ref().raw().get(),
                &raw,
                core::mem::size_of_val(&raw),
            )
        })
    }
    pub fn sync(&self, scope: SyncScope) -> Result<()> {
        // SAFETY: the capability remains owned throughout.
        status(unsafe {
            hyper_sys::file_sync(
                self.as_handle_ref().raw().get(),
                u32::from(scope == SyncScope::Full),
            )
        })
    }
    /// Acquires an advisory lock without polling. None waits indefinitely.
    /// Contended upgrades retain the shared grant and report Busy.
    pub fn lock(
        &self,
        mode: LockMode,
        deadline: Option<crate::time::FiniteDeadline>,
    ) -> Result<()> {
        self.lock_raw(
            mode,
            deadline.map_or(
                hyper_abi::HYPER_NATIVE_DEADLINE_INFINITE,
                crate::time::FiniteDeadline::as_raw,
            ),
        )
    }
    pub fn try_lock(&self, mode: LockMode) -> Result<()> {
        self.lock_raw(mode, 0)
    }
    fn lock_raw(&self, mode: LockMode, deadline: u64) -> Result<()> {
        // SAFETY: the File owner pins the lock identity throughout the wait.
        status(unsafe {
            hyper_sys::file_lock(
                self.as_handle_ref().raw().get(),
                u32::from(mode == LockMode::Exclusive),
                deadline,
            )
        })
    }
    pub fn unlock(&self) -> Result<()> {
        // SAFETY: the capability remains owned throughout.
        status(unsafe { hyper_sys::file_unlock(self.as_handle_ref().raw().get()) })
    }
}

const EMPTY_METADATA: hyper_abi::HyperNativeFileMetadata = hyper_abi::HyperNativeFileMetadata {
    filesystem_id: 0,
    mount_id: 0,
    node_id: 0,
    size: 0,
    mode: 0,
    kind: 0,
    valid_times: 0,
    reserved: 0,
    accessed_seconds: 0,
    accessed_nanoseconds: 0,
    accessed_reserved: 0,
    modified_seconds: 0,
    modified_nanoseconds: 0,
    modified_reserved: 0,
    created_seconds: 0,
    created_nanoseconds: 0,
    created_reserved: 0,
    changed_seconds: 0,
    changed_nanoseconds: 0,
    changed_reserved: 0,
};

const EMPTY_UPDATE: hyper_abi::HyperNativeFileMetadataUpdate =
    hyper_abi::HyperNativeFileMetadataUpdate {
        mask: 0,
        mode: 0,
        accessed_seconds: 0,
        accessed_nanoseconds: 0,
        accessed_reserved: 0,
        modified_seconds: 0,
        modified_nanoseconds: 0,
        modified_reserved: 0,
    };

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_metadata() -> hyper_abi::HyperNativeFileMetadata {
        hyper_abi::HyperNativeFileMetadata {
            filesystem_id: 1,
            mount_id: 2,
            kind: 1,
            ..EMPTY_METADATA
        }
    }
    #[test]
    fn metadata_preserves_unknown_and_pre_epoch_times() -> Result<()> {
        assert_eq!(decode(valid_metadata())?.modified, None);
        let raw = hyper_abi::HyperNativeFileMetadata {
            valid_times: 2,
            modified_seconds: -1,
            modified_nanoseconds: 999_999_999,
            ..valid_metadata()
        };
        assert_eq!(decode(raw)?.modified, Timestamp::new(-1, 999_999_999));
        Ok(())
    }
    #[test]
    fn rejects_malformed_metadata_without_silent_truncation() {
        for raw in [
            hyper_abi::HyperNativeFileMetadata {
                filesystem_id: 0,
                ..valid_metadata()
            },
            hyper_abi::HyperNativeFileMetadata {
                kind: 99,
                ..valid_metadata()
            },
            hyper_abi::HyperNativeFileMetadata {
                valid_times: 16,
                ..valid_metadata()
            },
            hyper_abi::HyperNativeFileMetadata {
                accessed_seconds: 1,
                ..valid_metadata()
            },
            hyper_abi::HyperNativeFileMetadata {
                valid_times: 1,
                accessed_nanoseconds: 1_000_000_000,
                ..valid_metadata()
            },
            hyper_abi::HyperNativeFileMetadata {
                changed_reserved: 1,
                ..valid_metadata()
            },
        ] {
            assert_eq!(decode(raw), Err(Error::InvalidResponse));
        }
    }
    #[test]
    fn update_mask_preserves_fields_not_requested() {
        let update = MetadataUpdate {
            modified: Timestamp::new(-2, 13),
            ..MetadataUpdate::default()
        }
        .raw();
        assert_eq!(update.mask, 4);
        assert_eq!(update.mode, 0);
        assert_eq!(update.accessed_seconds, 0);
        assert_eq!(update.modified_seconds, -2);
        assert_eq!(update.modified_nanoseconds, 13);
    }
    #[test]
    fn metadata_and_lock_authority_are_independently_narrowable() {
        use crate::handle::Rights;
        assert!(FileRights::from_rights(Rights::SET_ATTRIBUTES.union(Rights::LOCK_FILE)).is_some());
        assert!(
            !FileRights::READ
                .as_rights()
                .contains(Rights::SET_ATTRIBUTES)
        );
        assert!(!FileRights::WRITE.as_rights().contains(Rights::LOCK_FILE));
        assert!(
            DirectoryRights::from_rights(Rights::SET_ATTRIBUTES.union(Rights::LOCK_FILE)).is_some()
        );
    }
}
