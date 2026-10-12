// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Owned access to capability-relative filesystem objects.

mod metadata;
mod protection;
pub use metadata::{
    FileMetadata, LinkBehavior, LockMode, MetadataUpdate, OpenMode, SyncScope, Timestamp,
};
pub use protection::FileProtection;

use core::num::NonZeroU64;

use crate::handle::{
    DirectoryObject, DirectoryStreamObject, FileObject, HandleRef, OwnedHandle, Rights,
};
use crate::{Error, Result, Status};

const _: () = assert!(hyper_abi::HYPER_NATIVE_DIRECTORY_MAX_PATH_BYTES <= usize::MAX as u64);
const _: () = assert!(hyper_abi::HYPER_NATIVE_FILE_MAX_READ_BYTES <= usize::MAX as u64);
const _: () = assert!(hyper_abi::HYPER_NATIVE_DIRECTORY_ENTRY_PAGE_CAPACITY <= usize::MAX as u64);
const _: () = assert!(hyper_abi::HYPER_NATIVE_DIRECTORY_ENTRY_NAME_MAX_BYTES <= usize::MAX as u64);
pub const MAX_PATH_BYTES: usize = hyper_abi::HYPER_NATIVE_DIRECTORY_MAX_PATH_BYTES as usize;
pub const MAX_NAME_BYTES: usize = hyper_abi::HYPER_NATIVE_DIRECTORY_ENTRY_NAME_MAX_BYTES as usize;
const MAX_READ_BYTES: usize = hyper_abi::HYPER_NATIVE_FILE_MAX_READ_BYTES as usize;
const DIRECTORY_PAGE_CAPACITY: usize =
    hyper_abi::HYPER_NATIVE_DIRECTORY_ENTRY_PAGE_CAPACITY as usize;

/// Stable identity of one mounted filesystem instance.
///
/// This value is observation-only and cannot be resolved into a capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FilesystemId(NonZeroU64);

impl FilesystemId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Stable identity of one mount in a process-visible namespace.
///
/// This value is observation-only and cannot be resolved into a capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MountId(NonZeroU64);

impl MountId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Stable identity of one node within its filesystem instance.
///
/// Node zero is valid. Pair this value with [`FilesystemId`] when correlating
/// observations from distinct mounts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NodeId(u64);

impl NodeId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Namespace location identity reported for one opened filesystem object.
///
/// This is deliberately not a pathname: links, renames, unlinks, and mount
/// namespaces can give one node several names or no current name at all.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NodeLocation {
    filesystem: FilesystemId,
    mount: MountId,
    node: NodeId,
}

impl NodeLocation {
    #[must_use]
    pub const fn filesystem(self) -> FilesystemId {
        self.filesystem
    }

    #[must_use]
    pub const fn mount(self) -> MountId {
        self.mount
    }

    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }
}

/// Immutable metadata for one opened File object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileInfo {
    location: NodeLocation,
    size: u64,
    mode: u32,
}

impl FileInfo {
    #[must_use]
    pub const fn location(self) -> NodeLocation {
        self.location
    }

    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }

    #[must_use]
    pub const fn mode(self) -> u32 {
        self.mode
    }
}

/// Immutable metadata for one opened Directory object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryInfo {
    location: NodeLocation,
    mode: u32,
}

impl DirectoryInfo {
    #[must_use]
    pub const fn location(self) -> NodeLocation {
        self.location
    }

    #[must_use]
    pub const fn mode(self) -> u32 {
        self.mode
    }
}

/// Rights which may be requested for a newly opened file.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileRights(Rights);

impl FileRights {
    pub const NONE: Self = Self(Rights::NONE);
    pub const READ: Self = Self(Rights::READ);
    pub const WRITE: Self = Self(Rights::WRITE);
    pub const INSPECT: Self = Self(Rights::INSPECT);
    pub const DUPLICATE: Self = Self(Rights::DUPLICATE);
    pub const TRANSFER: Self = Self(Rights::TRANSFER);
    pub const EXECUTE: Self = Self(Rights::EXECUTE);
    pub const SET_ATTRIBUTES: Self = Self(Rights::SET_ATTRIBUTES);
    pub const LOCK_FILE: Self = Self(Rights::LOCK_FILE);
    pub const PROTECT: Self = Self(Rights::PROTECT);

    const ALLOWED: Rights = Rights::READ
        .union(Rights::WRITE)
        .union(Rights::INSPECT)
        .union(Rights::DUPLICATE)
        .union(Rights::TRANSFER)
        .union(Rights::EXECUTE)
        .union(Rights::SET_ATTRIBUTES)
        .union(Rights::LOCK_FILE)
        .union(Rights::PROTECT);

    /// Narrows generic rights to those meaningful for files.
    #[must_use]
    pub const fn from_rights(rights: Rights) -> Option<Self> {
        if Self::ALLOWED.contains(rights) {
            Some(Self(rights))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0.union(other.0))
    }

    #[must_use]
    pub const fn as_rights(self) -> Rights {
        self.0
    }
}

/// Rights which may be requested for a newly opened directory.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryRights(Rights);

impl DirectoryRights {
    pub const READ: Self = Self(Rights::READ);
    pub const WRITE: Self = Self(Rights::WRITE);
    pub const INSPECT: Self = Self(Rights::INSPECT);
    pub const DUPLICATE: Self = Self(Rights::DUPLICATE);
    pub const TRANSFER: Self = Self(Rights::TRANSFER);
    pub const EXECUTE: Self = Self(Rights::EXECUTE);
    pub const SET_ATTRIBUTES: Self = Self(Rights::SET_ATTRIBUTES);
    pub const LOCK_FILE: Self = Self(Rights::LOCK_FILE);
    pub const PROTECT: Self = Self(Rights::PROTECT);

    const ALLOWED: Rights = Rights::READ
        .union(Rights::WRITE)
        .union(Rights::INSPECT)
        .union(Rights::DUPLICATE)
        .union(Rights::TRANSFER)
        .union(Rights::EXECUTE)
        .union(Rights::SET_ATTRIBUTES)
        .union(Rights::LOCK_FILE)
        .union(Rights::PROTECT);

    #[must_use]
    pub const fn from_rights(rights: Rights) -> Option<Self> {
        if Self::ALLOWED.contains(rights) {
            Some(Self(rights))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0.union(other.0))
    }

    #[must_use]
    pub const fn as_rights(self) -> Rights {
        self.0
    }
}

/// Exclusive authority to resolve paths relative to one directory capability.
pub struct Directory {
    handle: OwnedHandle<DirectoryObject>,
}

impl Directory {
    /// Restores directory operations from an exclusively owned typed handle.
    ///
    /// This consumes the owner and is therefore safe for handles delegated at
    /// startup or received through a capability channel.
    #[must_use]
    pub const fn from_handle(handle: OwnedHandle<DirectoryObject>) -> Self {
        Self { handle }
    }

    /// Borrows the underlying directory authority for delegation.
    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, DirectoryObject> {
        self.handle.as_handle_ref()
    }

    /// Returns immutable identity and attributes for this Directory.
    ///
    /// The Directory handle must carry [`Rights::INSPECT`].
    pub fn info(&self) -> Result<DirectoryInfo> {
        decode_directory_info(raw_ops::directory_info(self.handle.as_handle_ref())?)
    }

    /// Opens one UTF-8 path and returns the unique new `File` owner.
    ///
    /// The source Directory must carry `READ` and every requested File right;
    /// the kernel then applies the resolved node's immutable rights ceiling.
    pub fn open(&self, path: &str, requested_rights: FileRights) -> Result<File> {
        validate_path(path)?;
        let directory = self.handle.as_handle_ref();
        let result = raw_ops::open(directory, path, requested_rights.as_rights());
        Status::from_raw(result.status).into_result()?;
        // SAFETY: successful DIRECTORY_OPEN_FILE publishes one new File owner
        // unless malformed output aliases the retained Directory borrow.
        let handle = unsafe {
            crate::handle::adopt_produced_handle_excluding(result.value0, &[directory.raw()])?
        };
        Ok(File { handle })
    }

    /// Exclusively creates a regular file and returns its open capability.
    pub fn create_file(&self, path: &str, rights: FileRights, mode: u32) -> Result<File> {
        validate_path(path)?;
        let directory = self.as_handle_ref();
        // SAFETY: this borrow pins the handle; path bytes are valid throughout.
        let result = unsafe {
            hyper_sys::directory_create_file(
                directory.raw().get(),
                path.as_ptr(),
                path.len(),
                rights.as_rights().bits(),
                mode,
            )
        };
        Status::from_raw(result.status).into_result()?;
        // SAFETY: success publishes one unique File handle, excluding its source.
        let handle = unsafe {
            crate::handle::adopt_produced_handle_excluding(result.value0, &[directory.raw()])?
        };
        Ok(File { handle })
    }

    /// Creates one directory; its parent must already exist.
    pub fn create_directory(&self, path: &str, mode: u32) -> Result<()> {
        validate_path(path)?;
        // SAFETY: the owned directory and borrowed path stay live.
        let result = unsafe {
            hyper_sys::directory_create_directory(
                self.as_handle_ref().raw().get(),
                path.as_ptr(),
                path.len(),
                mode,
            )
        };
        Status::from_raw(result.status).into_result()
    }

    /// Removes a non-directory name without following its final symlink.
    pub fn remove_file(&self, path: &str) -> Result<()> {
        self.remove(path, false)
    }

    /// Removes an empty directory. Open handles remain valid after removal.
    pub fn remove_directory(&self, path: &str) -> Result<()> {
        self.remove(path, true)
    }

    fn remove(&self, path: &str, directory: bool) -> Result<()> {
        validate_path(path)?;
        // SAFETY: the owned directory and borrowed path stay live.
        let result = unsafe {
            hyper_sys::directory_remove(
                self.as_handle_ref().raw().get(),
                path.as_ptr(),
                path.len(),
                u32::from(directory),
            )
        };
        Status::from_raw(result.status).into_result()
    }

    /// Opens a child directory relative to this capability.
    pub fn open_directory(&self, path: &str, requested_rights: DirectoryRights) -> Result<Self> {
        validate_path(path)?;
        let directory = self.handle.as_handle_ref();
        let result = raw_ops::open_directory(directory, path, requested_rights.as_rights());
        Status::from_raw(result.status).into_result()?;
        // SAFETY: successful DIRECTORY_OPEN_DIRECTORY publishes one new owner
        // unless malformed output aliases the retained parent Directory.
        let handle = unsafe {
            crate::handle::adopt_produced_handle_excluding(result.value0, &[directory.raw()])?
        };
        Ok(Self { handle })
    }

    /// Starts an independent, handle-owned scan using only this Directory's READ right.
    /// Closing the reader releases its position; cache pages remain reclaimable.
    pub fn reader(&self) -> Result<DirectoryReader> {
        let directory = self.handle.as_handle_ref();
        let result = raw_ops::begin_directory_read(directory);
        Status::from_raw(result.status).into_result()?;
        // SAFETY: success publishes a fresh stream owner distinct from the retained Directory.
        let stream = unsafe {
            crate::handle::adopt_produced_handle_excluding(result.value0, &[directory.raw()])?
        };
        Ok(DirectoryReader {
            stream,
            next_cookie: Some(0),
        })
    }

    /// Recovers the generic typed owner for delegation or explicit close.
    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<DirectoryObject> {
        self.handle
    }
}

/// Exclusive ownership of one filesystem file.
pub struct File {
    handle: OwnedHandle<FileObject>,
}

impl File {
    /// Writes a bounded range; the returned count may be short.
    pub fn write_at(&self, offset: u64, input: &[u8]) -> Result<usize> {
        self.write(Some(offset), input).map(|(count, _)| count)
    }

    /// Appends one bounded write atomically and reports its end offset.
    pub fn append(&self, input: &[u8]) -> Result<(usize, u64)> {
        self.write(None, input)
    }

    fn write(&self, offset: Option<u64>, input: &[u8]) -> Result<(usize, u64)> {
        let count = input.len().min(MAX_READ_BYTES);
        // SAFETY: the owned File and the selected input range remain live.
        let result = unsafe {
            hyper_sys::file_write_at(
                self.as_handle_ref().raw().get(),
                u32::from(offset.is_none()),
                offset.unwrap_or(0),
                input.as_ptr(),
                count,
            )
        };
        Status::from_raw(result.status).into_result()?;
        let actual = usize::try_from(result.value0).map_err(|_| Error::InvalidResponse)?;
        if actual > count || result.value1 < actual as u64 {
            return Err(Error::InvalidResponse);
        }
        Ok((actual, result.value1))
    }

    /// Changes the file length; extension reads as zero.
    pub fn resize(&self, size: u64) -> Result<()> {
        // SAFETY: the owned File pins the Native handle throughout this call.
        let result = unsafe { hyper_sys::file_resize(self.as_handle_ref().raw().get(), size) };
        Status::from_raw(result.status).into_result()
    }

    /// Restores file operations from an exclusively owned typed handle.
    ///
    /// This consumes the owner and is therefore safe for a delegated file.
    #[must_use]
    pub const fn from_handle(handle: OwnedHandle<FileObject>) -> Self {
        Self { handle }
    }

    /// Borrows the underlying file capability.
    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, FileObject> {
        self.handle.as_handle_ref()
    }

    /// Returns stable identity and a current attribute snapshot for this File.
    ///
    /// The File handle must carry [`Rights::INSPECT`].
    pub fn info(&self) -> Result<FileInfo> {
        decode_file_info(raw_ops::file_info(self.handle.as_handle_ref())?)
    }

    /// Returns the current file size reported by the kernel.
    pub fn size(&self) -> Result<u64> {
        self.read_at(0, &mut []).map(|outcome| outcome.file_size)
    }

    /// Reads at most one ABI-bounded chunk from `offset`.
    ///
    /// When `output` is larger than the ABI limit, only its first bounded
    /// prefix is considered. The returned file size is immutable for the life
    /// of this `File` object.
    pub fn read_at(&self, offset: u64, output: &mut [u8]) -> Result<ReadOutcome> {
        let capacity = output.len().min(MAX_READ_BYTES);
        let output = output.get_mut(..capacity).ok_or(Error::InvalidResponse)?;
        let result = raw_ops::read(self.handle.as_handle_ref(), offset, output);
        Status::from_raw(result.status).into_result()?;
        let actual = usize::try_from(result.value0).map_err(|_| Error::InvalidResponse)?;
        if actual > capacity {
            return Err(Error::InvalidResponse);
        }
        let actual_u64 = u64::try_from(actual).map_err(|_| Error::InvalidResponse)?;
        let end = offset
            .checked_add(actual_u64)
            .ok_or(Error::InvalidResponse)?;
        if actual != 0 && end > result.value1 {
            return Err(Error::InvalidResponse);
        }
        Ok(ReadOutcome {
            bytes_read: actual,
            file_size: result.value1,
        })
    }

    /// Fills `output`, issuing as many bounded reads as necessary.
    ///
    /// On an unexpected end of file, the completed prefix remains initialized
    /// and the error reports its exact length.
    pub fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<()> {
        if output.is_empty() {
            return Ok(());
        }
        let expected = output.len();
        let expected_u64 = u64::try_from(expected).map_err(|_| Error::OffsetOverflow)?;
        let end = offset
            .checked_add(expected_u64)
            .ok_or(Error::OffsetOverflow)?;
        let file_size = self.size()?;
        if end > file_size {
            return Err(Error::UnexpectedEndOfFile {
                completed: 0,
                expected,
                file_size,
            });
        }

        let mut completed = 0;
        while completed < expected {
            let completed_u64 = u64::try_from(completed).map_err(|_| Error::OffsetOverflow)?;
            let chunk_offset = offset
                .checked_add(completed_u64)
                .ok_or(Error::OffsetOverflow)?;
            let remaining = output.get_mut(completed..).ok_or(Error::InvalidResponse)?;
            let outcome = self.read_at(chunk_offset, remaining)?;
            if outcome.bytes_read == 0 {
                return Err(Error::UnexpectedEndOfFile {
                    completed,
                    expected,
                    file_size,
                });
            }
            completed = completed
                .checked_add(outcome.bytes_read)
                .ok_or(Error::InvalidResponse)?;
        }
        Ok(())
    }

    /// Transfers this capability into a standard file with stream offset zero.
    /// Rights remain unchanged; no path lookup or handle duplication occurs.
    #[cfg(all(feature = "std", target_os = "hyper"))]
    pub fn into_std(self) -> std::fs::File {
        use std::os::hyper::io::FromRawHandle;
        let raw = self.into_handle().into_raw().get();
        // SAFETY: Consuming the typed File transfers its unique, live handle
        // owner into std. No SDK owner remains to close or transfer it.
        unsafe { std::fs::File::from_raw_handle(raw) }
    }

    /// Recovers the generic typed owner for delegation or explicit close.
    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<FileObject> {
        self.handle
    }
}

/// Result metadata from one bounded `File` read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOutcome {
    pub bytes_read: usize,
    pub file_size: u64,
}

/// An independent directory scan. Its handle owns only bounded iteration state.
pub struct DirectoryReader {
    stream: OwnedHandle<DirectoryStreamObject>,
    next_cookie: Option<u64>,
}

impl DirectoryReader {
    fn read_page(&self, cursor: u64) -> Result<(DirectoryPage, Option<u64>)> {
        let mut records = [EMPTY_RAW_DIRECTORY_ENTRY; DIRECTORY_PAGE_CAPACITY];
        let result = raw_ops::read_directory(self.stream.as_handle_ref(), cursor, &mut records);
        Status::from_raw(result.status).into_result()?;
        let count = usize::try_from(result.value0).map_err(|_| Error::InvalidResponse)?;
        if count > DIRECTORY_PAGE_CAPACITY
            || (count == 0 && result.value1 != 0)
            || (result.value1 != 0 && result.value1 == cursor)
        {
            return Err(Error::InvalidResponse);
        }

        let mut entries = [None; DIRECTORY_PAGE_CAPACITY];
        for (slot, raw) in entries.iter_mut().zip(records.iter()).take(count) {
            *slot = Some(decode_directory_entry(raw)?);
        }
        if records
            .get(count..)
            .ok_or(Error::InvalidResponse)?
            .iter()
            .any(|record| *record != EMPTY_RAW_DIRECTORY_ENTRY)
        {
            return Err(Error::InvalidResponse);
        }

        Ok((
            DirectoryPage {
                entries,
                len: count,
            },
            NonZeroU64::new(result.value1).map(NonZeroU64::get),
        ))
    }

    /// Reads the next page, or returns `None` after the scan reaches its end.
    pub fn next_page(&mut self) -> Result<Option<DirectoryPage>> {
        let Some(cookie) = self.next_cookie else {
            return Ok(None);
        };
        let (page, next_cookie) = self.read_page(cookie)?;
        self.next_cookie = next_cookie;
        if page.len == 0 {
            Ok(None)
        } else {
            Ok(Some(page))
        }
    }
}

/// One validated, bounded directory-enumeration page.
pub struct DirectoryPage {
    entries: [Option<DirectoryEntry>; DIRECTORY_PAGE_CAPACITY],
    len: usize,
}

impl DirectoryPage {
    pub fn entries(&self) -> impl Iterator<Item = &DirectoryEntry> {
        self.entries[..self.len].iter().filter_map(Option::as_ref)
    }
}

/// One owned directory entry validated at the syscall boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    name: [u8; MAX_NAME_BYTES],
    name_length: usize,
    kind: DirectoryEntryKind,
    mode: u32,
    size: u64,
}

impl DirectoryEntry {
    /// Returns the validated UTF-8 name bytes without trailing storage.
    #[must_use]
    pub fn name_bytes(&self) -> &[u8] {
        self.name.get(..self.name_length).unwrap_or(&[])
    }

    #[must_use]
    pub const fn kind(&self) -> DirectoryEntryKind {
        self.kind
    }

    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

const EMPTY_RAW_DIRECTORY_ENTRY: hyper_abi::HyperNativeDirectoryEntry =
    hyper_abi::HyperNativeDirectoryEntry {
        size: 0,
        mode: 0,
        kind: 0,
        name_length: 0,
        reserved: 0,
        name: [0; 256],
    };

fn decode_directory_entry(raw: &hyper_abi::HyperNativeDirectoryEntry) -> Result<DirectoryEntry> {
    let name_length = usize::try_from(raw.name_length).map_err(|_| Error::InvalidResponse)?;
    if raw.reserved != 0 || name_length == 0 || name_length > MAX_NAME_BYTES {
        return Err(Error::InvalidResponse);
    }
    let name = raw.name.get(..name_length).ok_or(Error::InvalidResponse)?;
    core::str::from_utf8(name).map_err(|_| Error::InvalidResponse)?;
    if raw
        .name
        .get(name_length..)
        .ok_or(Error::InvalidResponse)?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::InvalidResponse);
    }
    let kind = match u64::from(raw.kind) {
        hyper_abi::HYPER_NATIVE_DIRECTORY_ENTRY_KIND_FILE => DirectoryEntryKind::File,
        hyper_abi::HYPER_NATIVE_DIRECTORY_ENTRY_KIND_DIRECTORY => DirectoryEntryKind::Directory,
        hyper_abi::HYPER_NATIVE_DIRECTORY_ENTRY_KIND_SYMLINK => DirectoryEntryKind::Symlink,
        hyper_abi::HYPER_NATIVE_DIRECTORY_ENTRY_KIND_OTHER => DirectoryEntryKind::Other,
        _ => return Err(Error::InvalidResponse),
    };
    let mut owned_name = [0; MAX_NAME_BYTES];
    owned_name
        .get_mut(..name_length)
        .ok_or(Error::InvalidResponse)?
        .copy_from_slice(name);
    Ok(DirectoryEntry {
        name: owned_name,
        name_length,
        kind,
        mode: raw.mode,
        size: raw.size,
    })
}

fn decode_location(filesystem_id: u64, mount_id: u64, node_id: u64) -> Result<NodeLocation> {
    let filesystem = NonZeroU64::new(filesystem_id)
        .map(FilesystemId)
        .ok_or(Error::InvalidResponse)?;
    let mount = NonZeroU64::new(mount_id)
        .map(MountId)
        .ok_or(Error::InvalidResponse)?;
    Ok(NodeLocation {
        filesystem,
        mount,
        node: NodeId(node_id),
    })
}

fn decode_file_info(raw: hyper_abi::HyperNativeFileInfo) -> Result<FileInfo> {
    if raw.reserved != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(FileInfo {
        location: decode_location(raw.filesystem_id, raw.mount_id, raw.node_id)?,
        size: raw.size,
        mode: raw.mode,
    })
}

fn decode_directory_info(raw: hyper_abi::HyperNativeDirectoryInfo) -> Result<DirectoryInfo> {
    if raw.reserved != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(DirectoryInfo {
        location: decode_location(raw.filesystem_id, raw.mount_id, raw.node_id)?,
        mode: raw.mode,
    })
}

pub(crate) fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.as_bytes().contains(&0) {
        Err(Error::InvalidPath)
    } else {
        Ok(())
    }
}

#[cfg(not(test))]
mod raw_ops {
    use super::{DirectoryObject, DirectoryStreamObject, HandleRef, Rights};
    use crate::Result;

    pub(super) fn open(
        root: HandleRef<'_, DirectoryObject>,
        path: &str,
        rights: Rights,
    ) -> hyper_sys::CallResult {
        // SAFETY: the typed borrow keeps the directory root live, and the UTF-8
        // path remains readable for its complete length during the syscall.
        unsafe {
            hyper_sys::directory_open_file(
                root.raw().get(),
                path.as_ptr(),
                path.len(),
                rights.bits(),
            )
        }
    }

    pub(super) fn open_directory(
        root: HandleRef<'_, DirectoryObject>,
        path: &str,
        rights: Rights,
    ) -> hyper_sys::CallResult {
        // SAFETY: the typed borrow and path slice remain live for the syscall.
        unsafe {
            hyper_sys::directory_open_directory(
                root.raw().get(),
                path.as_ptr(),
                path.len(),
                rights.bits(),
            )
        }
    }

    pub(super) fn begin_directory_read(
        directory: HandleRef<'_, DirectoryObject>,
    ) -> hyper_sys::CallResult {
        // SAFETY: the caller retains the Directory and adopts the returned stream.
        unsafe { hyper_sys::directory_begin_read(directory.raw().get()) }
    }

    pub(super) fn read_directory(
        directory: HandleRef<'_, DirectoryStreamObject>,
        cookie: u64,
        records: &mut [hyper_abi::HyperNativeDirectoryEntry; super::DIRECTORY_PAGE_CAPACITY],
    ) -> hyper_sys::CallResult {
        // SAFETY: the typed borrow keeps the directory live and the unique
        // fixed-capacity array remains writable for the complete syscall.
        unsafe {
            hyper_sys::directory_read(
                directory.raw().get(),
                cookie,
                records.as_mut_ptr(),
                records.len(),
            )
        }
    }

    pub(super) fn directory_info(
        directory: HandleRef<'_, DirectoryObject>,
    ) -> Result<hyper_abi::HyperNativeDirectoryInfo> {
        let mut record = hyper_abi::HyperNativeDirectoryInfo {
            filesystem_id: 0,
            mount_id: 0,
            node_id: 0,
            mode: 0,
            reserved: 0,
        };
        // SAFETY: the typed borrow keeps the directory live and `record` is
        // writable for the exact fixed-width output record.
        let result = unsafe { hyper_sys::directory_get_info(directory.raw().get(), &mut record) };
        let _supported_size =
            crate::validate_info_result(result, hyper_abi::HYPER_NATIVE_DIRECTORY_INFO_MIN_SIZE)?;
        Ok(record)
    }

    pub(super) fn read(
        file: HandleRef<'_, super::FileObject>,
        offset: u64,
        output: &mut [u8],
    ) -> hyper_sys::CallResult {
        // SAFETY: the typed borrow keeps the file live and the unique output
        // slice remains writable for its complete length during the syscall.
        unsafe {
            hyper_sys::file_read_at(file.raw().get(), offset, output.as_mut_ptr(), output.len())
        }
    }

    pub(super) fn file_info(
        file: HandleRef<'_, super::FileObject>,
    ) -> Result<hyper_abi::HyperNativeFileInfo> {
        let mut record = hyper_abi::HyperNativeFileInfo {
            filesystem_id: 0,
            mount_id: 0,
            node_id: 0,
            size: 0,
            mode: 0,
            reserved: 0,
        };
        // SAFETY: the typed borrow keeps the file live and `record` is
        // writable for the exact fixed-width output record.
        let result = unsafe { hyper_sys::file_get_info(file.raw().get(), &mut record) };
        let _supported_size =
            crate::validate_info_result(result, hyper_abi::HYPER_NATIVE_FILE_INFO_MIN_SIZE)?;
        Ok(record)
    }
}

#[cfg(test)]
mod raw_ops {
    use super::{DirectoryObject, DirectoryStreamObject, HandleRef, Rights};
    use crate::Result;

    const CONTENT: &[u8] = b"HypeR VFS test image";

    pub(super) fn open(
        _root: HandleRef<'_, DirectoryObject>,
        path: &str,
        _rights: Rights,
    ) -> hyper_sys::CallResult {
        if path == "bin/init" {
            hyper_sys::CallResult {
                status: hyper_abi::HYPER_NATIVE_STATUS_OK,
                value0: hyper_abi::HYPER_NATIVE_OBJECT_FILE.into(),
                value1: 0,
            }
        } else {
            hyper_sys::CallResult {
                status: hyper_abi::HYPER_NATIVE_STATUS_NOT_FOUND,
                value0: 0,
                value1: 0,
            }
        }
    }

    pub(super) fn open_directory(
        _root: HandleRef<'_, DirectoryObject>,
        path: &str,
        _rights: Rights,
    ) -> hyper_sys::CallResult {
        let status = if path == "lib" {
            hyper_abi::HYPER_NATIVE_STATUS_OK
        } else {
            hyper_abi::HYPER_NATIVE_STATUS_NOT_FOUND
        };
        hyper_sys::CallResult {
            status,
            value0: 0x100_u64 | u64::from(hyper_abi::HYPER_NATIVE_OBJECT_DIRECTORY),
            value1: 0,
        }
    }

    pub(super) fn begin_directory_read(
        _directory: HandleRef<'_, DirectoryObject>,
    ) -> hyper_sys::CallResult {
        hyper_sys::CallResult {
            status: 0,
            value0: 0x600_u64 | u64::from(hyper_abi::HYPER_NATIVE_OBJECT_DIRECTORY_STREAM),
            value1: 0,
        }
    }

    pub(super) fn read_directory(
        _directory: HandleRef<'_, DirectoryStreamObject>,
        cookie: u64,
        records: &mut [hyper_abi::HyperNativeDirectoryEntry; super::DIRECTORY_PAGE_CAPACITY],
    ) -> hyper_sys::CallResult {
        if cookie != 0 {
            return hyper_sys::CallResult {
                status: hyper_abi::HYPER_NATIVE_STATUS_INVALID_ARGUMENT,
                value0: 0,
                value1: 0,
            };
        }
        let entries = [
            (b"bin".as_slice(), 0o040_755, 0_u64),
            (b"init".as_slice(), 0o100_755, 20),
        ];
        for (record, (name, mode, size)) in records.iter_mut().zip(entries) {
            record.size = size;
            record.mode = mode;
            record.kind = if mode & 0o040_000 != 0 {
                hyper_abi::HYPER_NATIVE_DIRECTORY_ENTRY_KIND_DIRECTORY as u32
            } else {
                hyper_abi::HYPER_NATIVE_DIRECTORY_ENTRY_KIND_FILE as u32
            };
            record.name_length = name.len() as u32;
            if let Some(destination) = record.name.get_mut(..name.len()) {
                destination.copy_from_slice(name);
            }
        }
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_OK,
            value0: entries.len() as u64,
            value1: 0,
        }
    }

    pub(super) fn directory_info(
        _directory: HandleRef<'_, DirectoryObject>,
    ) -> Result<hyper_abi::HyperNativeDirectoryInfo> {
        Ok(hyper_abi::HyperNativeDirectoryInfo {
            filesystem_id: 11,
            mount_id: 17,
            node_id: 0,
            mode: 0o040_755,
            reserved: 0,
        })
    }

    pub(super) fn read(
        _file: HandleRef<'_, super::FileObject>,
        offset: u64,
        output: &mut [u8],
    ) -> hyper_sys::CallResult {
        let start = match usize::try_from(offset) {
            Ok(start) => start,
            Err(_) => usize::MAX,
        };
        let source = CONTENT.get(start..).unwrap_or(&[]);
        let actual = source.len().min(output.len());
        if let (Some(source), Some(destination)) = (source.get(..actual), output.get_mut(..actual))
        {
            destination.copy_from_slice(source);
        }
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_OK,
            value0: actual as u64,
            value1: CONTENT.len() as u64,
        }
    }

    pub(super) fn file_info(
        _file: HandleRef<'_, super::FileObject>,
    ) -> Result<hyper_abi::HyperNativeFileInfo> {
        Ok(hyper_abi::HyperNativeFileInfo {
            filesystem_id: 11,
            mount_id: 17,
            node_id: 2,
            size: CONTENT.len() as u64,
            mode: 0o100_755,
            reserved: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use super::{Directory, DirectoryEntryKind, DirectoryRights, FileRights};
    use crate::Error;
    use crate::handle::{AnyObject, DirectoryObject, FileObject, OwnedHandle, Rights};

    fn root_directory() -> Result<Directory, Error> {
        let raw = NonZeroU64::new(hyper_abi::HYPER_NATIVE_OBJECT_DIRECTORY.into())
            .ok_or(Error::InvalidResponse)?;
        // SAFETY: the host backend treats this one nonzero value as a unique
        // directory owner for the duration of the test.
        Ok(Directory::from_handle(unsafe {
            OwnedHandle::<DirectoryObject>::from_raw_owned(raw)
        }))
    }

    #[test]
    fn rights_narrowing_rejects_non_file_authority() {
        assert!(FileRights::from_rights(Rights::READ.union(Rights::TRANSFER)).is_some());
        assert!(FileRights::from_rights(Rights::WRITE).is_some());
        assert!(FileRights::from_rights(Rights::CREATE_PROCESS).is_none());
        assert!(FileRights::from_rights(Rights::MANAGE_NAMESPACE).is_none());
        assert!(DirectoryRights::from_rights(Rights::MANAGE_NAMESPACE).is_none());
        assert!(DirectoryRights::from_rights(Rights::READ.union(Rights::EXECUTE)).is_some());
        assert!(DirectoryRights::from_rights(Rights::WRITE).is_some());
    }

    #[test]
    fn opens_typed_child_directory() -> Result<(), Error> {
        let child = root_directory()?.open_directory("lib", DirectoryRights::READ)?;
        let _ = child.as_handle_ref();
        Ok(())
    }

    #[test]
    fn directory_pages_expose_validated_names_and_kinds() -> Result<(), Error> {
        let directory = root_directory()?;
        let mut reader = directory.reader()?;
        let Some(page) = reader.next_page()? else {
            return Err(Error::InvalidResponse);
        };
        let mut entries = page.entries();
        let Some(bin) = entries.next() else {
            return Err(Error::InvalidResponse);
        };
        assert_eq!(bin.name_bytes(), b"bin");
        assert_eq!(bin.kind(), DirectoryEntryKind::Directory);
        let Some(init) = entries.next() else {
            return Err(Error::InvalidResponse);
        };
        assert_eq!(init.name_bytes(), b"init");
        assert_eq!(init.kind(), DirectoryEntryKind::File);
        assert_eq!(init.size(), 20);
        assert!(entries.next().is_none());
        assert!(reader.next_page()?.is_none());
        Ok(())
    }

    #[test]
    fn open_and_exact_read_are_typed_and_bounded() -> Result<(), Error> {
        let file =
            root_directory()?.open("bin/init", FileRights::READ.union(FileRights::TRANSFER))?;
        let mut bytes = [0_u8; 20];
        file.read_exact_at(0, &mut bytes)?;
        assert_eq!(&bytes, b"HypeR VFS test image");
        assert_eq!(file.size()?, bytes.len() as u64);
        Ok(())
    }

    #[test]
    fn typed_info_reports_stable_location_and_attributes() -> Result<(), Error> {
        let directory = root_directory()?;
        let directory_info = directory.info()?;
        assert_eq!(directory_info.location().filesystem().get(), 11);
        assert_eq!(directory_info.location().mount().get(), 17);
        assert_eq!(directory_info.location().node().get(), 0);
        assert_eq!(directory_info.mode(), 0o040_755);

        let file = directory.open("bin/init", FileRights::READ.union(FileRights::INSPECT))?;
        let file_info = file.info()?;
        assert_eq!(file_info.location().filesystem().get(), 11);
        assert_eq!(file_info.location().mount().get(), 17);
        assert_eq!(file_info.location().node().get(), 2);
        assert_eq!(file_info.size(), 20);
        assert_eq!(file_info.mode(), 0o100_755);
        Ok(())
    }

    #[test]
    fn typed_info_rejects_reserved_data_and_zero_scope_identity() {
        assert_eq!(
            super::decode_file_info(hyper_abi::HyperNativeFileInfo {
                filesystem_id: 0,
                mount_id: 1,
                node_id: 0,
                size: 0,
                mode: 0,
                reserved: 0,
            }),
            Err(Error::InvalidResponse)
        );
        assert_eq!(
            super::decode_directory_info(hyper_abi::HyperNativeDirectoryInfo {
                filesystem_id: 1,
                mount_id: 1,
                node_id: 0,
                mode: 0,
                reserved: 1,
            }),
            Err(Error::InvalidResponse)
        );
    }

    #[test]
    fn delegated_typed_owners_reenter_safe_filesystem_apis() -> Result<(), Error> {
        let directory_raw = NonZeroU64::new(hyper_abi::HYPER_NATIVE_OBJECT_DIRECTORY.into())
            .ok_or(Error::InvalidResponse)?;
        // SAFETY: this models one type-erased owner received from the kernel.
        let directory = unsafe { OwnedHandle::<AnyObject>::from_raw_owned(directory_raw) }
            .downcast::<DirectoryObject>()
            .map_err(|failure| failure.error())?;
        let directory = Directory::from_handle(directory);
        let _ = directory.as_handle_ref();

        let file_raw = NonZeroU64::new(hyper_abi::HYPER_NATIVE_OBJECT_FILE.into())
            .ok_or(Error::InvalidResponse)?;
        // SAFETY: this models a distinct type-erased owner received from the
        // kernel for the duration of this host test.
        let file = unsafe { OwnedHandle::<AnyObject>::from_raw_owned(file_raw) }
            .downcast::<FileObject>()
            .map_err(|failure| failure.error())?;
        let file = super::File::from_handle(file);
        assert_eq!(file.size()?, 20);
        Ok(())
    }

    #[test]
    fn invalid_path_and_short_exact_read_fail_before_partial_copy() -> Result<(), Error> {
        assert!(matches!(
            root_directory()?.open("bad\0path", FileRights::READ),
            Err(Error::InvalidPath)
        ));
        let file = root_directory()?.open("bin/init", FileRights::READ)?;
        let mut bytes = [0xaa_u8; 21];
        assert!(matches!(
            file.read_exact_at(0, &mut bytes),
            Err(Error::UnexpectedEndOfFile {
                completed: 0,
                expected: 21,
                file_size: 20,
            })
        ));
        assert_eq!(bytes, [0xaa; 21]);
        file.read_exact_at(u64::MAX, &mut [])?;
        Ok(())
    }
}
