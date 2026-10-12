// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Explicit namespace operations for bootstrap and deployment managers.

use crate::fs::validate_path;
use crate::handle::{DirectoryObject, HandleRef};
use crate::{Error, Result, Status};
use hyper_abi as abi;

const MAX_MOVES: usize = abi::HYPER_NATIVE_FILESYSTEM_SWITCH_ROOT_MAX_MOVES as usize;

/// Mount a fresh writable Ramfs. The supplied directory must be a live root
/// anchor with `MANAGE_NAMESPACE | WRITE | EXECUTE` authority.
pub fn mount_ramfs(directory: HandleRef<'_, DirectoryObject>, path: &str) -> Result<()> {
    validate_path(path)?;
    // SAFETY: The capability and path remain borrowed for the synchronous call.
    check_result(unsafe {
        hyper_sys::filesystem_mount_ramfs(directory.raw().get(), path.as_ptr(), path.len())
    })
}

/// Replace the shared namespace root in one transaction. `new_root` and each
/// move's source are paths in the old root; `put_old` and each destination are
/// paths under the new root. Existing open objects retain their locations while
/// root anchors follow the new namespace root. Failure preserves all mount edges.
///
/// This requires `MANAGE_NAMESPACE | WRITE | EXECUTE` on a root anchor. At most
/// sixteen mount moves are admitted; no process is started or terminated here.
/// `new_root` must be a mounted filesystem root. Destinations must be distinct
/// directories in that filesystem and must not cover each other or child mounts.
pub fn switch_root(
    directory: HandleRef<'_, DirectoryObject>,
    new_root: &str,
    put_old: &str,
    moves: &[(&str, &str)],
) -> Result<()> {
    let request = RootSwitch::new(new_root, put_old, moves)?;
    let wire = request.wire(new_root, put_old);
    // SAFETY: The wire record, move array, all borrowed strings and capability
    // remain alive until this non-retaining syscall finishes.
    check_result(unsafe { hyper_sys::filesystem_switch_root(directory.raw().get(), &wire) })
}

struct RootSwitch {
    moves: [abi::HyperNativeFilesystemMountMove; MAX_MOVES],
    count: usize,
}
impl RootSwitch {
    fn new(new_root: &str, put_old: &str, moves: &[(&str, &str)]) -> Result<Self> {
        validate_path(new_root)?;
        validate_path(put_old)?;
        if moves.len() > MAX_MOVES {
            return Err(Error::Status(Status::from_raw(
                abi::HYPER_NATIVE_STATUS_INVALID_ARGUMENT,
            )));
        }
        let mut result = Self {
            moves: [abi::HyperNativeFilesystemMountMove {
                source: 0,
                source_length: 0,
                target: 0,
                target_length: 0,
            }; MAX_MOVES],
            count: moves.len(),
        };
        for (record, &(source, target)) in result.moves.iter_mut().zip(moves) {
            validate_path(source)?;
            validate_path(target)?;
            *record = abi::HyperNativeFilesystemMountMove {
                source: source.as_ptr() as u64,
                source_length: source.len() as u64,
                target: target.as_ptr() as u64,
                target_length: target.len() as u64,
            };
        }
        Ok(result)
    }
    fn wire(&self, new_root: &str, put_old: &str) -> abi::HyperNativeFilesystemRootSwitch {
        abi::HyperNativeFilesystemRootSwitch {
            new_root: new_root.as_ptr() as u64,
            new_root_length: new_root.len() as u64,
            put_old: put_old.as_ptr() as u64,
            put_old_length: put_old.len() as u64,
            moves: if self.count == 0 {
                0
            } else {
                self.moves.as_ptr() as u64
            },
            move_count: self.count as u64,
        }
    }
}

fn check_result(result: hyper_sys::CallResult) -> Result<()> {
    Status::from_raw(result.status).into_result()?;
    if result.value0 != 0 || result.value1 != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_move_set_has_no_wire_pointer() -> Result<()> {
        let request = RootSwitch::new("/new", "/boot", &[])?;
        let wire = request.wire("/new", "/boot");
        assert_eq!(wire.moves, 0);
        assert_eq!(wire.move_count, 0);
        Ok(())
    }

    #[test]
    fn rejects_invalid_paths_and_excess_moves_before_syscall() -> Result<()> {
        assert!(RootSwitch::new("", "/boot", &[]).is_err());
        assert!(RootSwitch::new("/new", "/boot", &[("/old", "bad\0path")]).is_err());
        assert!(RootSwitch::new("/new", "/boot", &[("/old", "/new"); MAX_MOVES + 1]).is_err());
        let long_path = [b'a'; 4097];
        let path = core::str::from_utf8(&long_path).map_err(|_| Error::InvalidPath)?;
        assert!(RootSwitch::new(path, "/boot", &[]).is_err());
        Ok(())
    }

    #[test]
    fn rejects_nonzero_reserved_success_values() {
        assert_eq!(
            check_result(hyper_sys::CallResult {
                status: abi::HYPER_NATIVE_STATUS_OK,
                value0: 1,
                value1: 0
            }),
            Err(Error::InvalidResponse)
        );
    }
}
