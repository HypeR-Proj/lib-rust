// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Capability-controlled publication of immutable executable memory.

mod mapping;
pub use mapping::ExecutableMapping;

use crate::handle::{
    AnyObject, ExecutableAuthorityObject, HandleRef, OwnedHandle, Rights, TypedObject, VmoObject,
};
use crate::{Error, Result, Status};
use core::num::NonZeroU64;

const EXECUTABLE_RIGHTS: Rights = Rights::READ
    .union(Rights::MAP)
    .union(Rights::EXECUTE)
    .union(Rights::INSPECT)
    .union(Rights::DUPLICATE)
    .union(Rights::TRANSFER);

/// Explicit authority to publish executable copies; never granted by the factory.
pub struct ExecutableAuthority {
    handle: OwnedHandle<ExecutableAuthorityObject>,
}

impl ExecutableAuthority {
    /// Accepts an explicitly delegated capability without amplifying its rights.
    pub const fn from_handle(handle: OwnedHandle<ExecutableAuthorityObject>) -> Self {
        Self { handle }
    }
    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, ExecutableAuthorityObject> {
        self.handle.as_handle_ref()
    }
    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<ExecutableAuthorityObject> {
        self.handle
    }

    /// Copies an ordinary writable RAM VMO into immutable executable backing.
    /// Requires `CREATE_EXECUTABLE` on this capability and READ on the source.
    /// Source ownership and contents are unchanged; later source writes cannot
    /// affect the executable copy. Active writable mappings, shared atomic waits
    /// and hardware ownership report BUSY. Destination memory is charged to the
    /// caller. Instruction-cache publication completes before success.
    pub fn publish(&self, source: HandleRef<'_, VmoObject>) -> Result<ExecutableVmo> {
        let authority = self.as_handle_ref().raw();
        let source = source.raw();
        ExecutableVmo::adopt(
            raw_ops::publish(authority.get(), source.get()),
            authority,
            source,
        )
    }
}

/// Physically independent immutable instructions, with no writable capability.
pub struct ExecutableVmo {
    handle: OwnedHandle<VmoObject>,
    byte_size: u64,
}

impl ExecutableVmo {
    /// Accepts an executable VMO received from another process.
    ///
    /// The received size must be nonzero and page-aligned. READ, MAP and EXECUTE
    /// are required; WRITE is forbidden, and administrative rights may have
    /// been attenuated. Inspecting handle rights does not require INSPECT.
    /// The size comes from the sender's protocol; the kernel checks the actual
    /// backing bounds when mapping. Failure closes the consumed handle.
    pub fn from_handle(handle: OwnedHandle<VmoObject>, byte_size: u64) -> Result<Self> {
        let info = raw_ops::info(handle.as_handle_ref().erase())?;
        validate_received(byte_size, info)?;
        Ok(Self { handle, byte_size })
    }

    fn adopt(
        result: hyper_sys::CallResult,
        authority: NonZeroU64,
        source: NonZeroU64,
    ) -> Result<Self> {
        Status::from_raw(result.status).into_result()?;
        // SAFETY: success transfers a fresh handle; reject aliases to either
        // borrowed input before constructing or closing an output owner.
        let owner = unsafe {
            crate::handle::adopt_produced_handle_excluding::<AnyObject>(
                result.value0,
                &[authority, source],
            )?
        };
        validate_output(result.value1, raw_ops::info(owner.as_handle_ref())?)?;
        let handle = owner
            .downcast::<VmoObject>()
            .map_err(|failure| failure.error())?;
        Ok(Self {
            handle,
            byte_size: result.value1,
        })
    }
    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, VmoObject> {
        self.handle.as_handle_ref()
    }
    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<VmoObject> {
        self.handle
    }
    #[must_use]
    pub const fn byte_size(&self) -> u64 {
        self.byte_size
    }
}

fn validate_output(size: u64, info: crate::handle::HandleInfo) -> Result<()> {
    validate_received(size, info)?;
    if info.rights != EXECUTABLE_RIGHTS {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}

fn validate_received(size: u64, info: crate::handle::HandleInfo) -> Result<()> {
    if info.kind != VmoObject::KIND {
        return Err(Error::UnexpectedObjectKind {
            expected: VmoObject::KIND.as_raw(),
            actual: info.kind.as_raw(),
        });
    }
    let required = Rights::READ.union(Rights::MAP).union(Rights::EXECUTE);
    if size == 0
        || !size.is_multiple_of(super::PAGE_SIZE)
        || !info.rights.contains(required)
        || !EXECUTABLE_RIGHTS.contains(info.rights)
    {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}

#[cfg(not(test))]
mod raw_ops {
    use super::*;
    pub(super) fn publish(authority: u64, source: u64) -> hyper_sys::CallResult {
        // SAFETY: the caller borrows both live inputs and adopts success output.
        unsafe { hyper_sys::executable_publish(authority, source, 0) }
    }
    pub(super) fn info(owner: HandleRef<'_, AnyObject>) -> Result<crate::handle::HandleInfo> {
        owner.info()
    }
}

#[cfg(test)]
#[path = "../../../tests/memory/executable.rs"]
mod tests;
#[cfg(test)]
use tests::raw_ops;
