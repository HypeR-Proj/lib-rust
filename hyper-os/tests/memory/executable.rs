// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) mod raw_ops {
    use super::*;
    pub(crate) fn publish(_: u64, _: u64) -> hyper_sys::CallResult {
        hyper_sys::CallResult {
            status: 0,
            value0: 0x10009,
            value1: crate::memory::PAGE_SIZE,
        }
    }
    pub(crate) fn info(owner: HandleRef<'_, AnyObject>) -> Result<crate::handle::HandleInfo> {
        let mut info = owner.info()?;
        info.rights = match owner.raw().get() {
            0x30009 => Rights::READ.union(Rights::MAP).union(Rights::EXECUTE),
            0x40009 => Rights::READ.union(Rights::MAP),
            0x50009 => EXECUTABLE_RIGHTS.union(Rights::WRITE),
            _ => EXECUTABLE_RIGHTS,
        };
        Ok(info)
    }
}

#[test]
fn received_executable_accepts_attenuated_rights_and_rejects_invalid_metadata() -> Result<()> {
    let output = ExecutableVmo::from_handle(input(0x30009)?, crate::memory::PAGE_SIZE)?;
    assert_eq!(output.byte_size(), crate::memory::PAGE_SIZE);
    assert_eq!(output.into_handle().as_handle_ref().raw().get(), 0x30009);
    let before = crate::handle::test_executable_close_count();
    for raw in [0x40009, 0x50009] {
        assert!(matches!(
            ExecutableVmo::from_handle(input(raw)?, crate::memory::PAGE_SIZE),
            Err(Error::InvalidResponse)
        ));
    }
    for size in [0, 1, crate::memory::PAGE_SIZE + 1] {
        assert!(matches!(
            ExecutableVmo::from_handle(input(0x60009)?, size),
            Err(Error::InvalidResponse)
        ));
    }
    assert_eq!(crate::handle::test_executable_close_count(), before + 5);
    let owner = input::<AnyObject>(0x30009)?;
    assert_eq!(
        validate_output(
            crate::memory::PAGE_SIZE,
            raw_ops::info(owner.as_handle_ref())?
        ),
        Err(Error::InvalidResponse)
    );
    Ok(())
}
fn input<T: crate::handle::ObjectType>(value: u64) -> Result<OwnedHandle<T>> {
    // SAFETY: synthetic handles belong to this test's local fake backend.
    unsafe { crate::handle::adopt_produced_handle_excluding(value, &[]) }
}

#[test]
fn publication_adopts_fresh_output_without_consuming_inputs() -> Result<()> {
    let authority = ExecutableAuthority::from_handle(input(8)?);
    let source = input::<VmoObject>(9)?;
    let output = authority.publish(source.as_handle_ref())?;
    assert_eq!(output.byte_size(), crate::memory::PAGE_SIZE);
    assert_eq!(output.as_handle_ref().raw().get(), 0x10009);
    assert_eq!(source.as_handle_ref().raw().get(), 9);
    assert_eq!(authority.into_handle().as_handle_ref().raw().get(), 8);
    assert_eq!(output.into_handle().as_handle_ref().raw().get(), 0x10009);
    Ok(())
}

#[test]
fn output_aliases_and_malformed_metadata_are_rejected() -> Result<()> {
    let authority = input::<ExecutableAuthorityObject>(8)?;
    let source = input::<VmoObject>(9)?;
    for value0 in [0, 8, 9] {
        let result = hyper_sys::CallResult {
            status: 0,
            value0,
            value1: crate::memory::PAGE_SIZE,
        };
        assert!(matches!(
            ExecutableVmo::adopt(
                result,
                authority.as_handle_ref().raw(),
                source.as_handle_ref().raw()
            ),
            Err(Error::InvalidResponse)
        ));
    }
    let owner = input::<AnyObject>(0x20009)?;
    let mut info = raw_ops::info(owner.as_handle_ref())?;
    for size in [0, 1, crate::memory::PAGE_SIZE + 1] {
        assert_eq!(validate_output(size, info), Err(Error::InvalidResponse));
    }
    info.rights = EXECUTABLE_RIGHTS.union(Rights::WRITE);
    assert_eq!(
        validate_output(crate::memory::PAGE_SIZE, info),
        Err(Error::InvalidResponse)
    );
    let error = hyper_sys::CallResult {
        status: hyper_abi::HYPER_NATIVE_STATUS_BUSY,
        value0: 9,
        value1: u64::MAX,
    };
    assert!(matches!(
        ExecutableVmo::adopt(
            error,
            authority.as_handle_ref().raw(),
            source.as_handle_ref().raw()
        ),
        Err(Error::Status(Status::BUSY))
    ));
    Ok(())
}
