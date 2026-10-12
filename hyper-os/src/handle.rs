// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Linear ownership and typed borrowing of Native handles.

use core::marker::PhantomData;
use core::num::NonZeroU64;

use crate::{Error, Result, Status};

mod private {
    pub trait Sealed {}
}

/// Marker implemented by the closed set of Native kernel-object types.
pub trait ObjectType: private::Sealed {}

/// Marker for an object type with one exact Native ABI kind.
pub trait TypedObject: ObjectType {
    const KIND: ObjectKind;
}

mod object_kind;
pub use object_kind::*;

/// Type-erased Native kernel object.
pub enum AnyObject {}

impl private::Sealed for AnyObject {}
impl ObjectType for AnyObject {}

/// Stable observation identity which never grants object authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Koid(NonZeroU64);

impl Koid {
    pub(crate) const fn from_nonzero(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    pub fn from_raw(raw: u64) -> Result<Self> {
        NonZeroU64::new(raw)
            .map(Self::from_nonzero)
            .ok_or(Error::InvalidResponse)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Monotonically attenuated rights carried by one Native handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rights(u64);

impl Rights {
    pub const NONE: Self = Self(0);
    pub const DUPLICATE: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_DUPLICATE);
    pub const TRANSFER: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_TRANSFER);
    pub const WAIT: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_WAIT);
    pub const INSPECT: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_INSPECT);
    pub const INSPECT_DETAILS: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_INSPECT_DETAILS);
    pub const READ: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_READ);
    pub const WRITE: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_WRITE);
    pub const MAP: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_MAP);
    pub const EXECUTE: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_EXECUTE);
    pub const RESIZE: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_RESIZE);
    pub const PIN: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_PIN);
    pub const START: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_START);
    pub const REQUEST_STOP: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_REQUEST_STOP);
    pub const RUN_VCPU: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_RUN_VCPU);
    pub const INJECT_INTERRUPT: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_INJECT_INTERRUPT);
    pub const GRANT_MEMORY: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_GRANT_MEMORY);
    pub const ASSIGN_DEVICE: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_ASSIGN_DEVICE);
    pub const MAP_DMA: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_MAP_DMA);
    pub const ACK_INTERRUPT: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_ACK_INTERRUPT);
    pub const REVOKE: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_REVOKE);
    pub const SIGNAL: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_SIGNAL);
    pub const CREATE_PROCESS: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_CREATE_PROCESS);
    pub const CREATE_THREAD: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_CREATE_THREAD);
    pub const CREATE_TASK_GROUP: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_CREATE_TASK_GROUP);
    pub const CREATE_RESOURCE_DOMAIN: Self =
        Self(hyper_abi::HYPER_NATIVE_RIGHT_CREATE_RESOURCE_DOMAIN);
    pub const SET_LIMITS: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_SET_LIMITS);
    pub const CREATE_EXECUTABLE: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_CREATE_EXECUTABLE);
    pub const TASK_GROUP_ATTACH_PROCESS: Self =
        Self(hyper_abi::HYPER_NATIVE_RIGHT_TASK_GROUP_ATTACH_PROCESS);
    pub const RESOURCE_DOMAIN_SPONSOR: Self =
        Self(hyper_abi::HYPER_NATIVE_RIGHT_RESOURCE_DOMAIN_SPONSOR);
    pub const DERIVE: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_DERIVE);
    pub const BIND_WAIT: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_BIND_WAIT);
    pub const SET_ATTRIBUTES: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_SET_ATTRIBUTES);
    pub const LOCK_FILE: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_LOCK_FILE);
    /// May change topology through a live namespace-root capability.
    pub const MANAGE_NAMESPACE: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_MANAGE_NAMESPACE);
    pub const PROTECT: Self = Self(hyper_abi::HYPER_NATIVE_RIGHT_PROTECT);
    pub const CREATE_VIRTUAL_MACHINE: Self =
        Self(hyper_abi::HYPER_NATIVE_RIGHT_CREATE_VIRTUAL_MACHINE);

    #[must_use]
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !hyper_abi::HYPER_NATIVE_RIGHTS_MASK == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Looks up one stable right name (the names returned by [`Self::names`]).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        RIGHT_NAMES
            .iter()
            .find_map(|(right, candidate)| (*candidate == name).then_some(*right))
    }

    /// Lists the vocabulary accepted by [`Self::from_name`].
    pub fn known_names() -> impl Iterator<Item = &'static str> {
        RIGHT_NAMES.iter().map(|(_, name)| *name)
    }

    /// Iterates stable lower-case names for every right in this set.
    #[must_use]
    pub const fn names(self) -> RightNames {
        RightNames {
            rights: self,
            next: 0,
        }
    }
}

const RIGHT_NAMES: &[(Rights, &str)] = &[
    (Rights::DUPLICATE, "duplicate"),
    (Rights::TRANSFER, "transfer"),
    (Rights::WAIT, "wait"),
    (Rights::INSPECT, "inspect"),
    (Rights::INSPECT_DETAILS, "inspect-details"),
    (Rights::READ, "read"),
    (Rights::WRITE, "write"),
    (Rights::MAP, "map"),
    (Rights::EXECUTE, "execute"),
    (Rights::RESIZE, "resize"),
    (Rights::PIN, "pin"),
    (Rights::START, "start"),
    (Rights::REQUEST_STOP, "request-stop"),
    (Rights::RUN_VCPU, "run-vcpu"),
    (Rights::INJECT_INTERRUPT, "inject-interrupt"),
    (Rights::GRANT_MEMORY, "grant-memory"),
    (Rights::ASSIGN_DEVICE, "assign-device"),
    (Rights::MAP_DMA, "map-dma"),
    (Rights::ACK_INTERRUPT, "ack-interrupt"),
    (Rights::REVOKE, "revoke"),
    (Rights::SIGNAL, "signal"),
    (Rights::CREATE_PROCESS, "create-process"),
    (Rights::CREATE_THREAD, "create-thread"),
    (Rights::CREATE_TASK_GROUP, "create-task-group"),
    (Rights::CREATE_RESOURCE_DOMAIN, "create-resource-domain"),
    (Rights::SET_LIMITS, "set-limits"),
    (Rights::CREATE_EXECUTABLE, "create-executable"),
    (Rights::TASK_GROUP_ATTACH_PROCESS, "attach-process"),
    (Rights::RESOURCE_DOMAIN_SPONSOR, "sponsor-domain"),
    (Rights::DERIVE, "derive"),
    (Rights::BIND_WAIT, "bind-wait"),
    (Rights::SET_ATTRIBUTES, "set-attributes"),
    (Rights::LOCK_FILE, "lock-file"),
    (Rights::PROTECT, "protect"),
    (Rights::MANAGE_NAMESPACE, "manage-namespace"),
    (Rights::CREATE_VIRTUAL_MACHINE, "create-virtual-machine"),
];

/// Iterator over the stable names in one [`Rights`] set.
pub struct RightNames {
    rights: Rights,
    next: usize,
}

impl Iterator for RightNames {
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((right, name)) = RIGHT_NAMES.get(self.next).copied() {
            self.next += 1;
            if self.rights.contains(right) {
                return Some(name);
            }
        }
        None
    }
}

/// The rights ceiling offered when delegating one capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RightsOffer {
    /// Offer every right currently carried by the source handle.
    SameRights,
    /// Offer exactly this rights ceiling.
    Exact(Rights),
}

impl RightsOffer {
    pub(crate) const fn raw(self) -> u64 {
        match self {
            Self::SameRights => hyper_abi::HYPER_NATIVE_CAPABILITY_DISPOSITION_SAME_RIGHTS,
            Self::Exact(rights) => rights.bits(),
        }
    }
}

/// Kernel-authored metadata for one process-local handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleInfo {
    pub kind: ObjectKind,
    pub rights: Rights,
    pub flags: u32,
}

/// Kernel-authored identity and kind for the object behind one handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectBasicInfo {
    pub koid: Koid,
    pub kind: ObjectKind,
}

/// Exclusive userspace ownership of one process-local Native handle.
///
/// This type is deliberately neither `Copy` nor `Clone`. Use [`Self::duplicate`]
/// to request another independently owned authority from the kernel.
pub struct OwnedHandle<T: ObjectType = AnyObject> {
    raw: Option<NonZeroU64>,
    _type: PhantomData<T>,
}

const _: () =
    assert!(core::mem::size_of::<OwnedHandle<AnyObject>>() == core::mem::size_of::<u64>());

impl<T: ObjectType> OwnedHandle<T> {
    /// Assumes exclusive ownership of one raw process handle.
    ///
    /// # Safety
    ///
    /// `raw` must identify a live handle owned exactly once by the caller. No
    /// other `OwnedHandle` may close or transfer the same process-local value.
    pub const unsafe fn from_raw_owned(raw: NonZeroU64) -> Self {
        Self {
            raw: Some(raw),
            _type: PhantomData,
        }
    }

    /// Borrows this handle without acquiring another kernel capability.
    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, T> {
        HandleRef {
            raw: self.live_raw(),
            _owner: PhantomData,
        }
    }

    /// Relinquishes Rust ownership without closing the process handle.
    #[must_use]
    pub fn into_raw(mut self) -> NonZeroU64 {
        match self.raw.take() {
            Some(raw) => raw,
            None => ownership_invariant(),
        }
    }

    /// Queries the kernel-authored kind, rights, and flags for this handle.
    pub fn info(&self) -> Result<HandleInfo> {
        query_info(self.live_raw())
    }

    /// Queries stable object identity and kind through this handle.
    ///
    /// The handle must carry [`Rights::INSPECT`]. The returned KOID is
    /// observation-only and cannot be converted back into authority.
    pub fn basic_info(&self) -> Result<ObjectBasicInfo> {
        query_basic_info(self.live_raw())
    }

    /// Creates one independently owned handle with attenuated rights.
    pub fn duplicate(&self, rights: Rights) -> Result<Self> {
        let source = self.live_raw();
        let result = duplicate_raw(source, rights);
        Status::from_raw(result.status).into_result()?;
        // SAFETY: successful HANDLE_DUPLICATE publishes one new owner unless a
        // malformed result aliases the still-live source, which the helper
        // rejects before constructing or closing any owner.
        unsafe { adopt_produced_handle_excluding(result.value0, &[source]) }
    }

    /// Replaces this handle with an attenuated generation-qualified value.
    ///
    /// A rejected syscall returns the original owner. A malformed successful
    /// response is explicitly committed because the source has already been
    /// consumed by the kernel and cannot safely be reconstructed.
    pub fn replace(mut self, rights: Rights) -> core::result::Result<Self, ReplaceFailure<T>> {
        let result = replace_raw(self.live_raw(), rights);
        let status = Status::from_raw(result.status);
        if status != Status::OK {
            return Err(ReplaceFailure::Rejected(HandleFailure {
                error: Error::Status(status),
                handle: self,
            }));
        }

        // HANDLE_REPLACE consumes the source on success, even if a broken
        // kernel subsequently reports an invalid replacement value.
        let _ = self.raw.take();
        let raw = NonZeroU64::new(result.value0)
            .ok_or(ReplaceFailure::Committed(Error::InvalidResponse))?;
        // SAFETY: the successful replacement result is the unique new owner.
        Ok(unsafe { Self::from_raw_owned(raw) })
    }

    /// Explicitly closes this handle, preserving ownership on rejection.
    pub fn try_close(mut self) -> core::result::Result<(), HandleFailure<T>> {
        let status = close_raw(self.live_raw());
        if status == Status::OK {
            let _ = self.raw.take();
            Ok(())
        } else {
            Err(HandleFailure {
                error: Error::Status(status),
                handle: self,
            })
        }
    }

    /// Erases only the compile-time object kind; ownership is unchanged.
    #[must_use]
    pub fn erase(mut self) -> OwnedHandle<AnyObject> {
        let raw = match self.raw.take() {
            Some(raw) => raw,
            None => ownership_invariant(),
        };
        // SAFETY: this is a type erasure of the same unique Rust owner.
        unsafe { OwnedHandle::from_raw_owned(raw) }
    }

    fn live_raw(&self) -> NonZeroU64 {
        match self.raw {
            Some(raw) => raw,
            None => ownership_invariant(),
        }
    }
}

/// Adopts one output from a successful handle-producing operation.
///
/// A malformed output which aliases a still-live input is rejected before an
/// `OwnedHandle` is constructed. In particular, the aliased input must not be
/// closed: it remains owned by its original safe wrapper.
///
/// # Safety
///
/// The successful syscall must transfer ownership of a nonzero `raw` value
/// when it does not equal one of `live_inputs`. Every value in `live_inputs`
/// must remain live and untransferred after the syscall returns.
pub(crate) unsafe fn adopt_produced_handle_excluding<T: ObjectType>(
    raw: u64,
    live_inputs: &[NonZeroU64],
) -> Result<OwnedHandle<T>> {
    let raw = NonZeroU64::new(raw).ok_or(Error::InvalidResponse)?;
    if live_inputs.contains(&raw) {
        return Err(Error::InvalidResponse);
    }
    // SAFETY: the caller establishes ownership transfer for every non-aliased
    // successful output, and the check above preserves all live inputs.
    Ok(unsafe { OwnedHandle::from_raw_owned(raw) })
}

/// Adopts both outputs of one successful two-handle creation operation.
///
/// Malformed output is still an ownership-bearing result: every distinct
/// nonzero value is closed exactly once before the protocol error is returned.
/// Keeping this rule beside `OwnedHandle` prevents pair-returning wrappers from
/// accidentally manufacturing duplicate Rust owners while validating results.
///
/// # Safety
///
/// The successful syscall must transfer ownership of every distinct nonzero
/// value in `raw` to the caller, including when the pair is malformed.
pub(crate) unsafe fn adopt_produced_handle_pair<First: ObjectType, Second: ObjectType>(
    raw: [u64; 2],
) -> Result<(OwnedHandle<First>, OwnedHandle<Second>)> {
    let [first, second] = match classify_produced_handle_pair(raw) {
        Ok(pair) => pair,
        Err(error) => {
            close_distinct_raw_owners(&raw);
            return Err(error);
        }
    };
    // SAFETY: the caller establishes that the successful operation transferred
    // both distinct outputs, which the checks above prove are nonzero.
    let first = unsafe { OwnedHandle::from_raw_owned(first) };
    // SAFETY: this is the second distinct owner from the same operation.
    let second = unsafe { OwnedHandle::from_raw_owned(second) };
    Ok((first, second))
}

fn classify_produced_handle_pair(raw: [u64; 2]) -> Result<[NonZeroU64; 2]> {
    let (Some(first), Some(second)) = (NonZeroU64::new(raw[0]), NonZeroU64::new(raw[1])) else {
        return Err(Error::InvalidResponse);
    };
    if first == second {
        return Err(Error::InvalidResponse);
    }
    Ok([first, second])
}

fn close_distinct_raw_owners(raw: &[u64]) {
    for (index, value) in raw.iter().copied().enumerate() {
        let Some(value) = NonZeroU64::new(value) else {
            continue;
        };
        if raw[..index].contains(&value.get()) {
            continue;
        }
        // SAFETY: this helper is reached only for ownership-bearing successful
        // results and de-duplication constructs exactly one owner per value.
        drop(unsafe { OwnedHandle::<AnyObject>::from_raw_owned(value) });
    }
}

impl OwnedHandle<AnyObject> {
    /// Validates and narrows this erased owner to one exact object kind.
    ///
    /// A failed query or kind mismatch returns the unchanged erased owner, so
    /// callers can inspect it, try another interpretation, or close it.
    pub fn downcast<T: TypedObject>(
        mut self,
    ) -> core::result::Result<OwnedHandle<T>, HandleFailure<AnyObject>> {
        let info = match self.info() {
            Ok(info) => info,
            Err(error) => {
                return Err(HandleFailure {
                    error,
                    handle: self,
                });
            }
        };
        if info.kind != T::KIND {
            return Err(HandleFailure {
                error: Error::UnexpectedObjectKind {
                    expected: T::KIND.as_raw(),
                    actual: info.kind.as_raw(),
                },
                handle: self,
            });
        }
        let raw = match self.raw.take() {
            Some(raw) => raw,
            None => ownership_invariant(),
        };
        // SAFETY: `self` was the unique owner and kernel metadata established
        // the marker's exact object kind before ownership moved here.
        Ok(unsafe { OwnedHandle::from_raw_owned(raw) })
    }
}

impl<T: ObjectType> Drop for OwnedHandle<T> {
    fn drop(&mut self) {
        if let Some(raw) = self.raw.take() {
            // Drop cannot report or retry a rejected close. Process teardown
            // remains the final owner of a handle which the kernel did not
            // consume; explicit lifecycle code should use `try_close`.
            let _ = close_raw(raw);
        }
    }
}

/// Copyable borrow of a handle whose [`OwnedHandle`] remains live.
pub struct HandleRef<'owner, T: ObjectType = AnyObject> {
    raw: NonZeroU64,
    _owner: PhantomData<&'owner OwnedHandle<T>>,
}

impl<'owner, T: ObjectType> HandleRef<'owner, T> {
    /// Creates a borrow tied to an owner tracked outside `OwnedHandle`.
    ///
    /// # Safety
    ///
    /// The raw handle must remain live and untransferred for `'owner`, and the
    /// caller must not grant a lifetime longer than that external owner.
    #[must_use]
    pub(crate) const unsafe fn from_raw_borrowed(raw: NonZeroU64) -> Self {
        Self {
            raw,
            _owner: PhantomData,
        }
    }

    #[must_use]
    pub(crate) const fn raw(&self) -> NonZeroU64 {
        self.raw
    }

    /// Creates an independently owned handle with attenuated rights.
    pub fn duplicate(&self, rights: Rights) -> Result<OwnedHandle<T>> {
        let result = duplicate_raw(self.raw, rights);
        Status::from_raw(result.status).into_result()?;
        // SAFETY: duplication produces a new owner; reject an alias to the live source.
        unsafe { adopt_produced_handle_excluding(result.value0, &[self.raw]) }
    }

    /// Queries metadata without acquiring or consuming authority.
    pub fn info(&self) -> Result<HandleInfo> {
        query_info(self.raw)
    }

    /// Queries stable object identity and kind through this borrowed handle.
    pub fn basic_info(&self) -> Result<ObjectBasicInfo> {
        query_basic_info(self.raw)
    }

    /// Erases only the borrowed compile-time object kind.
    #[must_use]
    pub fn erase(self) -> HandleRef<'owner, AnyObject> {
        HandleRef {
            raw: self.raw,
            _owner: PhantomData,
        }
    }
}

impl<T: ObjectType> Clone for HandleRef<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ObjectType> Copy for HandleRef<'_, T> {}

/// A rejected consuming operation together with the still-owned handle.
pub struct HandleFailure<T: ObjectType> {
    error: Error,
    handle: OwnedHandle<T>,
}

impl<T: ObjectType> HandleFailure<T> {
    #[must_use]
    pub const fn error(&self) -> Error {
        self.error
    }

    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<T> {
        self.handle
    }

    #[must_use]
    pub fn into_parts(self) -> (Error, OwnedHandle<T>) {
        (self.error, self.handle)
    }
}

/// Failure from a replacement which may already have consumed its source.
pub enum ReplaceFailure<T: ObjectType> {
    Rejected(HandleFailure<T>),
    Committed(Error),
}

fn query_info(raw: NonZeroU64) -> Result<HandleInfo> {
    let record = raw_ops::handle_info(raw)?;
    let rights = Rights::from_bits(record.rights).ok_or(Error::InvalidResponse)?;
    Ok(HandleInfo {
        kind: ObjectKind::from_kernel(record.object_kind)?,
        rights,
        flags: record.flags,
    })
}

fn query_basic_info(raw: NonZeroU64) -> Result<ObjectBasicInfo> {
    decode_basic_info(raw_ops::object_basic_info(raw)?)
}

fn decode_basic_info(record: hyper_abi::HyperNativeObjectBasicInfo) -> Result<ObjectBasicInfo> {
    if record.reserved != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(ObjectBasicInfo {
        koid: Koid::from_raw(record.koid)?,
        kind: ObjectKind::from_kernel(record.object_kind)?,
    })
}

fn close_raw(raw: NonZeroU64) -> Status {
    raw_ops::close(raw)
}

fn duplicate_raw(raw: NonZeroU64, rights: Rights) -> hyper_sys::CallResult {
    raw_ops::duplicate(raw, rights)
}

fn replace_raw(raw: NonZeroU64, rights: Rights) -> hyper_sys::CallResult {
    raw_ops::replace(raw, rights)
}

#[cfg(not(test))]
mod raw_ops {
    use core::num::NonZeroU64;

    use super::{Rights, Status};
    use crate::{Error, Result};

    pub(super) fn close(raw: NonZeroU64) -> Status {
        // SAFETY: the caller exclusively owns the raw handle for this close.
        Status::from_raw(unsafe { hyper_sys::handle_close(raw.get()) })
    }

    pub(super) fn duplicate(raw: NonZeroU64, rights: Rights) -> hyper_sys::CallResult {
        // SAFETY: the owner keeps the source live for this non-consuming call.
        unsafe { hyper_sys::handle_duplicate(raw.get(), rights.bits()) }
    }

    pub(super) fn replace(raw: NonZeroU64, rights: Rights) -> hyper_sys::CallResult {
        // SAFETY: the unique owner models the syscall's consume-on-success
        // transition and preserves itself when the kernel rejects the call.
        unsafe { hyper_sys::handle_replace(raw.get(), rights.bits()) }
    }

    pub(super) fn handle_info(raw: NonZeroU64) -> Result<hyper_abi::HyperNativeHandleInfo> {
        let mut record = hyper_abi::HyperNativeHandleInfo {
            object_kind: 0,
            flags: 0,
            rights: 0,
        };
        // SAFETY: `record` is writable for the ABI's exact fixed-width output,
        // and the borrowed source handle remains live throughout the syscall.
        let result = unsafe { hyper_sys::handle_get_info(raw.get(), &mut record) };
        let _supported_size =
            crate::validate_info_result(result, hyper_abi::HYPER_NATIVE_HANDLE_INFO_MIN_SIZE)?;
        if record.object_kind == hyper_abi::HYPER_NATIVE_OBJECT_NONE {
            return Err(Error::InvalidResponse);
        }
        Ok(record)
    }

    pub(super) fn object_basic_info(
        raw: NonZeroU64,
    ) -> Result<hyper_abi::HyperNativeObjectBasicInfo> {
        let mut record = hyper_abi::HyperNativeObjectBasicInfo {
            koid: 0,
            object_kind: 0,
            reserved: 0,
        };
        // SAFETY: `record` is writable for the exact ABI record and the
        // borrowed handle remains live throughout the syscall.
        let result = unsafe { hyper_sys::object_get_basic_info(raw.get(), &mut record) };
        let _supported_size = crate::validate_info_result(
            result,
            hyper_abi::HYPER_NATIVE_OBJECT_BASIC_INFO_MIN_SIZE,
        )?;
        Ok(record)
    }
}

#[cfg(test)]
mod raw_ops {
    use core::num::NonZeroU64;
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::{Rights, Status};
    use crate::Result;

    static SENTINEL_CLOSE_COUNT: AtomicU64 = AtomicU64::new(0);
    static ALIAS_CLOSE_COUNT: AtomicU64 = AtomicU64::new(0);

    pub(super) fn close(raw: NonZeroU64) -> Status {
        if raw.get() == super::TEST_SENTINEL_HANDLE {
            let _ = SENTINEL_CLOSE_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        if raw.get() == super::TEST_ALIAS_HANDLE {
            let _ = ALIAS_CLOSE_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        Status::OK
    }

    pub(crate) fn sentinel_close_count() -> u64 {
        SENTINEL_CLOSE_COUNT.load(Ordering::Relaxed)
    }

    pub(crate) fn alias_close_count() -> u64 {
        ALIAS_CLOSE_COUNT.load(Ordering::Relaxed)
    }

    pub(super) fn duplicate(raw: NonZeroU64, _rights: Rights) -> hyper_sys::CallResult {
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_OK,
            value0: if raw.get() == super::TEST_ALIAS_HANDLE {
                raw.get()
            } else {
                raw.get().saturating_add(256)
            },
            value1: 0,
        }
    }

    pub(super) fn replace(raw: NonZeroU64, _rights: Rights) -> hyper_sys::CallResult {
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_OK,
            value0: raw.get().saturating_add(512),
            value1: 0,
        }
    }

    pub(super) fn handle_info(raw: NonZeroU64) -> Result<hyper_abi::HyperNativeHandleInfo> {
        // Test handles encode a small object kind in their low byte and use
        // upper bits as a stand-in for the kernel's generation-qualified slot.
        let object_kind = (raw.get() & 0xff) as u32;
        let rights = match object_kind {
            hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL if raw.get() == 0x10002 => {
                hyper_abi::HYPER_NATIVE_RIGHT_READ | hyper_abi::HYPER_NATIVE_RIGHT_WAIT
            }
            hyper_abi::HYPER_NATIVE_OBJECT_PROCESS_BUILDER => {
                hyper_abi::HYPER_NATIVE_RIGHT_TRANSFER
                    | hyper_abi::HYPER_NATIVE_RIGHT_INSPECT
                    | hyper_abi::HYPER_NATIVE_RIGHT_WRITE
                    | hyper_abi::HYPER_NATIVE_RIGHT_START
                    | hyper_abi::HYPER_NATIVE_RIGHT_REQUEST_STOP
            }
            hyper_abi::HYPER_NATIVE_OBJECT_PROCESS => {
                hyper_abi::HYPER_NATIVE_RIGHT_TRANSFER
                    | hyper_abi::HYPER_NATIVE_RIGHT_WAIT
                    | hyper_abi::HYPER_NATIVE_RIGHT_INSPECT
                    | hyper_abi::HYPER_NATIVE_RIGHT_REQUEST_STOP
            }
            _ => hyper_abi::HYPER_NATIVE_RIGHTS_MASK,
        };
        Ok(hyper_abi::HyperNativeHandleInfo {
            object_kind,
            flags: 0,
            rights,
        })
    }

    pub(super) fn object_basic_info(
        raw: NonZeroU64,
    ) -> Result<hyper_abi::HyperNativeObjectBasicInfo> {
        Ok(hyper_abi::HyperNativeObjectBasicInfo {
            koid: raw.get().saturating_add(0x1_0000),
            object_kind: (raw.get() & 0xff) as u32,
            reserved: 0,
        })
    }
}

#[cfg(test)]
pub(crate) const TEST_SENTINEL_HANDLE: u64 = u64::MAX - 1;

#[cfg(test)]
const TEST_ALIAS_HANDLE: u64 = u64::MAX - 2;

#[cfg(test)]
pub(crate) fn test_sentinel_close_count() -> u64 {
    raw_ops::sentinel_close_count()
}

#[cfg(test)]
fn test_alias_close_count() -> u64 {
    raw_ops::alias_close_count()
}

#[cold]
#[cfg(not(test))]
pub(crate) fn ownership_invariant() -> ! {
    // Safe callers cannot observe a disarmed owner; this branch exists only
    // to contain an internal SDK bug without manufacturing a second owner.
    // SAFETY: this path is terminal and intentionally skips destructors.
    unsafe { hyper_sys::process_exit(hyper_abi::HYPER_NATIVE_STATUS_INTERNAL) }
}

#[cold]
#[cfg(test)]
pub(crate) fn ownership_invariant() -> ! {
    // Tests cannot link the Native terminal syscall. This path is unreachable
    // through the safe API and exists only to give both cfgs the same shape.
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use super::{AnyObject, ByteChannelObject, ObjectKind, OwnedHandle, Rights, TypedObject};

    #[test]
    fn produced_pair_classification_requires_two_distinct_nonzero_values() {
        assert_eq!(
            super::classify_produced_handle_pair([0, 2]),
            Err(crate::Error::InvalidResponse)
        );
        assert_eq!(
            super::classify_produced_handle_pair([1, 1]),
            Err(crate::Error::InvalidResponse)
        );
        let pair = super::classify_produced_handle_pair([1, 2]);
        assert_eq!(pair.map(|pair| [pair[0].get(), pair[1].get()]), Ok([1, 2]));
    }

    #[test]
    fn owned_handle_duplicate_and_replace_keep_one_owner() -> crate::Result<()> {
        let raw = NonZeroU64::new(hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL.into())
            .ok_or(crate::Error::InvalidResponse)?;
        // SAFETY: the test backend treats each nonzero value as one owner.
        let source = unsafe { OwnedHandle::<ByteChannelObject>::from_raw_owned(raw) };
        let duplicate = source.duplicate(Rights::READ)?;
        assert_ne!(
            source.as_handle_ref().raw(),
            duplicate.as_handle_ref().raw()
        );
        let replacement = match duplicate.replace(Rights::READ) {
            Ok(handle) => handle,
            Err(_) => return Err(crate::Error::InvalidResponse),
        };
        assert_ne!(
            source.as_handle_ref().raw(),
            replacement.as_handle_ref().raw()
        );
        Ok(())
    }

    #[test]
    fn malformed_duplicate_alias_preserves_the_live_source_owner() -> crate::Result<()> {
        let raw = NonZeroU64::new(super::TEST_ALIAS_HANDLE).ok_or(crate::Error::InvalidResponse)?;
        let closed_before = super::test_alias_close_count();
        // SAFETY: this test creates the sole owner of the dedicated raw value.
        let source = unsafe { OwnedHandle::<ByteChannelObject>::from_raw_owned(raw) };
        assert!(matches!(
            source.duplicate(Rights::READ),
            Err(crate::Error::InvalidResponse)
        ));
        assert_eq!(super::test_alias_close_count(), closed_before);
        assert_eq!(source.as_handle_ref().raw(), raw);
        source.try_close().map_err(|failure| failure.error())?;
        assert_eq!(super::test_alias_close_count(), closed_before + 1);
        Ok(())
    }

    #[test]
    fn erased_owner_downcasts_only_to_the_reported_kind() -> crate::Result<()> {
        let raw = NonZeroU64::new(hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL.into())
            .ok_or(crate::Error::InvalidResponse)?;
        // SAFETY: the test backend derives object kind from this nonzero value.
        let erased = unsafe { OwnedHandle::<AnyObject>::from_raw_owned(raw) };
        let typed = match erased.downcast::<ByteChannelObject>() {
            Ok(handle) => handle,
            Err(_) => return Err(crate::Error::InvalidResponse),
        };
        assert_eq!(
            typed.info().map(|info| info.kind),
            Ok(<ByteChannelObject as TypedObject>::KIND)
        );
        assert_eq!(
            <ByteChannelObject as TypedObject>::KIND.as_raw(),
            hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL
        );
        Ok(())
    }

    #[test]
    fn basic_info_reports_object_identity_without_changing_ownership() -> crate::Result<()> {
        let raw = NonZeroU64::new(hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL.into())
            .ok_or(crate::Error::InvalidResponse)?;
        // SAFETY: the test backend treats this nonzero value as one owner.
        let handle = unsafe { OwnedHandle::<ByteChannelObject>::from_raw_owned(raw) };
        let info = handle.basic_info()?;
        assert_eq!(info.kind, <ByteChannelObject as TypedObject>::KIND);
        assert_eq!(info.koid.get(), raw.get() + 0x1_0000);
        assert_eq!(handle.as_handle_ref().basic_info()?, info);
        Ok(())
    }

    #[test]
    fn basic_info_rejects_reserved_data_and_zero_identity() {
        let valid_kind = hyper_abi::HYPER_NATIVE_OBJECT_EVENT;
        assert_eq!(
            super::decode_basic_info(hyper_abi::HyperNativeObjectBasicInfo {
                koid: 1,
                object_kind: valid_kind,
                reserved: 1,
            }),
            Err(crate::Error::InvalidResponse)
        );
        assert_eq!(
            super::decode_basic_info(hyper_abi::HyperNativeObjectBasicInfo {
                koid: 0,
                object_kind: valid_kind,
                reserved: 0,
            }),
            Err(crate::Error::InvalidResponse)
        );
    }

    #[test]
    fn failed_downcast_returns_the_original_owner() -> crate::Result<()> {
        let raw = NonZeroU64::new(hyper_abi::HYPER_NATIVE_OBJECT_BYTE_CHANNEL.into())
            .ok_or(crate::Error::InvalidResponse)?;
        // SAFETY: the test backend treats this nonzero value as one owner.
        let erased = unsafe { OwnedHandle::<AnyObject>::from_raw_owned(raw) };
        let failure = match erased.downcast::<super::ThreadObject>() {
            Ok(_) => return Err(crate::Error::InvalidResponse),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.error(),
            crate::Error::UnexpectedObjectKind { .. }
        ));
        let recovered = failure.into_handle();
        assert_eq!(recovered.as_handle_ref().raw(), raw);
        recovered.try_close().map_err(|failure| failure.error())?;
        Ok(())
    }

    #[test]
    fn diagnostic_catalogs_cover_known_kinds_and_every_right_bit() {
        for (index, kind) in ObjectKind::KNOWN.iter().copied().enumerate() {
            assert_eq!(ObjectKind::from_name(kind.name()), Some(kind));
            assert_ne!(kind.name(), "unknown");
            assert_ne!(kind.purpose(), "object kind not known to this SDK");
            assert!(!ObjectKind::KNOWN[..index].contains(&kind));
        }
        assert_eq!(ObjectKind::from_name("physcial-device"), None);
        let bits = Rights::known_names()
            .filter_map(Rights::from_name)
            .fold(0, |bits, right| bits | right.bits());
        assert_eq!(bits, hyper_abi::HYPER_NATIVE_RIGHTS_MASK);
        assert_eq!(Rights::known_names().count(), bits.count_ones() as usize);
        assert_eq!(Rights::from_name("wriet"), None);
    }

    #[test]
    fn unknown_object_kind_preserves_numeric_identity() -> crate::Result<()> {
        let future = ObjectKind::from_kernel(u32::MAX)?;
        assert_eq!(future.as_raw(), u32::MAX);
        assert_eq!(future.name(), "unknown");
        assert_eq!(future.purpose(), "object kind not known to this SDK");
        assert!(ObjectKind::from_kernel(0).is_err());
        Ok(())
    }

    #[test]
    fn object_metadata_and_right_names_are_stable() {
        let kind = <super::TaskInspectorObject as TypedObject>::KIND;
        assert_eq!(kind.name(), "task-inspector");
        assert_eq!(kind.purpose(), "task observation");

        let rights = Rights::READ.union(Rights::WRITE).union(Rights::INSPECT);
        let mut names = rights.names();
        assert_eq!(names.next(), Some("inspect"));
        assert_eq!(names.next(), Some("read"));
        assert_eq!(names.next(), Some("write"));
        assert_eq!(names.next(), None);

        let mut names = Rights::CREATE_VIRTUAL_MACHINE.names();
        assert_eq!(names.next(), Some("create-virtual-machine"));
        assert_eq!(names.next(), None);
    }
}
