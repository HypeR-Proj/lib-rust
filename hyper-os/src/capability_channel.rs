// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Transactional capability rendezvous with failure-safe Rust ownership.

use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::num::NonZeroU64;
use core::slice;

use crate::handle::{
    AnyObject, CapabilityChannelObject, HandleRef, ObjectType, OwnedHandle, Rights, RightsOffer,
    TypedObject,
};
use crate::{Error, Result, Status};

const _: () =
    assert!(hyper_abi::HYPER_NATIVE_CAPABILITY_CHANNEL_MAX_MESSAGE_BYTES <= usize::MAX as u64);
const _: () = assert!(hyper_abi::HYPER_NATIVE_CAPABILITY_CHANNEL_MAX_HANDLES <= usize::MAX as u64);
const MAX_MESSAGE_BYTES: usize =
    hyper_abi::HYPER_NATIVE_CAPABILITY_CHANNEL_MAX_MESSAGE_BYTES as usize;
const MAX_CAPABILITIES: usize = hyper_abi::HYPER_NATIVE_CAPABILITY_CHANNEL_MAX_HANDLES as usize;

/// One validated source disposition for a capability rendezvous.
///
/// A MOVE disposition exclusively borrows an `Option<OwnedHandle<T>>`. The
/// option remains `Some` after every rejected send and becomes `None` only
/// after an `OK` result commits the kernel transfer.
pub struct CapabilityDisposition<'source> {
    record: hyper_abi::HyperNativeCapabilityDisposition,
    move_source: Option<&'source mut dyn MoveSource>,
}

impl<'source> CapabilityDisposition<'source> {
    /// Prepares a MOVE while retaining recoverable ownership until commit.
    pub fn move_handle<T: TypedObject>(
        source: &'source mut Option<OwnedHandle<T>>,
        offer: RightsOffer,
    ) -> Result<Self> {
        let owner = source.as_ref().ok_or(Error::MissingHandle)?;
        let _ = validate_source(owner.as_handle_ref(), offer, Rights::TRANSFER)?;
        Ok(Self {
            record: disposition_record(
                owner.as_handle_ref().raw(),
                offer,
                T::KIND.as_raw(),
                hyper_abi::HYPER_NATIVE_CAPABILITY_DISPOSITION_MOVE as u32,
            ),
            move_source: Some(source),
        })
    }

    /// Prepares a DUPLICATE while retaining the source on every outcome.
    pub fn duplicate<T: TypedObject>(
        source: HandleRef<'source, T>,
        offer: RightsOffer,
    ) -> Result<Self> {
        let _ = validate_source(source, offer, Rights::TRANSFER.union(Rights::DUPLICATE))?;
        Ok(Self {
            record: disposition_record(
                source.raw(),
                offer,
                T::KIND.as_raw(),
                hyper_abi::HYPER_NATIVE_CAPABILITY_DISPOSITION_DUPLICATE as u32,
            ),
            move_source: None,
        })
    }

    fn commit(&mut self) {
        if let Some(source) = self.move_source.take() {
            source.commit_move();
        }
    }
}

fn validate_source<T: TypedObject>(
    source: HandleRef<'_, T>,
    offer: RightsOffer,
    required: Rights,
) -> Result<crate::handle::HandleInfo> {
    let info = source.info()?;
    if info.kind != T::KIND {
        return Err(Error::UnexpectedObjectKind {
            expected: T::KIND.as_raw(),
            actual: info.kind.as_raw(),
        });
    }
    if !info.rights.contains(required) {
        return Err(Error::Status(Status::ACCESS_DENIED));
    }
    if let RightsOffer::Exact(offered) = offer
        && !info.rights.contains(offered)
    {
        return Err(Error::Status(Status::ACCESS_DENIED));
    }
    Ok(info)
}

fn disposition_record(
    raw: NonZeroU64,
    offer: RightsOffer,
    expected_kind: u32,
    operation: u32,
) -> hyper_abi::HyperNativeCapabilityDisposition {
    hyper_abi::HyperNativeCapabilityDisposition {
        handle: raw.get(),
        rights: offer.raw(),
        expected_kind,
        operation,
    }
}

/// Type-erased ownership slot retained across a fallible MOVE operation.
///
/// Dynamic dispatch preserves the source's concrete `OwnedHandle` type while
/// Rust itself carries the exclusive borrow and lifetime. No raw-pointer
/// reconstruction is needed at the commit boundary.
trait MoveSource {
    fn commit_move(&mut self);
}

impl<T: ObjectType> MoveSource for Option<OwnedHandle<T>> {
    fn commit_move(&mut self) {
        let Some(owner) = self.take() else {
            ownership_invariant();
        };
        let _ = owner.into_raw();
    }
}

/// One typed destination request and its optional received owner.
pub struct CapabilityReceiveSlot {
    expected_kind: crate::handle::ObjectKind,
    rights: Rights,
    received: Option<OwnedHandle<AnyObject>>,
}

impl CapabilityReceiveSlot {
    /// Declares one exact type-and-rights request.
    #[must_use]
    pub const fn new<T: TypedObject>(rights: Rights) -> Self {
        Self {
            expected_kind: T::KIND,
            rights,
            received: None,
        }
    }

    /// Returns whether this slot currently owns a received capability.
    #[must_use]
    pub const fn is_occupied(&self) -> bool {
        self.received.is_some()
    }

    /// Takes the received owner after checking the requested static type.
    pub fn take<T: TypedObject>(&mut self) -> Result<Option<OwnedHandle<T>>> {
        if self.expected_kind != T::KIND {
            return Err(Error::UnexpectedObjectKind {
                expected: T::KIND.as_raw(),
                actual: self.expected_kind.as_raw(),
            });
        }
        let Some(owner) = self.received.take() else {
            return Ok(None);
        };
        match owner.downcast::<T>() {
            Ok(owner) => Ok(Some(owner)),
            Err(failure) => {
                let (error, owner) = failure.into_parts();
                self.received = Some(owner);
                Err(error)
            }
        }
    }

    fn raw_request(&self) -> Result<hyper_abi::HyperNativeCapabilityReceiveSlot> {
        if self.received.is_some() {
            return Err(Error::OccupiedReceiveSlot);
        }
        Ok(hyper_abi::HyperNativeCapabilityReceiveSlot {
            handle: 0,
            rights: self.rights.bits(),
            expected_kind: self.expected_kind.as_raw(),
            flags: 0,
        })
    }
}

/// Successfully received bytes and capability count.
pub struct CapabilityMessage<'buffer> {
    bytes: &'buffer mut [u8],
    capability_count: usize,
}

impl<'buffer> CapabilityMessage<'buffer> {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    #[must_use]
    pub const fn capability_count(&self) -> usize {
        self.capability_count
    }
}

/// Exclusive ownership of one `CapabilityChannel` endpoint.
pub struct CapabilityChannel {
    handle: OwnedHandle<CapabilityChannelObject>,
}

impl CapabilityChannel {
    /// Restores the safe endpoint API from an exclusively owned typed handle.
    ///
    /// This is the normal entry after receiving a `CapabilityChannelObject`
    /// through a capability rendezvous. Consuming the owner prevents two safe
    /// wrappers from representing the same process-local handle.
    #[must_use]
    pub const fn from_handle(handle: OwnedHandle<CapabilityChannelObject>) -> Self {
        Self { handle }
    }

    /// Borrows this endpoint for typed signal waits.
    #[must_use]
    pub fn as_handle_ref(&self) -> HandleRef<'_, CapabilityChannelObject> {
        self.handle.as_handle_ref()
    }

    /// Creates a connected endpoint pair.
    pub fn create() -> Result<(Self, Self)> {
        let result = raw_ops::create();
        Status::from_raw(result.status).into_result()?;
        // SAFETY: an OK CAPABILITY_CHANNEL_CREATE result transfers ownership
        // of every distinct nonzero output, including malformed output pairs.
        let (first, second) =
            unsafe { crate::handle::adopt_produced_handle_pair([result.value0, result.value1])? };
        Ok((Self::from_handle(first), Self::from_handle(second)))
    }

    /// Attempts a single FIFO rendezvous.
    ///
    /// Every rejected result preserves all MOVE sources. `OK` atomically
    /// commits all MOVE dispositions before this function returns.
    pub fn try_send(
        &self,
        bytes: &[u8],
        dispositions: &mut [CapabilityDisposition<'_>],
    ) -> Result<()> {
        if bytes.len() > MAX_MESSAGE_BYTES || dispositions.len() > MAX_CAPABILITIES {
            return Err(Error::MessageTooLarge {
                bytes: bytes.len() as u64,
                handles: dispositions.len() as u64,
            });
        }
        for (index, disposition) in dispositions.iter().enumerate() {
            if dispositions[..index]
                .iter()
                .any(|present| present.record.handle == disposition.record.handle)
            {
                return Err(Error::InvalidCapabilityDisposition);
            }
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(dispositions.len())
            .map_err(|_| Error::Status(Status::NO_MEMORY))?;
        records.extend(dispositions.iter().map(|disposition| disposition.record));
        let status = raw_ops::try_send(self.handle.as_handle_ref(), bytes, &records);
        Status::from_raw(status).into_result()?;
        for disposition in dispositions {
            disposition.commit();
        }
        Ok(())
    }

    /// Waits for and receives one typed rendezvous.
    ///
    /// Only an `OK` result initializes the returned byte slice or installs
    /// owners into `slots`. After any error, callers must continue treating
    /// the entire byte buffer as uninitialized.
    pub fn receive<'buffer>(
        &self,
        deadline: u64,
        bytes: &'buffer mut [MaybeUninit<u8>],
        slots: &mut [CapabilityReceiveSlot],
    ) -> Result<CapabilityMessage<'buffer>> {
        let byte_capacity = bytes.len().min(MAX_MESSAGE_BYTES);
        if slots.len() > MAX_CAPABILITIES {
            return Err(Error::MessageTooLarge {
                bytes: bytes.len() as u64,
                handles: slots.len() as u64,
            });
        }
        let mut raw_slots = Vec::new();
        raw_slots
            .try_reserve_exact(slots.len())
            .map_err(|_| Error::Status(Status::NO_MEMORY))?;
        for slot in slots.iter() {
            raw_slots.push(slot.raw_request()?);
        }
        // Allocate all owner storage before the syscall can commit a transfer.
        // Successful output must be adopted even when later validation fails.
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(slots.len())
            .map_err(|_| Error::Status(Status::NO_MEMORY))?;
        owners.resize_with(slots.len(), || None);
        let endpoint = self.handle.as_handle_ref();
        let result = raw_ops::receive(
            endpoint,
            deadline,
            bytes
                .get_mut(..byte_capacity)
                .ok_or(Error::InvalidResponse)?,
            raw_slots
                .get_mut(..slots.len())
                .ok_or(Error::InvalidResponse)?,
        );
        let status = Status::from_raw(result.status);
        if status != Status::OK {
            return if status == Status::BUFFER_TOO_SMALL {
                Err(Error::MessageTooLarge {
                    bytes: result.value0,
                    handles: result.value1,
                })
            } else {
                Err(Error::Status(status))
            };
        }
        // Take ownership of every distinct nonzero successful output before
        // any fallible count conversion or validation can return.
        collect_successful_owners(&raw_slots, endpoint.raw(), &mut owners)?;
        let actual_bytes = usize::try_from(result.value0).map_err(|_| Error::InvalidResponse)?;
        let actual_capabilities =
            usize::try_from(result.value1).map_err(|_| Error::InvalidResponse)?;
        if actual_bytes > byte_capacity || actual_capabilities > slots.len() {
            return Err(Error::InvalidResponse);
        }
        validate_received_slots(&raw_slots, slots, actual_capabilities, &owners)?;
        for (slot, owner) in slots.iter_mut().zip(owners.iter_mut()) {
            slot.received = owner.take();
        }
        // SAFETY: `OK` initializes exactly the first `actual_bytes` bytes, and
        // the validated result keeps that count within the original buffer.
        let initialized =
            unsafe { slice::from_raw_parts_mut(bytes.as_mut_ptr().cast::<u8>(), actual_bytes) };
        Ok(CapabilityMessage {
            bytes: initialized,
            capability_count: actual_capabilities,
        })
    }

    #[must_use]
    pub fn into_handle(self) -> OwnedHandle<CapabilityChannelObject> {
        self.handle
    }
}

fn collect_successful_owners(
    raw_slots: &[hyper_abi::HyperNativeCapabilityReceiveSlot],
    endpoint: NonZeroU64,
    owners: &mut [Option<OwnedHandle<AnyObject>>],
) -> Result<()> {
    let mut repeated = false;
    for (index, slot) in raw_slots.iter().enumerate() {
        let Some(raw) = NonZeroU64::new(slot.handle) else {
            continue;
        };
        if raw_slots[..index]
            .iter()
            .any(|present| present.handle == raw.get())
        {
            repeated = true;
            continue;
        }
        // SAFETY: `OK` designates each distinct nonzero output value as one
        // newly installed owner. A malformed alias of the retained endpoint is
        // rejected before constructing or closing an owner for that value.
        owners[index] = Some(unsafe {
            crate::handle::adopt_produced_handle_excluding(raw.get(), &[endpoint])?
        });
    }
    if repeated {
        Err(Error::InvalidResponse)
    } else {
        Ok(())
    }
}

fn validate_received_slots(
    raw_slots: &[hyper_abi::HyperNativeCapabilityReceiveSlot],
    slots: &[CapabilityReceiveSlot],
    actual: usize,
    owners: &[Option<OwnedHandle<AnyObject>>],
) -> Result<()> {
    for (index, (raw, requested)) in raw_slots.iter().zip(slots).enumerate() {
        if (index < actual) != (raw.handle != 0) {
            return Err(Error::InvalidResponse);
        }
        if raw.rights != requested.rights.bits()
            || raw.expected_kind != requested.expected_kind.as_raw()
            || raw.flags != 0
        {
            return Err(Error::InvalidResponse);
        }
    }
    for index in 0..actual {
        let requested = slots.get(index).ok_or(Error::InvalidResponse)?;
        let owner = owners
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::InvalidResponse)?;
        let info = owner.info()?;
        if info.kind != requested.expected_kind || info.rights != requested.rights {
            return Err(Error::InvalidResponse);
        }
    }
    Ok(())
}

#[cfg(not(test))]
mod raw_ops {
    use core::mem::MaybeUninit;

    use super::{CapabilityChannelObject, HandleRef};

    pub(super) fn create() -> hyper_sys::CallResult {
        // SAFETY: this safe layer validates and assumes ownership of both
        // successful results before exposing them.
        unsafe { hyper_sys::capability_channel_create() }
    }

    pub(super) fn try_send(
        endpoint: HandleRef<'_, CapabilityChannelObject>,
        bytes: &[u8],
        dispositions: &[hyper_abi::HyperNativeCapabilityDisposition],
    ) -> hyper_abi::HyperNativeStatus {
        // SAFETY: the endpoint borrow and both slices remain live throughout
        // this non-retaining syscall; the caller owns commit bookkeeping.
        unsafe {
            hyper_sys::capability_channel_try_send(
                endpoint.raw().get(),
                bytes.as_ptr(),
                bytes.len(),
                dispositions.as_ptr(),
                dispositions.len(),
            )
        }
    }

    pub(super) fn receive(
        endpoint: HandleRef<'_, CapabilityChannelObject>,
        deadline: u64,
        bytes: &mut [MaybeUninit<u8>],
        slots: &mut [hyper_abi::HyperNativeCapabilityReceiveSlot],
    ) -> hyper_sys::CallResult {
        // SAFETY: both output slices are uniquely borrowed and the initialized
        // slot requests satisfy the raw receive contract.
        unsafe {
            hyper_sys::capability_channel_receive(
                endpoint.raw().get(),
                deadline,
                bytes.as_mut_ptr().cast::<u8>(),
                bytes.len(),
                slots.as_mut_ptr(),
                slots.len(),
            )
        }
    }
}

#[cfg(test)]
mod raw_ops {
    use core::mem::MaybeUninit;

    use super::{CapabilityChannelObject, HandleRef};

    pub(super) fn create() -> hyper_sys::CallResult {
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_OK,
            value0: hyper_abi::HYPER_NATIVE_OBJECT_CAPABILITY_CHANNEL.into(),
            value1: u64::from(hyper_abi::HYPER_NATIVE_OBJECT_CAPABILITY_CHANNEL) + 256,
        }
    }

    pub(super) fn try_send(
        _endpoint: HandleRef<'_, CapabilityChannelObject>,
        bytes: &[u8],
        _dispositions: &[hyper_abi::HyperNativeCapabilityDisposition],
    ) -> hyper_abi::HyperNativeStatus {
        if bytes == b"reject" {
            hyper_abi::HYPER_NATIVE_STATUS_WOULD_BLOCK
        } else {
            hyper_abi::HYPER_NATIVE_STATUS_OK
        }
    }

    pub(super) fn receive(
        _endpoint: HandleRef<'_, CapabilityChannelObject>,
        deadline: u64,
        bytes: &mut [MaybeUninit<u8>],
        slots: &mut [hyper_abi::HyperNativeCapabilityReceiveSlot],
    ) -> hyper_sys::CallResult {
        if deadline == 2 {
            if let Some(byte) = bytes.first_mut() {
                byte.write(0xff);
            }
            if let Some(slot) = slots.first_mut() {
                slot.handle = u64::MAX;
            }
            return hyper_sys::CallResult {
                status: hyper_abi::HYPER_NATIVE_STATUS_FAULT,
                value0: 0,
                value1: 0,
            };
        }
        let payload = b"rx";
        for (output, value) in bytes.iter_mut().zip(payload) {
            output.write(*value);
        }
        if deadline == 3 {
            if let Some(slot) = slots.first_mut() {
                slot.handle = crate::handle::TEST_SENTINEL_HANDLE;
            }
        } else if deadline == 5 {
            for (index, slot) in slots.iter_mut().enumerate() {
                slot.handle = u64::from(slot.expected_kind) + (index as u64 + 4) * 256;
            }
        } else if deadline == 4 {
            for slot in slots.iter_mut() {
                slot.handle = u64::from(slot.expected_kind) + 512;
            }
        } else if deadline != 1 {
            for slot in slots.iter_mut() {
                slot.handle = u64::from(slot.expected_kind);
            }
        }
        hyper_sys::CallResult {
            status: hyper_abi::HYPER_NATIVE_STATUS_OK,
            value0: payload.len() as u64,
            value1: if deadline == 3 {
                u64::MAX
            } else {
                slots.len() as u64
            },
        }
    }
}

#[cold]
fn ownership_invariant() -> ! {
    #[cfg(not(test))]
    {
        // SAFETY: safe callers cannot reach this SDK ownership invariant; a
        // terminal process exit avoids manufacturing a duplicate owner.
        unsafe { hyper_sys::process_exit(hyper_abi::HYPER_NATIVE_STATUS_INTERNAL) }
    }
    #[cfg(test)]
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;
    use core::num::NonZeroU64;

    use super::{CapabilityChannel, CapabilityDisposition, CapabilityReceiveSlot};
    use crate::handle::{CapabilityChannelObject, EventObject, OwnedHandle, Rights, RightsOffer};
    use crate::{Error, Status};

    fn event() -> crate::Result<OwnedHandle<EventObject>> {
        let raw = NonZeroU64::new(hyper_abi::HYPER_NATIVE_OBJECT_EVENT.into())
            .ok_or(Error::InvalidResponse)?;
        // SAFETY: the test backend assigns this value to one unique owner.
        Ok(unsafe { OwnedHandle::from_raw_owned(raw) })
    }

    #[test]
    fn move_is_disarmed_only_after_successful_commit() -> crate::Result<()> {
        let (sender, _receiver) = CapabilityChannel::create()?;
        let mut source = Some(event()?);
        {
            let move_disposition = CapabilityDisposition::move_handle(
                &mut source,
                RightsOffer::Exact(Rights::TRANSFER),
            )?;
            assert!(matches!(
                sender.try_send(b"reject", &mut [move_disposition]),
                Err(Error::Status(status)) if status == Status::WOULD_BLOCK
            ));
        }
        assert!(source.is_some());
        {
            let move_disposition = CapabilityDisposition::move_handle(
                &mut source,
                RightsOffer::Exact(Rights::TRANSFER),
            )?;
            sender.try_send(b"commit", &mut [move_disposition])?;
        }
        assert!(source.is_none());
        Ok(())
    }

    #[test]
    fn full_inventory_moves_atomically_and_receive_has_no_inline_owner_array() -> crate::Result<()>
    {
        let (sender, receiver) = CapabilityChannel::create()?;
        let rights =
            Rights::from_bits(hyper_abi::HYPER_NATIVE_RIGHTS_MASK).ok_or(Error::InvalidResponse)?;
        let mut slots: alloc::vec::Vec<_> = (0..super::MAX_CAPABILITIES)
            .map(|_| CapabilityReceiveSlot::new::<EventObject>(rights))
            .collect();
        let mut bytes = [MaybeUninit::uninit(); 8];
        let message = receiver.receive(5, &mut bytes, &mut slots)?;
        assert_eq!(message.capability_count(), 64);
        let mut owners: alloc::vec::Vec<_> = slots
            .iter_mut()
            .map(|slot| slot.take::<EventObject>())
            .collect::<crate::Result<_>>()?;
        for payload in [b"reject".as_slice(), b"commit".as_slice()] {
            let mut offers: alloc::vec::Vec<_> = owners
                .iter_mut()
                .map(|owner| {
                    CapabilityDisposition::move_handle(owner, RightsOffer::Exact(Rights::TRANSFER))
                })
                .collect::<crate::Result<_>>()?;
            let result = sender.try_send(payload, &mut offers);
            drop(offers);
            if payload == b"reject" {
                assert!(matches!(result, Err(Error::Status(Status::WOULD_BLOCK))));
                assert!(owners.iter().all(Option::is_some));
            } else {
                result?;
                assert!(owners.iter().all(Option::is_none));
            }
        }
        Ok(())
    }

    #[test]
    fn receive_publishes_only_validated_typed_owners() -> crate::Result<()> {
        let (_sender, receiver) = CapabilityChannel::create()?;
        let mut bytes = [MaybeUninit::uninit(); 8];
        let mut slots = [CapabilityReceiveSlot::new::<EventObject>(
            Rights::from_bits(hyper_abi::HYPER_NATIVE_RIGHTS_MASK).ok_or(Error::InvalidResponse)?,
        )];
        let message = receiver.receive(u64::MAX, &mut bytes, &mut slots)?;
        assert_eq!(message.bytes(), b"rx");
        assert_eq!(message.capability_count(), 1);
        assert!(slots[0].take::<EventObject>()?.is_some());
        Ok(())
    }

    #[test]
    fn received_endpoint_reenters_the_safe_channel_api() -> crate::Result<()> {
        let (_sender, receiver) = CapabilityChannel::create()?;
        let mut bytes = [MaybeUninit::uninit(); 8];
        let rights =
            Rights::from_bits(hyper_abi::HYPER_NATIVE_RIGHTS_MASK).ok_or(Error::InvalidResponse)?;
        let mut slots = [CapabilityReceiveSlot::new::<CapabilityChannelObject>(
            rights,
        )];
        let message = receiver.receive(4, &mut bytes, &mut slots)?;
        assert_eq!(message.capability_count(), 1);
        let endpoint = slots[0]
            .take::<CapabilityChannelObject>()?
            .ok_or(Error::InvalidResponse)?;
        let endpoint = CapabilityChannel::from_handle(endpoint);
        endpoint.try_send(b"delegated", &mut [])?;
        drop(endpoint.into_handle());
        Ok(())
    }

    #[test]
    fn malformed_success_and_fault_publish_no_safe_owner() -> crate::Result<()> {
        let (_sender, receiver) = CapabilityChannel::create()?;
        let rights =
            Rights::from_bits(hyper_abi::HYPER_NATIVE_RIGHTS_MASK).ok_or(Error::InvalidResponse)?;
        let mut bytes = [MaybeUninit::uninit(); 8];
        let mut slots = [CapabilityReceiveSlot::new::<EventObject>(rights)];
        assert!(matches!(
            receiver.receive(1, &mut bytes, &mut slots),
            Err(Error::InvalidResponse)
        ));
        assert!(!slots[0].is_occupied());
        assert!(matches!(
            receiver.receive(2, &mut bytes, &mut slots),
            Err(Error::Status(status)) if status == Status::FAULT
        ));
        assert!(!slots[0].is_occupied());
        Ok(())
    }

    #[test]
    fn malformed_success_closes_unpublished_output_owners() -> crate::Result<()> {
        let (_sender, receiver) = CapabilityChannel::create()?;
        let rights =
            Rights::from_bits(hyper_abi::HYPER_NATIVE_RIGHTS_MASK).ok_or(Error::InvalidResponse)?;
        let mut bytes = [MaybeUninit::uninit(); 8];
        let mut slots = [CapabilityReceiveSlot::new::<EventObject>(rights)];
        let closed_before = crate::handle::test_sentinel_close_count();
        assert!(matches!(
            receiver.receive(3, &mut bytes, &mut slots),
            Err(Error::InvalidResponse)
        ));
        assert_eq!(
            crate::handle::test_sentinel_close_count(),
            closed_before + 1
        );
        assert!(!slots[0].is_occupied());
        Ok(())
    }
}
