// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Typed, bounded multi-object waits for Native applications.

use core::marker::PhantomData;

use crate::handle::{
    ByteChannelObject, CapabilityChannelObject, HandleRef, ObjectType, ProcessObject, ThreadObject,
    VirtualCpuObject,
};
use crate::{Error, Result, Status};

const _: () = assert!(hyper_abi::HYPER_NATIVE_OBJECT_WAIT_MANY_MAX_ITEMS <= usize::MAX as u64);

/// Maximum number of objects accepted by one multi-object wait.
pub const MAX_ITEMS: usize = hyper_abi::HYPER_NATIVE_OBJECT_WAIT_MANY_MAX_ITEMS as usize;

/// A signal mask whose object kind is carried by the type system.
#[derive(Debug, Eq, PartialEq)]
pub struct ObjectSignals<T: ObjectType> {
    bits: u64,
    _object: PhantomData<fn() -> T>,
}

impl<T: ObjectType> Clone for ObjectSignals<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ObjectType> Copy for ObjectSignals<T> {}

impl<T: ObjectType> ObjectSignals<T> {
    const fn from_trusted_bits(bits: u64) -> Self {
        Self {
            bits,
            _object: PhantomData,
        }
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self::from_trusted_bits(self.bits | other.bits)
    }

    /// Returns whether any bit in this typed mask was observed.
    #[must_use]
    pub const fn is_present_in(self, observed: u64) -> bool {
        observed & self.bits != 0
    }
}

impl ObjectSignals<crate::handle::VirtualSerialObject> {
    pub const READABLE: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_VIRTUAL_SERIAL_READABLE);
    pub const WRITABLE: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_VIRTUAL_SERIAL_WRITABLE);
    pub const PEER_CLOSED: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_VIRTUAL_SERIAL_PEER_CLOSED);
}

impl ObjectSignals<ByteChannelObject> {
    pub const READABLE: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_READABLE);
    pub const WRITABLE: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_WRITABLE);
    pub const PEER_CLOSED: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_PEER_CLOSED);
}

impl ObjectSignals<crate::handle::GuestMailboxObject> {
    pub const READABLE: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_GUEST_MAILBOX_READABLE);
    pub const WRITABLE: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_GUEST_MAILBOX_WRITABLE);
    pub const PEER_CLOSED: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_GUEST_MAILBOX_PEER_CLOSED);
}

impl ObjectSignals<CapabilityChannelObject> {
    pub const PEER_RECEIVING: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_CAPABILITY_CHANNEL_PEER_RECEIVING);
    pub const PEER_CLOSED: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_CAPABILITY_CHANNEL_PEER_CLOSED);
}

impl ObjectSignals<ProcessObject> {
    pub const TERMINATED: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_PROCESS_TERMINATED);
}

impl ObjectSignals<ThreadObject> {
    pub const TERMINATED: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_THREAD_TERMINATED);
}

impl ObjectSignals<crate::handle::VirtualMachineObject> {
    pub const TERMINATED: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_VIRTUAL_MACHINE_TERMINATED);
    pub const POWER_REQUEST: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_VIRTUAL_MACHINE_POWER_REQUEST);
    pub const VCPU_TERMINATED: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_VIRTUAL_MACHINE_VCPU_TERMINATED);
}

impl ObjectSignals<VirtualCpuObject> {
    pub const MMIO_REQUEST: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_VIRTUAL_CPU_MMIO_REQUEST);
    pub const TERMINATED: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_VIRTUAL_CPU_TERMINATED);
}

/// One ordered borrowed handle and its typed signal mask.
///
/// The lifetime prevents the owning handle from being consumed while the
/// syscall borrows its process-local value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WaitItem<'owner> {
    handle: u64,
    signals: u64,
    _owner: PhantomData<HandleRef<'owner>>,
}

const _: () = assert!(
    core::mem::size_of::<WaitItem<'static>>()
        == core::mem::size_of::<hyper_abi::HyperNativeObjectWaitItem>()
);
const _: () = assert!(
    core::mem::align_of::<WaitItem<'static>>()
        == core::mem::align_of::<hyper_abi::HyperNativeObjectWaitItem>()
);

impl<'owner> WaitItem<'owner> {
    #[must_use]
    pub fn new<T: ObjectType>(handle: HandleRef<'owner, T>, signals: ObjectSignals<T>) -> Self {
        Self {
            handle: handle.raw().get(),
            signals: signals.bits,
            _owner: PhantomData,
        }
    }
}

/// The ordered item selected by a successful multi-object wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitObservation {
    pub index: usize,
    pub observed: u64,
}

/// Blocks until one requested level is present, the deadline expires, or the
/// calling Thread is cancelled.
/// Readiness is an observation, not a reservation. Multiplexed callers must
/// use nonblocking operations after waking and retry the full wait set on
/// `WOULD_BLOCK`; blocking on one observed source can stall all other sources.
pub fn wait_many(items: &[WaitItem<'_>], deadline: u64) -> Result<WaitObservation> {
    if items.is_empty() || items.len() > MAX_ITEMS {
        return Err(Error::InvalidWaitSet);
    }
    // SAFETY: `WaitItem` has the asserted ABI layout, every item retains a
    // borrow of its owner, and the slice remains readable for the whole call.
    let result = unsafe {
        hyper_sys::object_wait_many(
            items
                .as_ptr()
                .cast::<hyper_abi::HyperNativeObjectWaitItem>(),
            items.len(),
            deadline,
        )
    };
    Status::from_raw(result.status).into_result()?;
    let index = usize::try_from(result.value0).map_err(|_| Error::InvalidResponse)?;
    if index >= items.len() || result.value1 == 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(WaitObservation {
        index,
        observed: result.value1,
    })
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use super::{ObjectSignals, WaitItem};
    use crate::handle::{ByteChannelObject, OwnedHandle};

    #[test]
    fn wait_item_preserves_handle_and_signal_bits() -> crate::Result<()> {
        let raw = NonZeroU64::new(0x100_0001).ok_or(crate::Error::InvalidResponse)?;
        // SAFETY: the test creates one synthetic exclusive SDK owner.
        let owner = unsafe { OwnedHandle::<ByteChannelObject>::from_raw_owned(raw) };
        let item = WaitItem::new(
            owner.as_handle_ref(),
            ObjectSignals::<ByteChannelObject>::READABLE
                .union(ObjectSignals::<ByteChannelObject>::PEER_CLOSED),
        );
        assert_eq!(item.handle, raw.get());
        assert_eq!(
            item.signals,
            hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_READABLE
                | hyper_abi::HYPER_NATIVE_SIGNAL_BYTE_CHANNEL_PEER_CLOSED
        );
        Ok(())
    }
}

/// Non-repeating identifier returned by a persistent `WaitSet` registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RegistrationId(core::num::NonZeroU64);

impl RegistrationId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// One consumed notification. Rearm its registration to observe another level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Notification {
    pub registration: RegistrationId,
    pub signals: u64,
    /// Source signal-state observation sequence.
    pub sequence: u64,
}

/// Persistent, bounded subscriptions to Native object signals.
///
/// Registrations retain source object lifetime, independently of source handle
/// closure. Closing the set unregisters them. Sets cannot subscribe to sets or
/// be transferred to another process. Ready notifications are one-shot.
pub struct WaitSet {
    handle: crate::OwnedHandle<crate::handle::WaitSetObject>,
}

impl WaitSet {
    /// Restores operations from an owned process-local `WaitSet` capability.
    pub const fn from_handle(handle: crate::OwnedHandle<crate::handle::WaitSetObject>) -> Self {
        Self { handle }
    }

    /// Borrows the capability for inspection or rights attenuation.
    pub fn as_handle_ref(&self) -> HandleRef<'_, crate::handle::WaitSetObject> {
        self.handle.as_handle_ref()
    }

    pub fn into_handle(self) -> crate::OwnedHandle<crate::handle::WaitSetObject> {
        self.handle
    }

    pub fn new(capacity: usize) -> Result<Self> {
        // SAFETY: creation has no borrowed handles or user pointers.
        let result = unsafe { hyper_sys::wait_set_create(capacity) };
        Status::from_raw(result.status).into_result()?;
        if result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        // SAFETY: successful creation publishes one uniquely owned handle.
        let handle = unsafe { crate::handle::adopt_produced_handle_excluding(result.value0, &[])? };
        Ok(Self { handle })
    }

    pub fn add<T: ObjectType>(
        &self,
        source: HandleRef<'_, T>,
        signals: ObjectSignals<T>,
    ) -> Result<RegistrationId> {
        // SAFETY: both borrows pin their handles for the call.
        let result = unsafe {
            hyper_sys::wait_set_add(
                self.handle.as_handle_ref().raw().get(),
                source.raw().get(),
                signals.bits,
            )
        };
        Status::from_raw(result.status).into_result()?;
        if result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        core::num::NonZeroU64::new(result.value0)
            .map(RegistrationId)
            .ok_or(Error::InvalidResponse)
    }

    /// Rearms a consumed, disarmed registration. A pending event returns BUSY.
    pub fn rearm(&self, registration: RegistrationId) -> Result<()> {
        // SAFETY: the owned set remains live throughout this operation.
        let result = unsafe {
            hyper_sys::wait_set_rearm(self.handle.as_handle_ref().raw().get(), registration.get())
        };
        Status::from_raw(result.status).into_result()
    }

    /// Cancels a registration and removes its queued notification, if any.
    pub fn remove(&self, registration: RegistrationId) -> Result<()> {
        // SAFETY: the owned set remains live throughout this operation.
        let result = unsafe {
            hyper_sys::wait_set_remove(self.handle.as_handle_ref().raw().get(), registration.get())
        };
        Status::from_raw(result.status).into_result()
    }

    /// Consumes one event, waiting until an absolute monotonic deadline.
    pub fn wait(&self, deadline: u64) -> Result<Notification> {
        let mut record = [0u8; 24];
        // SAFETY: the owner pins the set and record is writable for the entire call.
        let result = unsafe {
            hyper_sys::wait_set_wait(
                self.handle.as_handle_ref().raw().get(),
                deadline,
                record.as_mut_ptr(),
                record.len(),
            )
        };
        Status::from_raw(result.status).into_result()?;
        let decode = |start: usize| -> u64 {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(&record[start..start + 8]);
            u64::from_le_bytes(bytes)
        };
        let registration = core::num::NonZeroU64::new(decode(0))
            .map(RegistrationId)
            .ok_or(Error::InvalidResponse)?;
        let signals = decode(8);
        if result.value0 != 0 || result.value1 != 0 || signals == 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(Notification {
            registration,
            signals,
            sequence: decode(16),
        })
    }
}

impl ObjectSignals<crate::handle::WaitSetObject> {
    pub const READABLE: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_WAIT_SET_READABLE);
}

impl ObjectSignals<crate::handle::GuestNotificationObject> {
    /// The backend or frontend VM retired. Queue processing cannot be resumed.
    pub const PEER_CLOSED: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_GUEST_NOTIFICATION_PEER_CLOSED);
}

impl ObjectSignals<crate::handle::PhysicalDeviceObject> {
    /// A newly delivered masked physical IRQ awaits userspace notification handling.
    /// Completing with asserted=true consumes readiness while retaining its sequence.
    pub const READABLE: Self =
        Self::from_trusted_bits(hyper_abi::HYPER_NATIVE_SIGNAL_PHYSICAL_DEVICE_READABLE);
}
