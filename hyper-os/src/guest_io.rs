// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Guest control mailboxes and direct cross-VM queue notification bindings.

use crate::handle::{
    AnyObject, GuestMailboxObject, GuestNotificationObject, HandleRef, OwnedHandle, Rights,
    TypedObject, VirtualMachineObject,
};
use crate::{Error, Result, Status};
use core::num::NonZeroU64;

pub const MAX_MESSAGE_BYTES: usize =
    hyper_abi::HYPER_NATIVE_GUEST_MAILBOX_MAX_MESSAGE_BYTES as usize;

pub struct Mailbox {
    handle: OwnedHandle<GuestMailboxObject>,
}
impl Mailbox {
    pub fn create(
        machine: HandleRef<'_, VirtualMachineObject>,
        base: u64,
        irq: u32,
    ) -> Result<Self> {
        // SAFETY: The machine stays borrowed; successful creation transfers one handle.
        let result = unsafe { hyper_sys::guest_mailbox_create(machine.raw().get(), base, irq) };
        Ok(Self {
            handle: adopt_created(
                result,
                Rights::TRANSFER
                    .union(Rights::INSPECT)
                    .union(Rights::READ)
                    .union(Rights::WRITE)
                    .union(Rights::WAIT),
                &[machine.raw()],
            )?,
        })
    }
    pub fn from_handle(handle: OwnedHandle<GuestMailboxObject>) -> Self {
        Self { handle }
    }
    pub fn into_handle(self) -> OwnedHandle<GuestMailboxObject> {
        self.handle
    }
    pub fn as_handle_ref(&self) -> HandleRef<'_, GuestMailboxObject> {
        self.handle.as_handle_ref()
    }
    pub fn send(&self, message: &[u8]) -> Result<()> {
        if message.is_empty() {
            return Err(Error::Status(Status::INVALID_ARGUMENT));
        }
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(Error::MessageTooLarge {
                bytes: message.len() as u64,
                handles: 0,
            });
        }
        // SAFETY: The borrowed message remains readable and is not retained.
        let result = unsafe {
            hyper_sys::guest_mailbox_send(
                self.handle.as_handle_ref().raw().get(),
                message.as_ptr(),
                message.len(),
            )
        };
        Status::from_raw(result.status).into_result()
    }
    /// Nonblocking receive. `WOULD_BLOCK` is observed through the handle's wait
    /// signals; a failed copy leaves the message available to a later call.
    pub fn receive(&self, destination: &mut [u8]) -> Result<usize> {
        let capacity = destination.len().min(MAX_MESSAGE_BYTES);
        // SAFETY: The destination is exclusively writable for the admitted capacity.
        let result = unsafe {
            hyper_sys::guest_mailbox_receive(
                self.handle.as_handle_ref().raw().get(),
                destination.as_mut_ptr(),
                capacity,
            )
        };
        Status::from_raw(result.status).into_result()?;
        let length = usize::try_from(result.value0).map_err(|_| Error::InvalidResponse)?;
        if result.value1 != 0 || length > capacity {
            return Err(Error::InvalidResponse);
        }
        Ok(length)
    }
}

pub struct Notification {
    handle: OwnedHandle<GuestNotificationObject>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Operation {
    Disable = 0,
    Enable = 1,
    RaiseConfigurationInterrupt = 2,
    /// Permanently withdraw both routes after backend DMA quiescence.
    Disconnect = hyper_abi::HYPER_NATIVE_GUEST_NOTIFICATION_DISCONNECT as u32,
}
impl Notification {
    pub fn from_handle(handle: OwnedHandle<GuestNotificationObject>) -> Self {
        Self { handle }
    }
    pub fn into_handle(self) -> OwnedHandle<GuestNotificationObject> {
        self.handle
    }
    /// Install the frontend route before its first vCPU start. The backend may
    /// already be running; both routes remain confined to the platform I/O
    /// aperture and publication is serialized with either VM stopping.
    pub fn create(
        frontend: HandleRef<'_, VirtualMachineObject>,
        backend: HandleRef<'_, VirtualMachineObject>,
        frontend_base: u64,
        backend_base: u64,
        frontend_irq: u32,
        backend_irq: u32,
    ) -> Result<Self> {
        // SAFETY: Both machine handles remain borrowed through the scalar call.
        let result = unsafe {
            hyper_sys::guest_notification_create(
                frontend.raw().get(),
                backend.raw().get(),
                frontend_base,
                backend_base,
                frontend_irq,
                backend_irq,
            )
        };
        Ok(Self {
            handle: adopt_created(
                result,
                Rights::TRANSFER
                    .union(Rights::INSPECT)
                    .union(Rights::WRITE)
                    .union(Rights::WAIT),
                &[frontend.raw(), backend.raw()],
            )?,
        })
    }
    pub fn as_handle_ref(&self) -> HandleRef<'_, GuestNotificationObject> {
        self.handle.as_handle_ref()
    }
    /// Permanently detach both MMIO routes after backend DMA quiescence.
    pub fn disconnect(&self) -> Result<()> {
        self.control(Operation::Disconnect).map(|_| ())
    }

    pub fn control(&self, operation: Operation) -> Result<u32> {
        // SAFETY: The handle is borrowed and the typed operation is ABI-valid.
        let result = unsafe {
            hyper_sys::guest_notification_control(
                self.handle.as_handle_ref().raw().get(),
                operation as u32,
            )
        };
        Status::from_raw(result.status).into_result()?;
        let epoch = u32::try_from(result.value0).map_err(|_| Error::InvalidResponse)?;
        if epoch == 0 || result.value1 != 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(epoch)
    }
}

pub(crate) fn adopt_created<T: TypedObject>(
    result: hyper_sys::CallResult,
    rights: Rights,
    live: &[NonZeroU64],
) -> Result<OwnedHandle<T>> {
    Status::from_raw(result.status).into_result()?;
    // SAFETY: Callers pass one successful, unadopted creation result and retain
    // every borrowed input. Even malformed outputs are owned before validation.
    let owner = unsafe {
        crate::handle::adopt_produced_handle_excluding::<AnyObject>(result.value0, live)?
    };
    if result.value1 != 0 || owner.info()?.rights != rights {
        return Err(Error::InvalidResponse);
    }
    owner.downcast::<T>().map_err(|failure| failure.error())
}
