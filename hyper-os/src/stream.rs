// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Request-sized byte streams. Character and terminal policy belong to servers.
//!
//! Every connection has one response consumer. Inherit a connector, never an
//! established connection, when starting another process.

use core::mem::MaybeUninit;

use crate::capability_channel::{CapabilityChannel, CapabilityDisposition, CapabilityReceiveSlot};
use crate::handle::{
    ByteChannelObject, CapabilityChannelObject, HandleRef, OwnedHandle, Rights, RightsOffer,
};
use crate::startup::StartupPurpose;
use crate::wait::{ObjectSignals, WaitItem, wait_many};
use crate::{Error, Result, Status};

pub const STANDARD_INPUT: StartupPurpose<CapabilityChannelObject> =
    StartupPurpose::new(0x8003_0011);
pub const STANDARD_OUTPUT: StartupPurpose<CapabilityChannelObject> =
    StartupPurpose::new(0x8003_0012);
pub const STANDARD_ERROR: StartupPurpose<CapabilityChannelObject> =
    StartupPurpose::new(0x8003_0013);
pub const CONNECTOR_RIGHTS: Rights = Rights::WAIT
    .union(Rights::WRITE)
    .union(Rights::DUPLICATE)
    .union(Rights::TRANSFER);
pub const SESSION_RIGHTS: Rights = Rights::WAIT.union(Rights::READ).union(Rights::WRITE);
pub const HEADER_BYTES: usize = 32;
pub const MAX_DATA: usize = 4096;
pub const MAX_FRAME: usize = HEADER_BYTES + MAX_DATA;
pub const MAGIC: u32 = 0x5354_524d;
pub const OPEN_MAGIC: [u8; 8] = *b"STRM\x01\0\0\0";
pub const ACCESS_READ: u64 = 1;
pub const ACCESS_WRITE: u64 = 2;
pub const INTERACTIVE: u64 = 1;
pub const READ: u16 = 1;
pub const CANCEL: u16 = 2;
pub const WRITE: u16 = 3;
pub const FENCE: u16 = 4;
pub const INFO: u16 = 5;
pub const DISCARD_INPUT: u16 = 6;
pub const RESPONSE: u16 = 0x8000;
pub const DATA: u16 = 0;
pub const EOF: u16 = 1;
pub const CANCELLED: u16 = 2;
pub const TIMED_OUT: u16 = 3;
pub const CONFIGURATION_CHANGED: u16 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub operation: u16,
    pub flags: u16,
    pub id: u64,
    pub value: u64,
    pub extra: u64,
}

impl Header {
    pub const fn request(operation: u16, id: u64, value: u64, extra: u64) -> Self {
        Self {
            operation,
            flags: 0,
            id,
            value,
            extra,
        }
    }

    pub const fn response(operation: u16, id: u64, flags: u16, value: u64, status: i64) -> Self {
        Self {
            operation: operation | RESPONSE,
            flags,
            id,
            value,
            extra: status as u64,
        }
    }

    pub fn encode(self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[..4].copy_from_slice(&MAGIC.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.operation.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.flags.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.id.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.value.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.extra.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let header = bytes.get(..HEADER_BYTES).ok_or(Error::InvalidResponse)?;
        let word = |offset| {
            let mut word = [0; 8];
            word.copy_from_slice(&header[offset..offset + 8]);
            u64::from_le_bytes(word)
        };
        if header[..4] != MAGIC.to_le_bytes() {
            return Err(Error::InvalidResponse);
        }
        Ok(Self {
            operation: u16::from_le_bytes([header[4], header[5]]),
            flags: u16::from_le_bytes([header[6], header[7]]),
            id: word(8),
            value: word(16),
            extra: word(24),
        })
    }

    pub fn status(self) -> Result<()> {
        Status::from_raw(self.extra as i64).into_result()
    }
}

pub struct Accepted {
    pub channel: OwnedHandle<ByteChannelObject>,
    pub access: u64,
}

/// Blocks only the connection admission worker, never the data reactor.
pub fn accept(listener: &CapabilityChannel) -> Result<Accepted> {
    accept_until(listener, crate::DEADLINE_INFINITE)
}

pub fn accept_until(listener: &CapabilityChannel, deadline: u64) -> Result<Accepted> {
    let mut bytes = [MaybeUninit::uninit(); 16];
    let mut slots = [CapabilityReceiveSlot::new::<ByteChannelObject>(
        SESSION_RIGHTS,
    )];
    let message = listener.receive(deadline, &mut bytes, &mut slots)?;
    if message.bytes().len() != 16
        || message.bytes()[..8] != OPEN_MAGIC
        || message.capability_count() != 1
    {
        return Err(Error::InvalidResponse);
    }
    let mut access = [0; 8];
    access.copy_from_slice(&message.bytes()[8..]);
    let access = u64::from_le_bytes(access);
    if access == 0 || access & !(ACCESS_READ | ACCESS_WRITE) != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(Accepted {
        channel: slots[0].take()?.ok_or(Error::MissingHandle)?,
        access,
    })
}

/// Connects once per process/stream. The server sends an INFO response with id 0.
pub fn connect(
    connector: HandleRef<'_, CapabilityChannelObject>,
    access: u64,
) -> Result<Connection> {
    if access == 0 || access & !(ACCESS_READ | ACCESS_WRITE) != 0 {
        return Err(Error::InvalidResponse);
    }
    let connector = CapabilityChannel::from_handle(connector.duplicate(CONNECTOR_RIGHTS)?);
    let (channel, remote) = crate::channel::create_pair()?;
    let mut remote = Some(remote);
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&OPEN_MAGIC);
    bytes[8..].copy_from_slice(&access.to_le_bytes());
    loop {
        let mut offer = [CapabilityDisposition::move_handle(
            &mut remote,
            RightsOffer::Exact(SESSION_RIGHTS),
        )?];
        match connector.try_send(&bytes, &mut offer) {
            Ok(()) => break,
            Err(Error::Status(Status::WOULD_BLOCK)) => {
                wait_many(
                    &[WaitItem::new(
                        connector.as_handle_ref(),
                        ObjectSignals::<CapabilityChannelObject>::PEER_RECEIVING
                            .union(ObjectSignals::<CapabilityChannelObject>::PEER_CLOSED),
                    )],
                    crate::DEADLINE_INFINITE,
                )?;
            }
            Err(error) => return Err(error),
        }
    }
    let mut reply = [0; HEADER_BYTES];
    let count = channel.as_byte_channel().receive(&mut reply)?;
    let info = Header::decode(&reply[..count])?;
    if count != HEADER_BYTES || info.operation != (INFO | RESPONSE) || info.id != 0 {
        return Err(Error::InvalidResponse);
    }
    info.status()?;
    Ok(Connection {
        channel,
        metadata: info.value,
        next_id: 1,
        pending_read: None,
    })
}

pub struct Connection {
    channel: OwnedHandle<ByteChannelObject>,
    metadata: u64,
    next_id: u64,
    pending_read: Option<(u64, usize)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadResult {
    Data(usize),
    Eof,
    Cancelled,
    TimedOut,
    ConfigurationChanged,
}

impl Connection {
    pub fn as_byte_channel(&self) -> crate::channel::ByteChannel<'_> {
        self.channel.as_byte_channel()
    }
    pub fn metadata(&self) -> u64 {
        self.metadata
    }
    pub fn as_handle_ref(&self) -> HandleRef<'_, ByteChannelObject> {
        self.channel.as_handle_ref()
    }
    pub fn wait_item(&self) -> WaitItem<'_> {
        WaitItem::new(
            self.channel.as_handle_ref(),
            ObjectSignals::<ByteChannelObject>::READABLE
                .union(ObjectSignals::<ByteChannelObject>::PEER_CLOSED),
        )
    }
    fn id(&mut self) -> Result<u64> {
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(Error::InvalidResponse)?;
        Ok(id)
    }
    pub fn start_read(&mut self, maximum: usize, deadline: u64) -> Result<()> {
        if self.pending_read.is_some() || maximum == 0 || maximum > MAX_DATA {
            return Err(Error::InvalidResponse);
        }
        let id = self.id()?;
        self.channel
            .as_byte_channel()
            .send(&Header::request(READ, id, maximum as u64, deadline).encode())?;
        self.pending_read = Some((id, maximum));
        Ok(())
    }
    pub fn try_complete(&mut self, output: &mut [u8]) -> Result<Option<ReadResult>> {
        let (id, maximum) = self.pending_read.ok_or(Error::InvalidResponse)?;
        if output.len() < maximum {
            return Err(Error::InvalidResponse);
        }
        let mut frame = [0; MAX_FRAME];
        let count = match self.channel.as_byte_channel().try_receive(&mut frame) {
            Ok(count) => count,
            Err(Error::Status(Status::WOULD_BLOCK)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let header = Header::decode(&frame[..count])?;
        if header.operation != (READ | RESPONSE) || header.id != id {
            return Err(Error::InvalidResponse);
        }
        self.pending_read = None;
        header.status()?;
        let length = usize::try_from(header.value).map_err(|_| Error::InvalidResponse)?;
        if length > maximum || count != HEADER_BYTES + length {
            return Err(Error::InvalidResponse);
        }
        let result = match header.flags {
            DATA if length != 0 => {
                output[..length].copy_from_slice(&frame[HEADER_BYTES..count]);
                ReadResult::Data(length)
            }
            EOF if length == 0 => ReadResult::Eof,
            CANCELLED if length == 0 => ReadResult::Cancelled,
            TIMED_OUT if length == 0 => ReadResult::TimedOut,
            CONFIGURATION_CHANGED if length == 0 => ReadResult::ConfigurationChanged,
            _ => return Err(Error::InvalidResponse),
        };
        self.pending_read = None;
        Ok(Some(result))
    }
    /// Sends output in bounded chunks. Completion means server acceptance.
    pub fn write_all(&mut self, mut bytes: &[u8]) -> Result<()> {
        if self.pending_read.is_some() {
            return Err(Error::Status(Status::BUSY));
        }
        while !bytes.is_empty() {
            let length = bytes.len().min(MAX_DATA);
            let id = self.id()?;
            let mut frame = [0; MAX_FRAME];
            frame[..HEADER_BYTES]
                .copy_from_slice(&Header::request(WRITE, id, length as u64, 0).encode());
            frame[HEADER_BYTES..HEADER_BYTES + length].copy_from_slice(&bytes[..length]);
            self.channel
                .as_byte_channel()
                .send(&frame[..HEADER_BYTES + length])?;
            let accepted = self.acknowledge(WRITE, id, length as u64)?;
            bytes = &bytes[accepted as usize..];
        }
        Ok(())
    }

    /// Orders prior output through the server; this is not a physical UART drain.
    pub fn fence(&mut self) -> Result<()> {
        if self.pending_read.is_some() {
            return Err(Error::Status(Status::BUSY));
        }
        let id = self.id()?;
        self.channel
            .as_byte_channel()
            .send(&Header::request(FENCE, id, 0, 0).encode())?;
        self.acknowledge(FENCE, id, 0).map(|_| ())
    }

    fn acknowledge(&self, operation: u16, id: u64, value: u64) -> Result<u64> {
        let mut frame = [0; HEADER_BYTES];
        let count = self.channel.as_byte_channel().receive(&mut frame)?;
        let header = Header::decode(&frame[..count])?;
        if count != HEADER_BYTES || header.operation != (operation | RESPONSE) || header.id != id {
            return Err(Error::InvalidResponse);
        }
        header.status()?;
        if header.flags != DATA || header.value > value || (value != 0 && header.value == 0) {
            return Err(Error::InvalidResponse);
        }
        Ok(header.value)
    }

    /// Requests cancellation; the original READ result remains the sole completion.
    /// A server that already committed the READ must not emit a second response.
    pub fn cancel(&self) -> Result<()> {
        let (id, _) = self.pending_read.ok_or(Error::InvalidResponse)?;
        self.channel
            .as_byte_channel()
            .send(&Header::request(CANCEL, id, id, 0).encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_round_trip_and_truncated_headers() {
        let value = Header::response(READ, 42, TIMED_OUT, 0, -1);
        assert_eq!(Header::decode(&value.encode()), Ok(value));
        for length in 0..HEADER_BYTES {
            assert!(Header::decode(&value.encode()[..length]).is_err());
        }
    }
}

/// Exclusive asynchronous borrow of the process's ordinary stdin connection.
///
/// This uses the same runtime owner as `std::io::stdin`; ordinary reads return
/// BUSY while borrowed. Cancel and collect the completion before releasing a
/// pending read. Dropping an unfinished read abandons this private connection.
pub struct ProcessInput {
    handle: core::num::NonZeroU64,
    _not_sync: core::marker::PhantomData<core::cell::Cell<()>>,
}

impl ProcessInput {
    pub fn acquire() -> Result<Self> {
        let mut handle = 0;
        // SAFETY: the runtime initializes the output and grants exclusive ownership.
        Status::from_raw(unsafe { runtime_input::acquire(&mut handle) }).into_result()?;
        Ok(Self {
            handle: core::num::NonZeroU64::new(handle).ok_or(Error::InvalidResponse)?,
            _not_sync: core::marker::PhantomData,
        })
    }
    pub fn as_handle_ref(&self) -> HandleRef<'_, ByteChannelObject> {
        // SAFETY: this exclusive claim keeps the runtime-owned handle live until Drop.
        unsafe { HandleRef::from_raw_borrowed(self.handle) }
    }
    pub fn wait_item(&self) -> WaitItem<'_> {
        WaitItem::new(
            self.as_handle_ref(),
            ObjectSignals::<ByteChannelObject>::READABLE
                .union(ObjectSignals::<ByteChannelObject>::PEER_CLOSED),
        )
    }
    pub fn start_read(&mut self, maximum: usize, deadline: u64) -> Result<()> {
        // SAFETY: this object owns the sole Native stdin claim.
        Status::from_raw(unsafe { runtime_input::begin(maximum, deadline) }).into_result()
    }
    pub fn try_complete(&mut self, output: &mut [u8]) -> Result<Option<ReadResult>> {
        let mut length = 0;
        let mut kind = 0;
        // SAFETY: the writable buffer is exclusive and both output scalars are live.
        let status = Status::from_raw(unsafe {
            runtime_input::poll(output.as_mut_ptr(), output.len(), &mut length, &mut kind)
        });
        if status == Status::WOULD_BLOCK && kind == u32::MAX {
            return Ok(None);
        }
        status.into_result()?;
        if length > output.len() {
            return Err(Error::InvalidResponse);
        }
        Ok(Some(match kind {
            0 if length != 0 => ReadResult::Data(length),
            1 if length == 0 => ReadResult::Eof,
            2 if length == 0 => ReadResult::Cancelled,
            3 if length == 0 => ReadResult::TimedOut,
            4 if length == 0 => ReadResult::ConfigurationChanged,
            _ => return Err(Error::InvalidResponse),
        }))
    }
    pub fn cancel(&mut self) -> Result<()> {
        // SAFETY: this object owns the sole Native stdin claim.
        Status::from_raw(unsafe { runtime_input::cancel() }).into_result()
    }
}
impl Drop for ProcessInput {
    fn drop(&mut self) {
        // SAFETY: release consumes exactly the claim acquired by this owner.
        unsafe { runtime_input::release() }
    }
}
#[cfg(target_os = "hyper")]
mod runtime_input {
    unsafe extern "C" {
        #[link_name = "hyper_runtime_stdin_acquire"]
        pub(super) fn acquire(handle: *mut u64) -> i64;
        #[link_name = "hyper_runtime_stdin_begin"]
        pub(super) fn begin(maximum: usize, deadline: u64) -> i64;
        #[link_name = "hyper_runtime_stdin_poll"]
        pub(super) fn poll(
            bytes: *mut u8,
            capacity: usize,
            actual: *mut usize,
            kind: *mut u32,
        ) -> i64;
        #[link_name = "hyper_runtime_stdin_cancel"]
        pub(super) fn cancel() -> i64;
        #[link_name = "hyper_runtime_stdin_release"]
        pub(super) fn release();
    }
}
#[cfg(not(target_os = "hyper"))]
mod runtime_input {
    pub(super) unsafe fn acquire(_: *mut u64) -> i64 {
        hyper_abi::HYPER_NATIVE_STATUS_NOT_SUPPORTED
    }
    pub(super) unsafe fn begin(_: usize, _: u64) -> i64 {
        hyper_abi::HYPER_NATIVE_STATUS_NOT_SUPPORTED
    }
    pub(super) unsafe fn poll(_: *mut u8, _: usize, _: *mut usize, _: *mut u32) -> i64 {
        hyper_abi::HYPER_NATIVE_STATUS_NOT_SUPPORTED
    }
    pub(super) unsafe fn cancel() -> i64 {
        hyper_abi::HYPER_NATIVE_STATUS_NOT_SUPPORTED
    }
    pub(super) unsafe fn release() {}
}
