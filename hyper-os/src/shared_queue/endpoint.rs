// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::mapping::AtomicWords;
use super::protocol::{CLOSED, Cursor, DATA_ARMED, HEAD, SPACE_ARMED, TAIL};
use super::{BatchOutcome, ConsumerParts, ProducerParts, QueueError, ReceiveSlot};
use crate::event::Event;
use crate::handle::{ByteChannelObject, HandleRef, OwnedHandle, VmarObject};
use crate::wait::{ObjectSignals, RegistrationId, WaitSet};
use core::sync::atomic::Ordering::SeqCst;

struct Waiter {
    // Close the set before its source handles during teardown.
    set: Option<WaitSet>,
    lifetime: Option<OwnedHandle<ByteChannelObject>>,
    readiness: RegistrationId,
    closed: RegistrationId,
    rearm: bool,
    peer_dead: bool,
}
impl Waiter {
    fn new(event: &Event, lifetime: OwnedHandle<ByteChannelObject>) -> crate::Result<Self> {
        let set = WaitSet::new(2)?;
        let readiness = set.add(event.as_handle_ref(), ObjectSignals::SIGNALED)?;
        let closed = set.add(
            lifetime.as_handle_ref(),
            ObjectSignals::<ByteChannelObject>::PEER_CLOSED,
        )?;
        Ok(Self {
            set: Some(set),
            lifetime: Some(lifetime),
            readiness,
            closed,
            rearm: false,
            peer_dead: false,
        })
    }
    fn prepare(&mut self) -> Result<(), QueueError> {
        if self.peer_dead {
            return Err(QueueError::PeerDied);
        }
        if self.rearm {
            self.set
                .as_ref()
                .ok_or(QueueError::Poisoned)?
                .rearm(self.readiness)?;
            self.rearm = false;
        }
        Ok(())
    }
    fn wait(&mut self, deadline: u64) -> Result<(), QueueError> {
        let mut notifications = [None; 2];
        self.set
            .as_ref()
            .ok_or(QueueError::Poisoned)?
            .wait_batch(deadline, &mut notifications)?;
        for notification in notifications.into_iter().flatten() {
            if notification.registration == self.readiness {
                self.rearm = true;
            } else if notification.registration == self.closed {
                self.peer_dead = true;
            } else {
                return Err(QueueError::InvalidPeer);
            }
        }
        Ok(())
    }
    fn close(&mut self) {
        self.set.take();
        self.lifetime.take();
    }
}

/// Single producer owner. Mutable borrowing serializes its local publication.
pub struct Producer {
    data: AtomicWords,
    control: AtomicWords,
    data_ready: Event,
    space_ready: Event,
    waiter: Waiter,
    cursor: Cursor,
    poisoned: bool,
}
/// Single consumer owner. A received message is copied into private storage.
pub struct Consumer {
    data: AtomicWords,
    control: AtomicWords,
    data_ready: Event,
    space_ready: Event,
    waiter: Waiter,
    cursor: Cursor,
    poisoned: bool,
}

impl Producer {
    /// Map one fresh role, after transferring its capabilities to this process.
    ///
    /// # Safety
    /// `root` must belong to the calling process. No other VMAR authority may
    /// unmap/protect these private children during this owner's lifetime. All
    /// aliases of the populated shared storage must use aligned atomic u64
    /// accesses at matching offsets. Each role has exactly one protocol owner.
    pub unsafe fn map(
        parts: ProducerParts,
        root: HandleRef<'_, VmarObject>,
    ) -> Result<Self, QueueError> {
        if parts.data.basic_info()?.koid == parts.control.basic_info()?.koid {
            return Err(QueueError::InvalidPeer);
        }
        // SAFETY: caller supplies lifetime/aliasing contract; geometry is local.
        let data = unsafe {
            AtomicWords::map(
                root,
                parts.data.as_handle_ref(),
                parts.config.data_bytes(),
                true,
            )?
        };
        // SAFETY: same contract; peer control remains read-only in this role.
        let control = unsafe {
            AtomicWords::map(
                root,
                parts.control.as_handle_ref(),
                crate::memory::PAGE_SIZE as usize,
                false,
            )?
        };
        if data.load(HEAD, SeqCst)? != 0 || data.load(CLOSED, SeqCst)? != 0 {
            return Err(QueueError::InvalidPeer);
        }
        let waiter = Waiter::new(&parts.space_ready, parts.lifetime)?;
        Ok(Self {
            data,
            control,
            data_ready: parts.data_ready,
            space_ready: parts.space_ready,
            waiter,
            cursor: Cursor::new(parts.config),
            poisoned: false,
        })
    }

    /// Publish complete messages, stopping at the first full/error result.
    /// A failure after publication is returned alongside its committed prefix.
    pub fn try_send_batch(&mut self, input: &[&[u8]]) -> BatchOutcome {
        let mut outcome = BatchOutcome {
            completed: 0,
            stop: None,
        };
        if self.poisoned {
            outcome.stop = Some(QueueError::Poisoned);
            return outcome;
        }
        if self.waiter.peer_dead {
            outcome.stop = Some(QueueError::PeerDied);
            return outcome;
        }
        outcome =
            super::protocol::send_batch(&mut self.cursor, &self.data, &self.control, input, || {
                notify(&self.control, DATA_ARMED, &self.data_ready)
            });
        if outcome.stop.is_some_and(QueueError::terminal) {
            self.poisoned = true;
            self.waiter.close();
        }
        outcome
    }

    /// Wait for capacity using one absolute deadline across all spurious hints.
    pub fn wait_writable_until(&mut self, deadline: u64) -> Result<(), QueueError> {
        if self.poisoned {
            return Err(QueueError::Poisoned);
        }
        let result = self.wait_writable(deadline);
        let disarm = self
            .data
            .store(SPACE_ARMED, 0, SeqCst)
            .map_err(QueueError::from);
        let result = result.and(disarm);
        self.handle_wait_result(result)
    }
    fn wait_writable(&mut self, deadline: u64) -> Result<(), QueueError> {
        loop {
            if self.waiter.peer_dead {
                return Err(QueueError::PeerDied);
            }
            if self.cursor.writable(&self.control)? {
                return Ok(());
            }
            deadline_check(deadline)?;
            self.space_ready.signal(Event::SIGNALED, 0)?;
            self.waiter.prepare()?;
            self.data.store(SPACE_ARMED, 1, SeqCst)?;
            if self.cursor.writable(&self.control)? {
                return Ok(());
            }
            self.waiter.wait(deadline)?;
        }
    }
    fn handle_wait_result(&mut self, result: Result<(), QueueError>) -> Result<(), QueueError> {
        if result.is_err_and(wait_fatal) {
            self.poisoned = true;
            self.waiter.close();
        }
        result
    }
    /// Publish a graceful end after the last message, then relinquish this role.
    /// Dropping without `finish` reports peer death rather than clean end-of-stream.
    pub fn finish(mut self) -> Result<(), QueueError> {
        if self.poisoned {
            return Err(QueueError::Poisoned);
        }
        self.data.store(CLOSED, 1, SeqCst)?;
        let result = notify(&self.control, DATA_ARMED, &self.data_ready);
        self.waiter.close();
        result
    }
}

impl Consumer {
    /// Map the fresh consumer role. See [`Producer::map`] for the safety contract.
    ///
    /// # Safety
    /// The same current-process root, private VMAR lifetime, populated storage,
    /// consistent atomic-u64 aliases and unique protocol-role rules apply.
    pub unsafe fn map(
        parts: ConsumerParts,
        root: HandleRef<'_, VmarObject>,
    ) -> Result<Self, QueueError> {
        if parts.data.basic_info()?.koid == parts.control.basic_info()?.koid {
            return Err(QueueError::InvalidPeer);
        }
        // SAFETY: caller supplies lifetime/aliasing contract; peer data is read-only.
        let data = unsafe {
            AtomicWords::map(
                root,
                parts.data.as_handle_ref(),
                parts.config.data_bytes(),
                false,
            )?
        };
        // SAFETY: the caller supplies the same contract for this role's control.
        let control = unsafe {
            AtomicWords::map(
                root,
                parts.control.as_handle_ref(),
                crate::memory::PAGE_SIZE as usize,
                true,
            )?
        };
        if control.load(TAIL, SeqCst)? != 0 {
            return Err(QueueError::InvalidPeer);
        }
        let waiter = Waiter::new(&parts.data_ready, parts.lifetime)?;
        Ok(Self {
            data,
            control,
            data_ready: parts.data_ready,
            space_ready: parts.space_ready,
            waiter,
            cursor: Cursor::new(parts.config),
            poisoned: false,
        })
    }

    /// Consume complete messages into private buffers. A short buffer preserves
    /// the head message. Slots outside the committed prefix expose no message.
    pub fn try_receive_batch(&mut self, output: &mut [ReceiveSlot<'_>]) -> BatchOutcome {
        for slot in output.iter_mut() {
            slot.length = None;
        }
        let mut outcome = BatchOutcome {
            completed: 0,
            stop: None,
        };
        if self.poisoned {
            outcome.stop = Some(QueueError::Poisoned);
            return outcome;
        }
        outcome = super::protocol::receive_batch(
            &mut self.cursor,
            &self.data,
            &self.control,
            output,
            self.waiter.peer_dead,
            || notify(&self.data, SPACE_ARMED, &self.space_ready),
        );
        if outcome.stop.is_some_and(QueueError::terminal) {
            self.poisoned = true;
            self.waiter.close();
        }
        outcome
    }

    pub fn wait_readable_until(&mut self, deadline: u64) -> Result<(), QueueError> {
        if self.poisoned {
            return Err(QueueError::Poisoned);
        }
        let result = self.wait_readable(deadline);
        let disarm = self
            .control
            .store(DATA_ARMED, 0, SeqCst)
            .map_err(QueueError::from);
        let result = result.and(disarm);
        if result.is_err_and(wait_fatal) {
            self.poisoned = true;
            self.waiter.close();
        }
        result
    }
    fn wait_readable(&mut self, deadline: u64) -> Result<(), QueueError> {
        loop {
            if self.cursor.readable(&self.data)? {
                return Ok(());
            }
            if self.waiter.peer_dead {
                return Err(QueueError::PeerDied);
            }
            deadline_check(deadline)?;
            self.data_ready.signal(Event::SIGNALED, 0)?;
            self.waiter.prepare()?;
            self.control.store(DATA_ARMED, 1, SeqCst)?;
            if self.cursor.readable(&self.data)? {
                return Ok(());
            }
            self.waiter.wait(deadline)?;
        }
    }
}

fn notify(words: &AtomicWords, armed: usize, event: &Event) -> Result<(), QueueError> {
    // SC joins the cursor publication and waiter arm/recheck order. The Event
    // syscall provides a scheduling hint, not the shared-memory fence.
    match words.load(armed, SeqCst)? {
        0 => Ok(()),
        1 => event.signal(0, Event::SIGNALED).map_err(QueueError::from),
        _ => Err(QueueError::InvalidPeer),
    }
}
fn deadline_check(deadline: u64) -> Result<(), QueueError> {
    if deadline != crate::DEADLINE_INFINITE
        && crate::time::monotonic_now()?.as_nanoseconds() >= deadline
    {
        return Err(QueueError::System(crate::Error::Status(
            crate::Status::TIMED_OUT,
        )));
    }
    Ok(())
}
fn wait_fatal(error: QueueError) -> bool {
    match error {
        QueueError::System(crate::Error::Status(
            crate::Status::TIMED_OUT | crate::Status::CANCELLED,
        )) => false,
        other => other.terminal(),
    }
}
