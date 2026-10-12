// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Native capabilities for applications using ordinary Rust `main`.
//!
//! Standard streams and the bootstrap Console remain owned by the runtime
//! until process exit, including during std cleanup and TLS destructors.

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use hyper_os::handle::{ByteChannelObject, CapabilityChannelObject, ConsoleObject, OwnedHandle};
use hyper_os::startup::{CONSOLE, Startup, StartupPurpose};
use hyper_os::{Error, Result};

static CLAIMED: AtomicBool = AtomicBool::new(false);
static STREAMS: OnceLock<Streams> = OnceLock::new();

struct Streams {
    input: Option<OwnedHandle<ByteChannelObject>>,
    input_stream: Option<OwnedHandle<CapabilityChannelObject>>,
    output_stream: Option<OwnedHandle<CapabilityChannelObject>>,
    error_stream: Option<OwnedHandle<CapabilityChannelObject>>,
    output: Option<OwnedHandle<ByteChannelObject>>,
    error: Option<OwnedHandle<ByteChannelObject>>,
    console: Option<OwnedHandle<ConsoleObject>>,
}

/// Claims the application's startup capabilities exactly once.
///
/// Call this before starting additional threads. Stream purposes are retained
/// by the runtime; use std I/O, or the borrowed handles below for Native waits
/// and message routing. A second call fails rather than creating another owner.
pub fn startup() -> Result<Startup<'static>> {
    if CLAIMED.swap(true, Ordering::AcqRel) {
        return Err(Error::InvalidStartup);
    }
    #[cfg(target_os = "hyper")]
    let raw = {
        unsafe extern "C" {
            fn hyper_runtime_startup() -> *const crate::RawStartup;
        }
        // SAFETY: the matching CRT initialized the immutable process-lifetime
        // record before main. CLAIMED grants unique ownership to this caller.
        unsafe { hyper_runtime_startup() }
    };
    #[cfg(not(target_os = "hyper"))]
    let raw = core::ptr::null();
    // SAFETY: the Native CRT owns the live record for the process lifetime;
    // the atomic claim prevents duplicate safe owners. Null is rejected on hosts.
    let mut startup = unsafe { Startup::from_raw(raw)? };
    // These service purposes match hyper-service::stdio. Keeping the owners in
    // a static prevents Startup::drop from closing handles still used by std.
    let streams = Streams {
        input: startup.take_optional(StartupPurpose::new(0x80030001))?,
        input_stream: startup.take_optional(hyper_os::stream::STANDARD_INPUT)?,
        output_stream: startup.take_optional(hyper_os::stream::STANDARD_OUTPUT)?,
        error_stream: startup.take_optional(hyper_os::stream::STANDARD_ERROR)?,
        output: startup.take_optional(StartupPurpose::new(0x80030002))?,
        error: startup.take_optional(StartupPurpose::new(0x80030003))?,
        console: startup.take_optional(CONSOLE)?,
    };
    STREAMS.set(streams).map_err(|_| Error::InvalidStartup)?;
    Ok(startup)
}

/// Borrows stdin for Native readiness waits or message routing.
pub fn stdin() -> Result<&'static OwnedHandle<ByteChannelObject>> {
    STREAMS
        .get()
        .and_then(|s| s.input.as_ref())
        .ok_or(Error::MissingHandle)
}

/// Borrows the inheritable input connector, never a private read connection.
pub fn stdin_stream() -> Result<Option<&'static OwnedHandle<CapabilityChannelObject>>> {
    Ok(STREAMS
        .get()
        .ok_or(Error::InvalidStartup)?
        .input_stream
        .as_ref())
}
pub fn stdout_stream() -> Result<Option<&'static OwnedHandle<CapabilityChannelObject>>> {
    Ok(STREAMS
        .get()
        .ok_or(Error::InvalidStartup)?
        .output_stream
        .as_ref())
}
pub fn stderr_stream() -> Result<Option<&'static OwnedHandle<CapabilityChannelObject>>> {
    Ok(STREAMS
        .get()
        .ok_or(Error::InvalidStartup)?
        .error_stream
        .as_ref())
}

/// Queries the stream server's terminal metadata; pipes remain ordinary bytes.
pub fn stdin_is_terminal() -> bool {
    #[cfg(target_os = "hyper")]
    {
        unsafe extern "C" {
            fn hyper_runtime_stream_is_terminal(stream: u32) -> i32;
        }
        // SAFETY: this query takes no pointers or transferred handles.
        unsafe { hyper_runtime_stream_is_terminal(0) != 0 }
    }
    #[cfg(not(target_os = "hyper"))]
    {
        false
    }
}

/// Borrows stdout for Native message routing.
pub fn stdout() -> Result<&'static OwnedHandle<ByteChannelObject>> {
    STREAMS
        .get()
        .and_then(|s| s.output.as_ref())
        .ok_or(Error::MissingHandle)
}

/// Borrows stderr for Native message routing.
pub fn stderr() -> Result<&'static OwnedHandle<ByteChannelObject>> {
    STREAMS
        .get()
        .and_then(|s| s.error.as_ref())
        .ok_or(Error::MissingHandle)
}

/// Borrows the runtime-owned bootstrap Console capability.
pub fn console() -> Result<&'static OwnedHandle<ConsoleObject>> {
    STREAMS
        .get()
        .and_then(|s| s.console.as_ref())
        .ok_or(Error::MissingHandle)
}
