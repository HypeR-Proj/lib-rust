// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Native capabilities for applications using ordinary Rust `main`.
//!
//! Standard streams and the bootstrap Console remain owned by the runtime
//! until process exit, including during std cleanup and TLS destructors.

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use hyper_os::handle::{ByteChannelObject, ConsoleObject, OwnedHandle};
use hyper_os::startup::{CONSOLE, Startup, StartupPurpose};
use hyper_os::{Error, Result};

static CLAIMED: AtomicBool = AtomicBool::new(false);
static STREAMS: OnceLock<Streams> = OnceLock::new();

struct Streams {
    input: Option<OwnedHandle<ByteChannelObject>>,
    terminal_input: bool,
    _terminal_alias: Option<OwnedHandle<ByteChannelObject>>,
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
    let ordinary = startup.take_optional(StartupPurpose::new(0x80030001))?;
    let terminal = startup.take_optional(StartupPurpose::new(0x80030004))?;
    if let Some(alias) = &terminal {
        let input = ordinary.as_ref().ok_or(Error::InvalidStartup)?;
        if alias.basic_info()? != input.basic_info()? {
            return Err(Error::InvalidStartup);
        }
    }
    let terminal_input = terminal.is_some();
    let streams = Streams {
        input: ordinary,
        terminal_input,
        _terminal_alias: terminal,
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

/// Whether inherited stdin uses terminal packet/EOF semantics rather than
/// binary pipe semantics. Propagate this only when inheriting the same source.
pub fn stdin_is_terminal() -> bool {
    STREAMS.get().is_some_and(|streams| streams.terminal_input)
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
