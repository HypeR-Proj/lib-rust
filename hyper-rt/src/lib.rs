// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Minimal language runtime for freestanding `HypeR` Native Rust applications.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
pub mod process;

/// Rust's standard heap-backed collections and formatting facilities.
pub extern crate alloc;

#[cfg(all(not(test), not(feature = "std"), target_os = "none"))]
#[global_allocator]
static ALLOCATOR: hyper_sys::allocator::NativeAllocator = hyper_sys::allocator::NativeAllocator;

pub use hyper_os::startup::Startup;
pub use hyper_sys::RawStartup;

/// Process status returned from a Native Rust application entry point.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitCode(i32);

impl ExitCode {
    pub const SUCCESS: Self = Self(0);
    pub const FAILURE: Self = Self(1);

    #[must_use]
    pub const fn from_raw(status: i32) -> Self {
        Self(status)
    }

    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self.0
    }
}

#[doc(hidden)]
pub type ApplicationMain = for<'runtime> fn(Startup<'runtime>) -> ExitCode;

/// Enters one safe Rust application from the C runtime boundary.
///
/// # Safety
///
/// `raw` must satisfy [`Startup::from_raw`] for the duration of `main`.
#[doc(hidden)]
pub unsafe fn run(raw: *const RawStartup, main: ApplicationMain) -> i32 {
    // SAFETY: the C runtime calls this function only with its live, validated
    // stack-local startup view, and `main` cannot retain its lifetime.
    let startup = match unsafe { Startup::from_raw(raw) } {
        Ok(startup) => startup,
        Err(_) => return ExitCode::FAILURE.as_raw(),
    };
    main(startup).as_raw()
}

/// Defines the unique Native runtime entry for an application.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        const _: $crate::ApplicationMain = $main;

        #[unsafe(no_mangle)]
        unsafe extern "C" fn hyper_main(startup: *const $crate::RawStartup) -> i32 {
            // SAFETY: `hyper_main` is called only by the matching Native CRT,
            // whose successful parser owns the startup pointer contract.
            unsafe { $crate::run(startup, $main) }
        }
    };
}

#[cfg(all(not(test), not(feature = "std")))]
#[panic_handler]
fn panic(_information: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: a panic aborts the active Native Process without running
    // destructors, matching this runtime's configured panic strategy.
    unsafe { hyper_sys::process_exit(hyper_abi::HYPER_NATIVE_STATUS_INTERNAL) }
}
