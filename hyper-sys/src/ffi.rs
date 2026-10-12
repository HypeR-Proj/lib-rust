// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! C runtime syscall veneers linked from the installed Native runtime.

use crate::{CallResult, RawStartup, abi};

unsafe extern "C" {
    #[link_name = "hyper_native_call6"]
    pub(super) fn ffi_native_call6(
        number: u64,
        argument0: u64,
        argument1: u64,
        argument2: u64,
        argument3: u64,
        argument4: u64,
        argument5: u64,
    ) -> CallResult;

    #[link_name = "hyper_abi_query"]
    pub(super) fn ffi_abi_query() -> CallResult;

    #[link_name = "hyper_clock_get_monotonic"]
    pub(super) fn ffi_clock_get_monotonic() -> CallResult;

    #[link_name = "hyper_startup_find_handle"]
    pub(super) fn ffi_startup_find_handle(
        startup: *const RawStartup,
        purpose: u32,
        handle: *mut abi::HyperNativeHandle,
    ) -> abi::HyperNativeStatus;

    #[link_name = "hyper_handle_close"]
    pub(super) fn ffi_handle_close(handle: abi::HyperNativeHandle) -> abi::HyperNativeStatus;

    #[link_name = "hyper_object_wait_one"]
    pub(super) fn ffi_object_wait_one(
        object: abi::HyperNativeHandle,
        signals: u64,
        deadline: u64,
    ) -> CallResult;

    #[link_name = "hyper_byte_channel_write"]
    pub(super) fn ffi_byte_channel_write(
        endpoint: abi::HyperNativeHandle,
        bytes: *const u8,
        byte_count: usize,
    ) -> abi::HyperNativeStatus;

    #[link_name = "hyper_byte_channel_read"]
    pub(super) fn ffi_byte_channel_read(
        endpoint: abi::HyperNativeHandle,
        bytes: *mut u8,
        byte_capacity: usize,
    ) -> CallResult;

    #[link_name = "hyper_console_read"]
    pub(super) fn ffi_console_read(
        console: abi::HyperNativeHandle,
        bytes: *mut u8,
        capacity: usize,
    ) -> CallResult;

    #[link_name = "hyper_console_write"]
    pub(super) fn ffi_console_write(
        console: abi::HyperNativeHandle,
        bytes: *const u8,
        count: usize,
    ) -> CallResult;

    #[link_name = "hyper_thread_create"]
    pub(super) fn ffi_thread_create(
        entry: u64,
        stack: u64,
        tls: u64,
        argument: u64,
        affinity_words: *const u64,
        affinity_word_count: usize,
    ) -> CallResult;
    #[link_name = "hyper_thread_start"]
    pub(super) fn ffi_thread_start(thread: u64) -> abi::HyperNativeStatus;
    #[link_name = "hyper_thread_request_stop"]
    pub(super) fn ffi_thread_request_stop(thread: u64) -> abi::HyperNativeStatus;
    #[link_name = "hyper_atomic_wait"]
    pub(super) fn ffi_atomic_wait(
        address: *const u32,
        expected: u32,
        deadline: u64,
    ) -> abi::HyperNativeStatus;
    #[link_name = "hyper_atomic_wake"]
    pub(super) fn ffi_atomic_wake(address: *const u32, count: u32) -> CallResult;
    #[link_name = "hyper_thread_sleep"]
    pub(super) fn ffi_thread_sleep(deadline: u64) -> abi::HyperNativeStatus;
    #[link_name = "hyper_thread_yield"]
    pub(super) fn ffi_thread_yield() -> abi::HyperNativeStatus;

    #[link_name = "hyper_thread_exit"]
    pub(super) fn ffi_thread_exit(status: i64) -> !;

    #[link_name = "hyper_process_exit"]
    pub(super) fn ffi_process_exit(status: i64) -> !;
}
