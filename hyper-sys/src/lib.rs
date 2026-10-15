// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Raw bindings to the `HypeR` Native userspace ABI.
//!
//! This crate deliberately exposes the ownership and pointer hazards of the
//! machine ABI. Native applications should use `hyper-os`; language runtimes
//! are the expected direct consumers of this crate.

#![no_std]

pub mod allocator;

mod console;
mod device;
mod ffi;
mod fs;
mod guest_io;
mod handle;
mod inspect;
mod ipc;
mod memory;
mod startup;
mod system;
mod task;
mod vm;
mod wait;

pub use console::{
    console_discard_input, console_read, console_write, virtual_serial_acknowledge_output,
    virtual_serial_create, virtual_serial_register_output, virtual_serial_write,
};
pub use device::{
    device_claim, device_claim_bundle, device_claim_matching, device_firmware_read,
    device_irq_complete, device_irq_pending, device_mmio, device_profile_info,
    device_resource_info, physical_device_info,
};
pub use fs::{
    directory_begin_read, directory_canonicalize, directory_create_directory,
    directory_create_file, directory_get_info, directory_get_metadata, directory_get_self_metadata,
    directory_link, directory_open_directory, directory_open_directory_nofollow,
    directory_open_file, directory_open_file_with_options, directory_read, directory_read_link,
    directory_remove, directory_remove_if, directory_rename, directory_scope_create,
    directory_set_metadata, directory_symlink, file_get_info, file_get_metadata, file_lock,
    file_protect, file_read_at, file_resize, file_set_metadata, file_sync, file_unlock,
    file_write_at, filesystem_begin_root_switch, filesystem_finish_root_switch,
    filesystem_mount_ramfs, filesystem_switch_root,
};
pub use guest_io::{
    filesystem_mount, filesystem_unmount, guest_interrupt_create, guest_interrupt_set_level,
    guest_mailbox_create, guest_mailbox_receive, guest_mailbox_send, guest_mapping_create,
    guest_mapping_release, guest_memory_scalar, guest_memory_transfer, guest_notification_access,
    guest_notification_configure, guest_notification_control, guest_notification_create,
    native_block_activate, native_block_create, native_block_transfer,
};
pub use handle::{
    handle_close, handle_duplicate, handle_get_info, handle_replace, object_get_basic_info,
};
pub use hyper_abi as abi;
pub use inspect::{
    cpu_inspector_read, memory_inspector_read, memory_inspector_read_statistics,
    object_inspector_derive_process, object_inspector_derive_resource_domain,
    object_inspector_derive_task_group, object_inspector_read_details,
    object_inspector_scan_handles, object_inspector_scan_objects, task_inspector_derive_process,
    task_inspector_derive_resource_domain, task_inspector_derive_task_group,
    task_inspector_scan_processes, task_inspector_scan_threads,
};
pub use ipc::{
    byte_channel_create, byte_channel_read, byte_channel_write, capability_channel_create,
    capability_channel_receive, capability_channel_try_send,
};
pub use memory::{
    vmar_allocate, vmar_destroy, vmar_lock_memory, vmar_map, vmar_map_file, vmar_map_private,
    vmar_protect, vmar_unlock_memory, vmar_unmap, vmo_create, vmo_create_contiguous,
    vmo_create_snapshot, vmo_get_dma_extent, vmo_read, vmo_write,
};
pub use startup::{AuxiliaryEntry, RawStartup, startup_find_handle};
pub use system::{abi_query, clock_get_monotonic, clock_get_realtime, system_config};
pub use task::{
    process_builder_abort, process_builder_add_handle, process_builder_create,
    process_builder_seal, process_builder_set_affinity, process_builder_set_data,
    process_builder_set_memory_lock, process_builder_set_name, process_builder_start,
    process_derive_observer, process_exit, process_get_current_id, process_get_info,
    process_request_stop, resource_domain_create, task_group_create, task_group_request_stop,
    thread_create, thread_exit, thread_request_stop, thread_sleep, thread_start, thread_yield,
};
pub use vm::{
    guest_memory_create, pending_virtual_machine_abort, pending_virtual_machine_assign_device,
    pending_virtual_machine_install, pending_virtual_machine_map_memory,
    pending_virtual_machine_seal, pending_virtual_machine_set_bootstrap,
    pending_virtual_machine_set_memory, pending_virtual_machine_set_virtual_serial,
    virtual_cpu_complete_mmio, virtual_cpu_get_info, virtual_cpu_get_mmio_request,
    virtual_cpu_set_affinity, virtual_cpu_start, virtual_machine_complete_power_request,
    virtual_machine_create, virtual_machine_creation_lease_create,
    virtual_machine_creation_lease_get_platform_info, virtual_machine_get_info,
    virtual_machine_get_power_request, virtual_machine_open_vcpu, virtual_machine_register_mmio,
    virtual_machine_request_stop,
};
pub use wait::{
    atomic_wait, atomic_wake, object_wait_many, object_wait_one, wait_set_add, wait_set_create,
    wait_set_rearm, wait_set_remove, wait_set_wait,
};

/// Register result returned by one `HypeR` Native syscall.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallResult {
    pub status: abi::HyperNativeStatus,
    pub value0: u64,
    pub value1: u64,
}

const _: () = assert!(core::mem::size_of::<CallResult>() == 24);
const _: () = assert!(core::mem::align_of::<CallResult>() == 8);
