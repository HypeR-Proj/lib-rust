// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Native object markers and their diagnostic vocabulary share one catalog.

use super::{ObjectType, TypedObject, private};
use crate::{Error, Result};

/// One Native object-kind value reported by the kernel.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectKind(u32);

macro_rules! object_types {
    ($(($marker:ident, $kind:ident, $name:literal, $purpose:literal)),+ $(,)?) => {
        $(
            #[doc = concat!("Type marker for Native `", stringify!($kind), "` objects.")]
            pub enum $marker {}

            impl private::Sealed for $marker {}
            impl ObjectType for $marker {}
            impl TypedObject for $marker {
                const KIND: ObjectKind = ObjectKind(hyper_abi::$kind);
            }
        )+

        impl ObjectKind {
            /// All object kinds understood by this SDK.
            pub const KNOWN: &'static [Self] = &[$(Self(hyper_abi::$kind)),+];

            /// Returns the stable Native name of this object kind.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self.0 {
                    $(hyper_abi::$kind => $name,)+
                    _ => "unknown",
                }
            }

            /// Summarizes the role carried by this object kind.
            #[must_use]
            pub const fn purpose(self) -> &'static str {
                match self.0 {
                    $(hyper_abi::$kind => $purpose,)+
                    _ => "object kind not known to this SDK",
                }
            }
        }
    };
}

object_types!(
    (
        ProcessRetirementObject,
        HYPER_NATIVE_OBJECT_PROCESS_RETIREMENT,
        "process-retirement",
        "supervised diagnostic retention"
    ),
    (
        CrashViewObject,
        HYPER_NATIVE_OBJECT_CRASH_VIEW,
        "crash-view",
        "revocable stopped-process observation"
    ),
    (
        EventObject,
        HYPER_NATIVE_OBJECT_EVENT,
        "event",
        "notification"
    ),
    (
        ByteChannelObject,
        HYPER_NATIVE_OBJECT_BYTE_CHANNEL,
        "byte-channel",
        "byte channel endpoint"
    ),
    (
        ThreadObject,
        HYPER_NATIVE_OBJECT_THREAD,
        "thread",
        "thread control"
    ),
    (
        ProcessObject,
        HYPER_NATIVE_OBJECT_PROCESS,
        "process",
        "process supervision"
    ),
    (
        TaskGroupObject,
        HYPER_NATIVE_OBJECT_TASK_GROUP,
        "task-group",
        "lifecycle group"
    ),
    (
        ResourceDomainObject,
        HYPER_NATIVE_OBJECT_RESOURCE_DOMAIN,
        "resource-domain",
        "resource accounting"
    ),
    (
        TaskFactoryObject,
        HYPER_NATIVE_OBJECT_TASK_FACTORY,
        "task-factory",
        "process creation"
    ),
    (
        ExecutableAuthorityObject,
        HYPER_NATIVE_OBJECT_EXECUTABLE_AUTHORITY,
        "executable-authority",
        "executable mapping"
    ),
    (VmoObject, HYPER_NATIVE_OBJECT_VMO, "vmo", "memory object"),
    (
        VmarObject,
        HYPER_NATIVE_OBJECT_VMAR,
        "vmar",
        "address-space region"
    ),
    (
        ConsoleObject,
        HYPER_NATIVE_OBJECT_CONSOLE,
        "console",
        "system console"
    ),
    (
        DirectoryObject,
        HYPER_NATIVE_OBJECT_DIRECTORY,
        "directory",
        "filesystem directory"
    ),
    (
        FileObject,
        HYPER_NATIVE_OBJECT_FILE,
        "file",
        "filesystem file"
    ),
    (
        CapabilityChannelObject,
        HYPER_NATIVE_OBJECT_CAPABILITY_CHANNEL,
        "capability-channel",
        "capability rendezvous"
    ),
    (
        ProcessBuilderObject,
        HYPER_NATIVE_OBJECT_PROCESS_BUILDER,
        "process-builder",
        "staged process construction"
    ),
    (
        TaskInspectorObject,
        HYPER_NATIVE_OBJECT_TASK_INSPECTOR,
        "task-inspector",
        "task observation"
    ),
    (
        ObjectInspectorObject,
        HYPER_NATIVE_OBJECT_OBJECT_INSPECTOR,
        "object-inspector",
        "object observation"
    ),
    (
        MemoryInspectorObject,
        HYPER_NATIVE_OBJECT_MEMORY_INSPECTOR,
        "memory-inspector",
        "memory observation"
    ),
    (
        CpuInspectorObject,
        HYPER_NATIVE_OBJECT_CPU_INSPECTOR,
        "cpu-inspector",
        "CPU-time observation"
    ),
    (
        VirtualMachineCreationAuthorityObject,
        HYPER_NATIVE_OBJECT_VIRTUAL_MACHINE_CREATION_AUTHORITY,
        "vm-creation-authority",
        "virtual-machine creation authority"
    ),
    (
        VirtualMachineCreationLeaseObject,
        HYPER_NATIVE_OBJECT_VIRTUAL_MACHINE_CREATION_LEASE,
        "virtual-machine-creation-lease",
        "one-shot virtual-machine construction"
    ),
    (
        PendingVirtualMachineObject,
        HYPER_NATIVE_OBJECT_PENDING_VIRTUAL_MACHINE,
        "pending-virtual-machine",
        "staged virtual-machine construction"
    ),
    (
        VirtualMachineObject,
        HYPER_NATIVE_OBJECT_VIRTUAL_MACHINE,
        "virtual-machine",
        "virtual-machine supervision"
    ),
    (
        VirtualCpuObject,
        HYPER_NATIVE_OBJECT_VIRTUAL_CPU,
        "virtual-cpu",
        "virtual-CPU supervision"
    ),
    (
        VirtualSerialObject,
        HYPER_NATIVE_OBJECT_VIRTUAL_SERIAL,
        "virtual-serial",
        "virtual serial endpoint"
    ),
    (
        WaitSetObject,
        HYPER_NATIVE_OBJECT_WAIT_SET,
        "wait-set",
        "wait registration set"
    ),
    (
        GuestInterruptObject,
        HYPER_NATIVE_OBJECT_GUEST_INTERRUPT,
        "guest-interrupt",
        "exclusive guest interrupt line"
    ),
    (
        GuestMemoryObject,
        HYPER_NATIVE_OBJECT_GUEST_MEMORY,
        "guest-memory",
        "guest physical memory"
    ),
    (
        DeviceAssignmentAuthorityObject,
        HYPER_NATIVE_OBJECT_DEVICE_ASSIGNMENT_AUTHORITY,
        "device-assignment-authority",
        "physical-device assignment authority"
    ),
    (
        PhysicalDeviceObject,
        HYPER_NATIVE_OBJECT_PHYSICAL_DEVICE,
        "physical-device",
        "physical device and its resources"
    ),
    (
        GuestMailboxObject,
        HYPER_NATIVE_OBJECT_GUEST_MAILBOX,
        "guest-mailbox",
        "shared guest communication memory"
    ),
    (
        GuestNotificationObject,
        HYPER_NATIVE_OBJECT_GUEST_NOTIFICATION,
        "guest-notification",
        "guest interrupt notification"
    ),
    (
        NativeBlockObject,
        HYPER_NATIVE_OBJECT_NATIVE_BLOCK,
        "native-block",
        "block device access"
    ),
    (
        GuestMappingObject,
        HYPER_NATIVE_OBJECT_GUEST_MAPPING,
        "guest-mapping",
        "guest address-space mapping"
    ),
    (
        DirectoryStreamObject,
        HYPER_NATIVE_OBJECT_DIRECTORY_STREAM,
        "directory-stream",
        "directory enumeration"
    ),
    (
        RootTransitionObject,
        HYPER_NATIVE_OBJECT_ROOT_TRANSITION,
        "root-transition",
        "reversible namespace publication"
    ),
    (
        FileProtectionObject,
        HYPER_NATIVE_OBJECT_FILE_PROTECTION,
        "file-protection",
        "process-local content protection"
    ),
);

impl ObjectKind {
    pub(crate) fn from_kernel(raw: u32) -> Result<Self> {
        if raw == hyper_abi::HYPER_NATIVE_OBJECT_NONE {
            Err(Error::InvalidResponse)
        } else {
            Ok(Self(raw))
        }
    }

    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Looks up a stable name without accepting misspelled kinds.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::KNOWN.iter().copied().find(|kind| kind.name() == name)
    }
}
