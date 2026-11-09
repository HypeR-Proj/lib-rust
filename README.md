<!--
SPDX-FileCopyrightText: 2026 roolrz
SPDX-License-Identifier: Apache-2.0
-->

# HypeR Rust SDK

This component provides freestanding Rust bindings for applications compiled
directly against the HypeR Native ABI. The crates use `#![no_std]`, make no
Linux or POSIX assumptions, and are installed as source so consumers compile
them with the Rust toolchain selected for the application.

## Crates

| Crate | Responsibility |
| --- | --- |
| `hyper-sys` | Raw syscall, C-runtime, pointer, and handle bindings |
| `hyper-os` | Safe capability-oriented operating-system interfaces |
| `hyper-rt` | Rust application entry, process-heap allocator, panic termination, and exit status |
| `hyper-filesystem` | Bounded filesystem service wire protocol, metadata types |

Raw syscall bindings are confined to `hyper-sys`; `hyper-os` owns the narrowly
scoped unsafe mappings needed to provide typed memory access. Application code
should normally depend only on `hyper-os` and `hyper-rt`. `hyper-os` is an
application-independent semantic layer and keeps Rust standard-library
platform adapters separate from its stable-facing capability interfaces.

Within `hyper-sys`, syscall bindings are grouped by capability family: task,
memory, filesystem, IPC, VM, device, and guest I/O. `ffi.rs` declares the C
runtime veneers, and `startup.rs` owns the startup record layouts. The crate
root explicitly re-exports the raw functions and types used by runtime
consumers.

The safe layer includes bounded byte streams, transactional capability
rendezvous, startup-capability parsing, directory access, physical and emergency
Console access, object waits, and staged Process construction. Rust owners keep
MOVE operations recoverable until the kernel commits them, while typed receive
slots validate object kind and exact rights before publishing a capability to
application code. System-service protocols and helper implementations belong
to their respective bootstrap or formal-system libraries; the SDK imposes no
generic userspace IPC wire envelope.

Capability receive reports `Error::ReceiveRejected` only for a matched transfer
which installed no destination capabilities and retained all sender MOVE owners.
`ReceiveRejection::Capacity` contains the required byte/handle counts;
`ReceiveRejection::Status` preserves the underlying cause. Ordinary `Error::Status`
and local validation errors describe the receiver invocation, endpoint or wait.
A rejected match is not automatically retryable: output-memory faults, exhausted
resources and internal errors require their own policy. After any error, ignore
all output memory; even partially written handle values are not live owners.
ByteChannel size errors remain `Error::MessageTooLarge`.

The initial runtime reuses the SDK startup parser and architecture syscall
veneer from `stdlib/system`. The startup vector comes from the selected userspace loader;
the kernel only supplies a bootstrap channel, mapping capabilities and opaque
data. The dynamic loader or static CRT initializes a private heap VMAR before
application entry, and
`hyper-rt` installs the `libsystem` process heap as Rust's global allocator.
Applications can use `alloc` without implementing an allocator:

```rust
extern crate alloc;

use alloc::{format, string::String, vec::Vec};

let name = String::from("shell");
let message = format!("hello from {name}");
let bytes: Vec<u8> = [b"hyper> ".as_slice(), message.as_bytes()].concat();
```

`hyper_rt::alloc` also re-exports the crate. This provides `String`, `Vec`,
`Box`, collections, `.concat()`, and `format!`; the freestanding mode does not provide `std` or
POSIX APIs. The allocator supports over-aligned Rust layouts and preserves the
original buffer when reallocation fails. Its eight arenas retain at most 512 KiB
of wholly free regions per process. `hyper_os::memory::trim_heap()` (or the
low-level `hyper_sys::allocator::trim()`) releases that idle capacity; thread
detach and allocation failure also trim. Live allocations remain valid.
Use fallible collection APIs such as `try_reserve` where OOM is recoverable;
infallible allocation failure follows Rust's allocation-error path and the
runtime's aborting panic policy. Memory use remains charged to the process's
resource domain. See [the C heap contract](https://github.com/HypeR-Proj/lib-system/blob/main/README.md#process-heap).

`task::ProcessBuilder` stages arguments and environment entries in SDK-owned
memory, then uploads their encoding before `seal()` or `into_handle()`.
Transferring the typed builder therefore also transfers its staged data;
`into_handle()` is fallible. A receiver using `from_handle()` may seal and start
the builder, but cannot append to the sender's local argument list. Successful
`start()` waits for runtime readiness. A kernel syscall failure returns a
recoverable builder; a userspace loading failure after kernel commit produces
`StartFailure::Committed`, requests child stop and waits for termination.
Readiness precedes constructors and application entry.

`hyper-cargo` in freestanding mode rebuilds `core` and `alloc` as PIC for Native PIE linking using
the pinned compiler's `rust-src`. The driver locally enables Cargo's unstable
`build-std` through `RUSTC_BOOTSTRAP=1`; this is a toolchain dependency, not a
stable Rust target support claim. SDK assembly fetches the compiler-library
lockfile's dependencies before offline application builds.

## Build boundary

The source workspace supports formatting, linting, and host-side tests:

```sh
cargo fmt --manifest-path stdlib/rust/Cargo.toml --all -- --check
cargo clippy --manifest-path stdlib/rust/Cargo.toml \
  --workspace --target aarch64-unknown-none --lib -- -D warnings
cargo test --manifest-path stdlib/rust/Cargo.toml -p hyper-os -p hyper-sys
```

Applications do not use source-tree path dependencies. SDK assembly installs
these crates below `share/hyper/rust`, relocates the workspace's ABI dependency
to the installed `share/hyper/abi`, and `bin/hyper-cargo` supplies the
installed paths, target, linker, and PIE model. Repository builds select
Cargo's `--offline` mode; SDK consumers remain free to use separately reviewed
dependencies.

## License

Licensed under the Apache License, Version 2.0. See
[the project license](https://github.com/HypeR-Proj/HypeR/blob/main/LICENSE).

## Standard Rust applications

The SDK now also provides a partial platform port of Rust `std`, including
ordinary `main()`, standard streams, startup arguments, and clap support.
`hyper-cargo` selects this mode by default. Existing `hyper_rt::entry!`
applications select `HYPER_RUST_STD=0`; std applications using this crate
enable its `std` feature and use ordinary `main()`. See the
[Native std guide](https://github.com/HypeR-Proj/lib-rust-std/blob/main/pal/README.md) for the support matrix,
build contract, and Native thread and atomic-wait backend.

Native std programs can call `hyper_rt::process::startup()` once to claim their
non-stream startup capabilities. Standard streams and the bootstrap Console
remain runtime-owned for std cleanup and TLS destructors. Prefer `std::io` for
ordinary I/O. `hyper_rt::process::{stdin_stream,stdout_stream,stderr_stream}`
borrow connector owners; the original `stdin`, `stdout` and `stderr` getters
remain for byte-channel pipes. Use `hyper_os::stream::ProcessInput` for event-driven
stdin so explicit reads and std share one connection and pending request.
`console` remains available only where physical Console authority was delegated.

Native `thread` bindings expose dormant creation, start, stop, typed termination
waits, and process-private `AtomicU32` wait/wake. Raw thread construction and
asynchronous stop require explicit unsafe lifetime contracts. Applications
should prefer `std::thread` and `std::sync` for language-level ownership.
Capability IPC and object waits remain Native APIs: std does not represent
VM control handles or transferable capability channels.


`fs::Directory` provides capability-relative creation/removal; `fs::File`
provides explicit-offset reads/writes, atomic append and resize. WRITE must be
present on the originating Directory before writable File authority can be
opened. Open owners survive unlink. `Directory::reader()` returns a fallible,
independent `DirectoryReader` owning a DirectoryStream handle; it requires only
Directory READ. Each reader retains bounded iteration state rather than cache
pages. Mutations of the scanned remote directory, or renames of it or an ancestor,
invalidate the scan; unrelated directory and file-content changes preserve traversal. Cookies are opaque and bound to their stream.
Prefer `std::fs` when path and stream operations
are sufficient; keep Native handles for explicit delegation and executable
provenance.

`wait::WaitSet` owns up to 1024 persistent one-shot subscriptions. `add` returns
an opaque non-reused registration ID; `wait` returns that ID, observed signals
and sequence. Consume before `rearm`, and use `remove` to cancel. Registration
management requires BIND_WAIT, consumption requires WAIT, and sources require
WAIT. Closing a set removes its subscriptions; source handle closure does not
cancel the retained object observation. WaitSet and CapabilityChannel sources
are currently rejected. ByteChannel endpoints can be explicitly duplicated;
peer close occurs only after the last active endpoint owner closes.
`wait_batch(deadline, &mut [None; N])` consumes up to 64 notifications in one
invocation without heap allocation. It waits only for the first event, then
returns the immediately available prefix; process the first returned-count
`Some` slots and rearm each registration as appropriate. Remaining slots are
`None`. Concurrent consumers or rearm can interleave, so this is not an atomic
snapshot. An already delivered notification can outlive registration removal;
consumers replacing subscriptions must recognize stale IDs. The single-event
`wait` remains available.

Shared process synchronization uses `HandleRef<VmoObject>::wait_u32(offset,
expected, absolute_deadline)` and `wake_u32(offset, count)`, also available on
`WritableVmo`. Identity is the VMO object plus its aligned byte offset, independent
of each process's mapping address. Wait requires READ|WRITE, wake only WRITE;
neither requires MAP. A mismatch returns success without sleeping. After every
successful wait, reload the condition; success does not transfer lock ownership.
Count zero wakes nobody. Closing handles or unmapping does not cancel an admitted
wait; thread cancellation and deadlines release it. Private address-based atomic
waits remain separate.

`memory::SharedAtomicU32Mapping` maps a private child VMAR and exposes checked
`load`/`store`/`compare_exchange` by u32 index without ordinary references to shared memory. Its
constructor and `wait_u32` are unsafe because every concurrent alias must use
aligned, same-width `AtomicU32` accesses; use explicit release/acquire ordering
for application data. Do not mix this layout with the shared queue's u64 words.
Mapping requires READ|WRITE|MAP and current-process VMAR authority. An active
shared wait retains writable admission and backing even after unmap, so ordinary
VMO byte reads/writes, snapshots and new exclusive hardware ownership return BUSY.
Wake does not access backing and can return zero during hardware ownership.

Executable memory requires an explicitly delegated `ExecutableAuthority`;
ordinary applications receive none by default. In `memory`, wrap that startup
handle with `ExecutableAuthority::from_handle`, then `publish(source)` to obtain
an `ExecutableVmo`. Publication copies the whole ordinary writable RAM VMO into
physically distinct immutable backing charged to the caller. It requires
CREATE_EXECUTABLE on the authority and READ on the source; active writable
mappings, shared atomic waits and hardware leases return BUSY. Unmap write views
before publishing. Later writes to the original source cannot change the result.

`unsafe { executable.map(root_vmar) }` reserves an RX child mapping. Its
`base_address()` exposes no safe callable function: the caller remains responsible
for instruction validity, ABI correctness and any accessed memory, and must finish
execution before dropping the mapping. The kernel completes instruction-cache
publication before returning the executable VMO. No operation creates a writable
alias to the executable copy. The VMO and mapping have independent lifetimes.

With the optional `hyper-os/std` feature on HypeR targets,
`hyper_os::fs::File::into_std()` transfers a Native File capability into
`std::fs::File` without reopening or duplicating it. The standard file owns
close, starts at offset zero, and preserves the original rights. Subsequent
I/O uses std; Native capability acquisition and delegation remain explicit.

## Buffered reads and bounded transfers

`fs::ReadAt` describes exact positioned reads and length queries without a
cursor, format, or allocation policy. Native `fs::File` implements it using its
existing READ authority. `fs::BufferedReader` wraps any such source with four
4 KiB buffers for sparse small reads, reducing syscall overhead above the kernel
page cache. It is a local read view, not a snapshot or a coherent shared cache:
create a fresh reader after mutations or hold content protection separately.
`into_inner()` releases all buffers and recovers the source for large transfers.

With `hyper-os/std`, `fs::transfer::copy_range` copies an exact bounded source
range to an arbitrary consumer, overlapping reads and consumption using two
512 KiB buffers and one scoped worker. Small transfers run inline. All source
reads stay within the selected range; the consumer sees relative offsets. Both
callbacks must finish using each borrowed slice before returning. On failure,
already consumed bytes remain committed, channels close and the reader joins
before the call returns. Consumer unwinding also closes channels before joining.
VM loading and ordinary `cp` share this implementation, including its alignment
and cancellation rules. `copy_range_profiled` additionally measures read and
consumer work; those durations overlap and are not total wall time. Ordinary
copies perform no profiling clock reads.

## Filesystem block queues

`block::BlockQueue` derives a bounded logical producer from an exclusive
`NativeBlock` capability. Ordinary `submit_read` / `submit_write` submissions
own their kernel payload until collection; waiting does not consume a result.
`wait_space` waits for one admission slot and an exact payload size without
reserving either. Callers retry submission after waking and collect their
completed tickets to return credits.

Filesystem providers can export one queue-owned source window with
`create_window`. `filesystem::SharedBuffer::from_readonly_memory` returns a
separate `ReadonlyBuffer`; it offers no mutable-slice accessor, and the kernel
rejects writable mappings of the underlying VMO. The provider passes the queue
as `Some(queue)` to `filesystem::mount` alongside its channel and writable
metadata buffer. Non-block providers pass `None` and retain buffered RPC payload
transport with a zero write token; they have no physical-extent authority.
A write RPC supplies an operation token. `submit_window(token, ranges)` refers
to that window through `WindowWrite { first, offset, bytes }` descriptors rather
than copying payload through the provider. All accepted writes must complete
before the provider replies. Invented, expired or out-of-range tokens/ranges
are rejected. Closing a queue does not revoke already mapped readonly storage.

File writes report an accepted input prefix, not a durability guarantee. Short
writes and appends advance by the returned count; retry only the remaining
suffix. A later storage failure remains observable through subsequent operations
or filesystem sync, even when the write returned a nonzero count. A failed
transfer can have indeterminate effects, and gap zero filling can survive an
error; neither case implies rollback or permits blindly replaying an append.

`hyper-filesystem::protocol::ReadExtentPlan` describes a bounded prefix using
physical byte offsets within the mount's authorized block volume, including
partial-sector tails. It contains no pointers or writable destination grants.
The kernel validates and executes the plan into its own request/cache pages.
Providers that transform bytes can return `Unsupported` to use buffered reads.
See [block I/O](https://hyper-proj.github.io/lib-block/docs/block-io.html) for copy boundaries,
ordering, failure and quota semantics.

## Shared file mappings

`file.map_shared(parent, options)` reserves a free child VMAR and creates a
`SharedFileMapping` over existing complete file pages in the calling process.
`unsafe { file.map_shared_at(parent, address, options) }` is the exact-address
variant for callers that already control their virtual-address layout.
It needs File READ, and WRITE for shared writable authority, plus VMAR MAP.
An initially read-only mapping still retains potential WRITE when its source
File has WRITE. Use a READ-only source to avoid that lease and its exclusion of
FileProtection.
The initial implementation requires a provider that delegated periodic writeback
ownership; synchronous FAT providers reject the operation. File-size changes,
conflicting content protection and executable shared access are rejected.
Explicit residency locking and address-keyed atomic wait/wake on shared file
mappings are unsupported; coordination uses separate objects or memory.

Shared mappings and ordinary file reads/writes access the same canonical bytes.
The owner exposes raw pointers, never safe Rust slices: applications must uphold
aliasing, atomic-access and cross-process synchronization requirements. Closing
the original File preserves mapping authority. `sync(SyncScope::Data)` and
`sync(SyncScope::Full)` synchronize through that retained authority; they require
the source File to have carried WRITE at mapping creation. `sync_range` accepts whole pages, while `Volume` is not a range scope. These are file fences,
not unconditional checkpoints or atomic snapshots of concurrent writers.

`try_close` unmaps and destroys the owned region, retaining retry authority on
failure. Drop attempts cleanup once. Neither unmap nor process exit implies
fsync. Faults that cannot be serviced retain the kernel's fatal-fault policy;
normal mapping does not pin pages or extend VMO atomic wait/wake to files.

## Explicit memory residency

`hyper_os::memory::{lock_memory, unlock_memory}` operate on a nonempty,
page-aligned interval of the calling process's VMAR. The corresponding
`lock_current_memory` / `unlock_current_memory` functions select all existing
mappings in the VMAR, including descendants and excluding guard holes. New
mappings are never implicitly locked. Locking populates the selected memory;
a failed transaction leaves existing residency grants unchanged, though reads
may have warmed the file cache.

The VMAR requires `LOCK_MEMORY`, independently of `MAP`. A launcher whose task
factory carries that right can call `ProcessBuilder::set_memory_lock_allowed`
explicitly; it is disabled for newly created builders. Lock quota belongs to
the requesting resource domain. Unmap and process exit release residency;
unlock never cancels another mapping's claim. Shared clean file-backed pages
remain available to other mappings while locked, but COW remains private.
This provides no stable physical address and is separate from device DMA pins.

A service must prepare its dependency closure before announcing readiness if
refaulting could require its own suspended predecessor. That policy belongs to
the service and its configuration, not to the loader or kernel.

## Workspace tests

Use the [HypeR workspace](https://github.com/HypeR-Proj/HypeR) to resolve dependencies:

```sh
python3 project.py test lib-rust
```

Paths in the documentation are relative to the repo-managed workspace root.
Edit this repository and prepare the workspace again before building.

## Stream admission failures

`hyper_os::stream::accept_until` reports `Error::InvalidStreamRequest` when an
admitted peer's connection payload or handle count violates the stream protocol.
The receive's `Error::ReceiveRejected` still identifies a rolled-back matched
transfer. Other errors, including `InvalidResponse` from trusted ABI validation,
retain their original meaning and must not be blindly retried as peer input.

## Byte-channel deadlines

`ByteChannel::send_until` and `receive_until` take an absolute monotonic deadline.
Retries and readiness waits share that deadline. An already expired call does
not send or consume a queued message. Existing `send` and `receive` retain their
unbounded-wait behavior; callers requiring a budget use the explicit methods.

## Shared message queues

`hyper_os::shared_queue` provides bounded SPSC messages over ordinary shared RAM.
Each direction has one producer and one consumer; bidirectional protocols use
one pair per direction. This is a userspace protocol over existing VMO, Event,
ByteChannel and WaitSet capabilities, not a new kernel object or POSIX facility.

Negotiate `VERSION` and `Config` in the surrounding connection protocol. Call
`create_pair`, then transfer the five capabilities in each role's parts before
mapping them. Geometry is fixed locally: 1–1024 slots, 1–65536 bytes per message,
and at most 16 MiB of producer storage. Creation populates backing before
publishing either endpoint. The producer can write only data storage; the
consumer can write only control storage. Each peer maps the other's VMO read-only.
The separate Event capabilities carry readiness, and a ByteChannel is retained
solely for endpoint lifetime. Mappings use private child VMARs.

`Producer::map` and `Consumer::map` are unsafe boundaries: the root must belong
to the calling process, other VMAR authority must not invalidate their mappings,
and every concurrent alias must use aligned atomic u64 accesses at identical
offsets. Each role has one protocol owner. Corrupt indices and lengths cannot
supply an address or overrun a private buffer; arbitrary mixed-width or
non-atomic aliases are outside this Rust memory-model contract. No shared
payload reference escapes the SDK.

`try_send_batch` / `try_receive_batch` return a committed message count plus an
optional stopping reason. Retry only the suffix. In particular, a notification
failure can accompany a nonzero committed count and poisons the endpoint; it
must not cause replay of the prefix. A too-small receive buffer reports the
required size without consuming the head message. `ReceiveSlot::message`
exposes only a successfully consumed private copy. Empty messages are supported.

The nonblocking path queries no lifecycle syscall. On Full or Empty, call the
corresponding `wait_*_until` with one absolute deadline; it handles readiness,
spurious hints, timeout cleanup and peer death. Pure polling can continue to
report Full/Empty after an abrupt peer exit. Publication does not acknowledge
consumption or guarantee that a peer remains alive. `Producer::finish` publishes
a graceful close marker: the consumer drains preceding messages, then receives
Closed. Dropping or terminating a producer without that marker yields PeerDied
when observed, with no guarantee about an unobserved final publication.

The wire layout uses little-endian payload words. Producer words 0/1/2 are
head/space-wait-armed/closed; consumer words 0/1 are tail/data-wait-armed. Both
headers occupy eight words. Each data slot has one length word followed by
`ceil(message_bytes / 8)` payload words. Cursors are monotonic u64 values and
never wrap; exhaustion closes the endpoint. Before sleeping, an endpoint
clears its Event, arms its flag, then rechecks the peer cursor. Cursor publication
and armed checks use a single sequentially consistent order, so both sides
cannot miss each other's publication. Events are scheduling hints, not memory
barriers. Notifications coalesce across each batch and no syscall is issued
when the peer has not armed a wait. This protocol grants no DMA authority and
its endpoint closure is not a device-retirement acknowledgement.

Host tests cover malformed metadata, committed failures, counter exhaustion
and arm/recheck interleavings. The service lifecycle case transfers real roles
between processes and covers backpressure, timer expiry/reuse and both forms
of closure. These tests do not replace physical AArch64 weak-order validation.
