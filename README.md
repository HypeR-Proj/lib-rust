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

Unsafe machine interactions are confined to `hyper-sys`. Application code
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

The initial runtime reuses the SDK startup parser and architecture syscall
veneer from `stdlib/hyper`. The startup vector comes from the selected userspace loader;
the kernel only supplies a bootstrap channel, mapping capabilities and opaque
data. The dynamic loader or static CRT initializes a private heap VMAR before
application entry, and
`hyper-rt` installs the `libhyper` process heap as Rust's global allocator.
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
resource domain. See [the C heap contract](https://github.com/HypeR-Proj/libc/blob/main/README.md#process-heap).

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
[Native std guide](https://github.com/HypeR-Proj/lib-std/blob/main/pal/README.md) for the support matrix,
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

`hyper-filesystem::protocol::ReadExtentPlan` describes a bounded prefix using
physical byte offsets within the mount's authorized block volume, including
partial-sector tails. It contains no pointers or writable destination grants.
The kernel validates and executes the plan into its own request/cache pages.
Providers that transform bytes can return `Unsupported` to use buffered reads.
See [block I/O](https://hyper-proj.github.io/lib-block/docs/block-io.html) for copy boundaries,
ordering, failure and quota semantics.

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
