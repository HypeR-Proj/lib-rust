// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Optional protocol observations, independent of message delivery and rights.

use crate::handle::{ByteChannelObject, HandleRef};
use hyper_abi as abi;

/// Explicit causal context. Copy it with a request, never infer it from the
/// previously received message. It is observational data, not a capability.
#[derive(Clone, Copy, Debug)]
pub struct RpcContext {
    generation: u64,
    connection: u64,
    request: u64,
}

/// Best-effort tracing for a `READ|WRITE` endpoint. Construct once per connection:
/// kernels without tracing are probed once and make no per-request trace calls.
/// Instrumented kernels perform one annotation invocation at each boundary.
pub struct RpcTracer<'owner> {
    endpoint: HandleRef<'owner, ByteChannelObject>,
    supported: bool,
    connection: u64,
}

impl<'owner> RpcTracer<'owner> {
    pub fn new(endpoint: HandleRef<'owner, ByteChannelObject>) -> Self {
        let mut tracer = Self {
            endpoint,
            supported: true,
            connection: 0,
        };
        let probe = tracer.call([0; 6]);
        tracer.connection = probe.map_or(0, |result| result[1]);
        tracer.supported = tracer.connection != 0;
        tracer
    }

    /// The ID must be unique among concurrent requests on this connection and
    /// must match the server's explicit protocol ID. Zero emits no annotation.
    pub fn client_begin(
        &self,
        request: u64,
        operation: u64,
        parent: Option<RpcContext>,
    ) -> Option<RpcContext> {
        self.begin(
            abi::HYPER_NATIVE_RPC_TRACE_CLIENT_BEGIN,
            request,
            operation,
            parent,
        )
    }

    /// Begin handling one decoded request, optionally propagating a parent.
    pub fn server_begin(
        &self,
        request: u64,
        operation: u64,
        parent: Option<RpcContext>,
    ) -> Option<RpcContext> {
        self.begin(
            abi::HYPER_NATIVE_RPC_TRACE_SERVER_BEGIN,
            request,
            operation,
            parent,
        )
    }

    /// Record a protocol-defined completion code, including errors. Missing or
    /// stale contexts are ignored; tracing never changes the operation result.
    pub fn client_end(&self, context: Option<RpcContext>, status: u64) {
        self.end(abi::HYPER_NATIVE_RPC_TRACE_CLIENT_END, context, status);
    }

    /// Complete server processing after publishing the reply (or a send error).
    pub fn server_end(&self, context: Option<RpcContext>, status: u64) {
        self.end(abi::HYPER_NATIVE_RPC_TRACE_SERVER_END, context, status);
    }

    fn begin(
        &self,
        phase: u64,
        request: u64,
        detail: u64,
        parent: Option<RpcContext>,
    ) -> Option<RpcContext> {
        let parent = parent.map_or([0; 3], |p| [p.generation, p.connection, p.request]);
        let [generation, connection] =
            self.call([phase, request, detail, parent[0], parent[1], parent[2]])?;
        (generation != 0 && connection != 0).then_some(RpcContext {
            generation,
            connection,
            request,
        })
    }

    fn end(&self, phase: u64, context: Option<RpcContext>, status: u64) {
        if let Some(context) = context
            && context.connection == self.connection
        {
            let _ = self.call([phase, context.request, status, context.generation, 0, 0]);
        }
    }

    fn call(&self, arguments: [u64; 6]) -> Option<[u64; 2]> {
        if !self.supported {
            return None;
        }
        // SAFETY: the borrow retains the endpoint. Scalars grant no authority;
        // the kernel validates READ|WRITE and optional instrumentation support.
        let result =
            unsafe { hyper_sys::byte_channel_trace_rpc(self.endpoint.raw().get(), arguments) };
        (result.status == abi::HYPER_NATIVE_STATUS_OK).then_some([result.value0, result.value1])
    }
}
