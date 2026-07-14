# Roadmap

## Zig 1.0 `std.Build` stable → decompose sws

Once Zig's package manager (`zig fetch`, `build.zig.zon`, `b.addModule`) stabilizes with 1.0, break the monorepo into three independently versioned, composable crates:

### `sw-core` — network runtime (zero-protocol)

| Component | File(s) |
|-----------|---------|
| io_uring event loop | `http/event_loop.zig` (generic, not HTTP-specific) |
| Fiber | `next/fiber.zig` |
| Next.go / Next.submit | `next/next.zig`, `next/queue.zig` |
| StackPool (O(1) slot pool) | `stack_pool.zig`, `stack_pool_sticker.zig` |
| BufferPool (provided buffers) | `buffer_pool.zig` |
| LargeBufferPool | `shared/large_buffer_pool.zig` |
| RingShared + IORegistry | `shared/ring_shared.zig`, `shared/io_registry.zig` |
| InvokeQueue | `shared/io_invoke.zig` |
| Pipe (push→pull adapter) | `next/pipe.zig` |
| RingSharedClient (outbound TCP) | `shared/tcp_stream.zig` |
| async logger | `async_logger.zig` |
| SPSC ring buffer | `spsc_ringbuffer.zig` |
| Constants | `constants.zig` |

**Dependencies:** Zig std only. No TLS.

**Exported module:** `sw_core` — usable by any io_uring project, regardless of protocol.

### `sw-httpclient` — outbound HTTP/1.1 client

| Component | File(s) |
|-----------|---------|
| HttpClient (fiber-driven) | `client/http_client.zig` |
| RingB (dedicated thread) | `client/ring.zig` |
| TinyCache (keep-alive pool) | `client/tiny_cache.zig` |
| DnsResolver (async UDP) | `dns/resolver.zig`, `dns/cache.zig`, `dns/packet.zig` |
| c-ares adapter | `client/dns.zig` |

**Dependencies:** `sw-core`, TLS (`tls.zig`, optional).

**Exported module:** `sw_httpclient` — standalone io_uring HTTP client for any Zig project.

### `sws` — application server

| Component | File(s) |
|-----------|---------|
| AsyncServer facade | `http/async_server.zig` |
| HTTP/1.1 routing + middleware | `http/http_routing.zig`, `http/middleware_store.zig` |
| HTTP read/write | `http/tcp_read.zig`, `http/tcp_write.zig`, `http/http_parser.zig` |
| HTTP response | `http/http_response.zig`, `http/http_helpers.zig`, `http/http_body.zig` |
| HTTP fiber task | `http/http_fiber.zig`, `http/fiber_task.zig` |
| Context (request model) | `http/context.zig` |
| WebSocket | `ws/` + `http/ws_handler.zig` |
| Raw TCP | `tcp/` + `http/tcp_handler.zig` |
| Raw UDP | `udp/` |
| TCP accept + connection mgr | `http/tcp_accept.zig`, `http/connection_mgr.zig`, `http/connection.zig` |
| Deferred / hook system | `deferred.zig`, `http/hook_system.zig` |
| TLS integration | `tls/` |

**Dependencies:** `sw-core`, `sw-httpclient` (optional, for `HttpClient` in handlers).

**Exported module:** `sws` — full server framework.

### End state

```
zig fetch sw-core
zig fetch sw-httpclient   # optional
zig fetch sws

// build.zig
const sw_core = b.dependency("sw-core", .{}).module("sw_core");
const sw_httpclient = b.dependency("sw-httpclient", .{}).module("sw_httpclient");
const sws = b.dependency("sws", .{}).module("sws");
```

Users who only need the outbound HTTP client no longer pull in the entire server. Users who only need the runtime (for custom protocols) don't pull HTTP routing. Each crate versions independently; breaking changes are scoped.

### Pre-1.0

Keep the monorepo. All internal refactoring (fiber_task rename, SlotPool generalization, buffer pool extraction) happens here to prepare for the split. Back-compat shims may be needed during the transition.

### Zig versions

| Version | Status |
|---------|--------|
| 0.14.0–0.16.0 | Monorepo, `zig build` |
| 1.0 | Split into 3 repos, `zig fetch` |
