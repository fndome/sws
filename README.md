# sws — Single Worker Server

[中文文档](README_CN.md)

`io_uring` based Single Worker Server (HTTP + WebSocket + Raw TCP + UDP) on Linux, in Zig 0.16.0.

## Project Goal

`sws` is not just a `req/s` demo. It is a small Linux-only network runtime built
around Zig, `io_uring`, fibers, explicit buffer ownership, and one IO-thread
event loop. The immediate goal is to make the HTTP/WebSocket/DNS/client paths
correct, measurable, and easy to audit before chasing larger benchmark numbers.

Current scope:

- HTTP/1.1 server: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, JSON/text/html
  responses, request body helpers, middleware, keep-alive boundaries.
- WebSocket: HTTP/1.1 upgrade, frame parse/write, ping/pong/close handling.
- Raw TCP: second listen port, zero-copy byte dispatch, shared `accum_buf`
  buffer reassembly with WebSocket.
- Raw UDP: single fd `IORING_OP_RECVMSG`, slab buffer pool, sync/async
  handler modes via `server.udp()` / `server.udp4Sync()`.
- DNS and outbound HTTP client: async UDP DNS, small TTL cache, keep-alive
  connection reuse.
- Linux + `io_uring` only. TLS/HTTPS/WSS via pure-Zig tls.zig library, bundled in `lib/`.
  Enable with `-Denable-tls=true`.

Performance numbers should be read together with the benchmark mode. The local
self-test is a correctness smoke test: client and server share one machine and
the default benchmark is only `50 x 100` keep-alive requests. Use
`-Doptimize=ReleaseFast` and explicit benchmark environment variables before
comparing throughput:

```bash
zig build -Doptimize=ReleaseFast
SWS_BENCH_CONNS=500 SWS_BENCH_REQS_PER_CONN=1000 ./zig-out/bin/im-bench
```

```
IO thread (io_uring Ring A + fiber):
  ├── accept/read/write CQE → fiber → handler → respond
  ├── drain user SubmitQueues
  ├── drain Next.go() ringbuffer tasks
  ├── drain DeferredResponse / InvokeQueue → respond
  ├── drainTick (DNS tick + invoke.drain + tick_hooks)
  └── TTL incremental scan (StackPool live list)

Worker pool (optional, offload CPU/GPU/blocking I/O):
  └── Next.submit() → worker thread → compute → InvokeQueue → IO thread drains
```

Handlers run as **fibers on the IO thread** by default.
- `Next.go()` — fiber on IO thread, zero thread switch. Use for DB io_uring, async I/O.
- `Next.submit()` — worker pool. Use **only for CPU-intensive computation** that would block.

## Concurrency Model (Must Read Before Code Review)

sws is a **single-threaded** system with explicit handoff points. This is the
single most important fact about the codebase. Internalizing it prevents an
entire class of false bug reports.

### The One Rule

```
IO thread owns everything. Worker threads own nothing except their own stack.

IO thread ──[submit]──→ mutex queue ──→ worker pops task
Worker    ──[invoke]──→ CAS list    ──→ IO thread drains next tick
              ↑                           ↑
         one-way handoff             one-way handoff
```

There is **no shared mutable state** between the IO thread and worker threads.
They communicate only through two unidirectional handoff queues.

### Code Review Checklist

- **Do NOT add atomics.** `@atomicStore`, `@cmpxchgStrong`, `@atomicLoad` have
  no place in IO-thread-only data paths. They don't protect anything (there is
  no concurrent access) and actively mislead future readers into thinking
  multi-threaded access exists. Use plain `field = value` / `if field != 0`.

- **Do NOT add mutexes** to IO-thread data structures (StackSlot, Connection,
  BufferPool, LargeBufferPool, DnsResolver, WsServer). They are accessed by
  exactly one thread.

- **WorkerPool internals** (`stack_freelist`, `stack_pool`) are shared among
  workers. With the default `initPool4NextSubmit(1)`, there is exactly one
  worker — no concurrency. The race only exists with `n > 1`.

- **The `Next.go()` ringbuffer** (`SubmitQueue`) is IO-thread push, IO-thread
  pop (`drainNextTasks`). Single-threaded despite the "SPSC" name.

- **`shared_fiber_active`** is read and written only by the IO thread. No
  atomic needed. The per-task-stack wrappers (`httpTaskCleanup`,
  `wsTaskCleanup`) do not touch it.

- **When auditing code**, start by verifying which execution context each
  piece of data lives in. If both ends are in the IO thread, any concern
  about "thread safety" is a false alarm. If a worker thread touches it,
  trace the handoff — is it through `submit()` (mutex) or `invoke.push()`
  (CAS)? If neither, it's a bug.

### Common Mistakes in Past Audits

| Mistake | Why Wrong |
|---------|-----------|
| "`shared_fiber_active` should be atomic" | IO thread only. No other thread reads or writes it |
| "`LargeBufferPool.freelist_top` needs a lock" | IO thread only. Worker never touches this pool |
| "`ensureWriteBuf` races with `submitWrite`" | Both run on IO thread, sequentially |
| "`ConnState` transitions need atomics" | IO thread only. State changes happen in event loop order |

## Critical Usage Warning

**Never perform filesystem reads or writes through the kernel block layer in
handler code.** The IO thread's io_uring event loop runs on a single thread.
Any operation that blocks the calling thread will stall the entire server,
including all active connections.

### Storage Backends You Must NOT Use via File I/O

These backends route I/O through the kernel block layer and will block the IO
thread, even when mounted as a local path:

- **FUSE** — any filesystem mounted via FUSE (s3fs, gcsfuse, etc.)
- **Longhorn v1** — kernel iSCSI initiator → engine → replica; synchronous
  replication quorum inside the kernel I/O path
- **Ceph RBD (kernel)** — kernel block device waits for OSD acknowledgements
- Any network-attached block device mounted through the standard kernel
  filesystem stack (NFS, iSCSI, DRBD with synchronous mode)

### Storage Backends That Are Safe

- **local_pv** — directly attached NVMe/SSD with low-latency page cache writes
- **SPDK-based user-space storage** — storage engines that bypass the kernel
  block layer entirely using polled-mode NVMe drivers and vhost-user shared
  memory. Examples: **OpenEBS Mayastor**, Longhorn v2 (SPDK backend).

SPDK storage is safe because the I/O path never enters the kernel — data moves
DMA-direct from NVMe to user-space ring buffers, and the polled-mode driver
never blocks the calling thread.

### For Remote Object Storage

Use **non-blocking network sockets at the io_uring level** — issue `OP_SEND` /
`OP_RECV` to the remote API endpoint directly:

```
handler → OP_SEND/OP_RECV → S3/OSS/MinIO HTTP API
           ↑ io_uring native, non-blocking
```

Do NOT mount S3/OSS via FUSE and read/write files.

## Requirements

- Linux 5.1+ (io_uring)
- Zig 0.16.0

## Quick Start

```bash
git clone https://github.com/fndome/sws
cd sws
zig build run
```

## Use as a Library

```zig
const sws = @import("sws");

pub fn main() !void {
    var server = try sws.AsyncServer.init(alloc, io, "0.0.0.0:9090", null, 0);
    defer server.deinit();

    server.GET("/hello", myHandler);
    try server.run();
}
```

## Architecture

### Source Layout

```
src/
├── root.zig            (116)  public API — init, handlers, hooks, Next
├── deferred.zig        ( 39)  DeferredResponse — send JSON/text from any thread
├── constants.zig       ( 31)  shared constants
├── antpath.zig         ( 79)  ant-style path matching (/user/*)
├── async_logger.zig    ( 98)  async ring-buffer logger
├── buffer_pool.zig     (182)  tiered write buffer pool (8 size classes)
├── stack_pool.zig      (299)  O(1) pre-allocated connection slot pool
├── stack_pool_sticker.zig (362) CQE dispatch sticker for StackPool
├── spsc_ringbuffer.zig (193)  SPSC queue for Next.go() tasks

src/http/               (5787 lines)
├── async_server.zig    (819)  facade — init/deinit + public API forwarding
├── event_loop.zig      (448)  run / dispatchCqes / drain* / TTL
├── http_routing.zig    (618)  use / GET/POST / processBodyRequest + fiber dispatch
├── http_response.zig   (182)  respond / respondJson / respondZeroCopy
├── http_fiber.zig      (215)  HttpTaskCtx + httpTaskExec/Cleanup/Complete
├── http_body.zig       (202)  submitBodyRead / onBodyChunk / onStreamRead
├── http_parser.zig     (152)  incremental HTTP parser
├── http_helpers.zig    (210)  request parsing utilities
├── ws_handler.zig      (611)  tryWsUpgrade / onWsFrame / sendWsFrame / write queue
├── fiber_task.zig      ( 71)  fiber task context (shared by WS + raw TCP)
├── tcp_handler.zig     (265)  onTcpAcceptComplete / onRawData / sendTcp
├── tcp_accept.zig      (167)  onAcceptComplete / allocFixedIndex
├── tcp_read.zig        (759)  submitRead / onReadComplete (header parse + body route)
├── tcp_write.zig       (342)  submitWrite / onWriteComplete
├── connection_mgr.zig  (168)  closeConn / getConn / nextUserData
├── connection.zig      ( 78)  Connection type
├── hook_system.zig     ( 59)  DeferredNode / addHook* / sendDeferredResponse
├── context.zig         (381)  Context type + ResponseBuilder chain API
├── types.zig           (  7)  Middleware / Handler types
└── middleware_store.zig( 33)  MiddlewareStore

src/next/               (1183 lines)
├── next.zig            (603)  Next.go / Next.submit / worker pool + tick
├── fiber.zig           (206)  x86_64/ARM64 fiber implementation
├── pipe.zig            (179)  push-to-pull adapter for sync-protocol libs
├── chunk_stream.zig    (130)  chunked transfer stream
└── queue.zig           ( 65)  lock-free invoke queue

src/ws/                 (651 lines)
├── frame.zig           (254)  WebSocket frame parse/write + masking
├── upgrade.zig         (212)  HTTP → WS upgrade handshake
├── server.zig          (159)  WebSocket server registry
└── types.zig           ( 26)  WebSocket types

src/client/             (1832 lines)
├── http_client.zig    (1209)  HttpClient — dedicated-thread, fiber-driven HTTP client
├── ring.zig           ( 152)  RingB — io_uring ring + DNS + TinyCache + InvokeQueue
├── tiny_cache.zig     ( 273)  per-host keep-alive connection pool
├── dns.zig            ( 198)  c-ares async DNS adapter
└── README.md                 → [Why sws ships its own io_uring HTTP client](src/client/README.md)

src/dns/                (991 lines)
├── resolver.zig       (339)  io_uring async UDP DNS resolver
├── packet.zig         (452)  DNS packet builder/parser
└── cache.zig          (200)  TTL DNS cache

src/shared/             (955 lines)
├── tcp_stream.zig     (654)  RingSharedClient — io_uring outbound TCP client
├── large_buffer_pool.zig (108) 64 × 1MB pre-allocated blocks
├── io_registry.zig    ( 84)  client fd callback registry
├── ring_shared.zig    ( 55)  RingShared — single ring + registry + invoke
└── io_invoke.zig      ( 54)  cross-thread CAS callback queue

src/tls/                (340 lines)
├── tls.zig            (235)  TLS 1.3 integration via lib/tls.zig
└── noop.zig           (105)  TLS no-op stub (plaintext mode)

src/udp/                (294 lines)
├── server.zig         (203)  UdpServer — init/bind/send, sync/async handler modes
├── buffer.zig         ( 75)  UdpBufferPool — slab buffer pool
└── types.zig          ( 16)  SenderAddr + UdpHandler type

src/dev/                (548 lines)
├── server.zig         (314)  development server with auto-restart
├── compat.zig         ( 87)  platform compatibility layer
├── io.zig             ( 15)  IO abstraction interface
├── io_win.zig         ( 74)  Windows IO backend
└── io_posix.zig       ( 58)  POSIX IO backend

src/tcp/                ( 53 lines)
├── server.zig         ( 52)  TcpServer — handler registry + send API
└── types.zig          (  1)  TcpHandler type
```

Total: **~14,255 lines** across 64 source files.


The entire event loop runs on **one IO thread**. Handlers execute as **fibers** (user-space coroutines) on the same thread.

```
IO thread (single):
  io_uring.submit_and_wait(1)
    → CQE dispatch (via StackPool sticker)
    → fiber → handler → ctx.text/json/html
    → drainPendingResumes (fiber resume queue)
    → drainNextTasks (Next.go ringbuffer tasks)
    → drainTick (DNS tick + invoke.drain + tick_hooks)
    → TTL scan (StackPool live list, incremental)
    → TTL scan (StackPool live list, incremental)
    → loop
```

No background threads unless you call `server.initPool4NextSubmit(n)`.

### StackPool — O(1) connection pool

Connections are stored in a **pre-allocated array** (not a hash map). O(1) acquire/release via freelist.

```
StackPool<StackSlot, 1_048_576>
  ├── slots: [1M]StackSlot — contiguous, cache-line-aligned
  ├── freelist: [1M]u32 — O(1) pop/push
  ├── live: []u32 — active slot indices (TTL scan source)
  └── warmup() — touch all pages to eliminate cold-start faults
```

#### StackSlot (384 bytes, 5 cache lines)

Each connection slot is split across independent cache lines for contention-free hot-path access:

```
line1 ( 64B): fd, gen_id, state, write_offset, req_count — CQE dispatch (hottest)
line2 ( 64B): conn_id, last_active_ms, active_list_pos — TTL scanning
line3 ( 64B): fiber_context, large_buf_ptr — async anchors, Worker Pool, oversized body
line4 (128B): writev_in_flight, response_buf, write_iovs, ws_write_queue — write path (low frequency)
line5 ( 64B): sentinel (0x53574153) + workspace union — HTTP/WS/Compute view
```

**Ghost event defense:** `user_data = (gen_id << 32) | idx`. After close, gen_id is zeroed. Any in-flight CQE arriving after close fails the gen_id match and is silently discarded.

**Workspace switching:** The `line5.ws` union switches between `HttpWork`, `WsWork`, and `ComputeWork` views depending on connection state — no heap allocation for protocol parsing state.

### Ring A + Dedicated Thread for Outbound

**Ring A** (built-in): the main server's `io_uring` ring — accept, connection read/write, DNS, invoke.

**Outbound rings** (Ring B, HTTP client): each runs on its own dedicated OS thread with its own `io_uring` ring. The IO thread is never interrupted for outbound I/O. See [src/client/README.md](src/client/README.md) for why the HTTP client is built-in.

```
Ring A (main server, IO thread):
  ├── accept / read / write / close
  ├── io_registry (client callbacks)
  ├── dns_resolver (async UDP DNS)
  └── rs.invoke (cross-thread push → IO thread callback)

Ring B (HTTP client, dedicated thread):
  ├── ring.submit_and_wait(1)
  ├── tick → dns.tick + invoke.drain + copy_cqes + dispatch
  ├── IORegistry
  ├── DnsResolver
  ├── InvokeQueue
  └── TinyCache (per-host keep-alive pool)
```

### Init

```zig
var server = try AsyncServer.init(alloc, io, "0.0.0.0:9090", app_ctx, fiber_stack_size_kb);
//                                                                    ↑ 0 = 256KB
```

First handler/middleware registration calls `ensureNext()` → creates `Next` (ringbuffer) + `setDefault()`.

Internally, `AsyncServer.init()` creates:
- `pool`: StackPool — O(1) contiguous connection array
- `large_pool`: LargeBufferPool(64) — 64 × 1MB blocks for oversized requests (>32KB)
- `rs`: RingShared — single ring shared resource (ring + registry + invoke)
- `io_registry`: IORegistry — outbound client connection registry
- `dns_resolver`: DnsResolver — async UDP DNS with TTL cache

To add the built-in HTTP client:

```zig
// RingB with 1s built-in TinyCache TTL:
var ring_b = try sws.HttpRing.init(alloc, io, server.ring.fd, 1000);
defer ring_b.deinit();

// HttpClient auto-uses RingB's TinyCache — keep-alive, zero-config
var http_client = try sws.HttpClient.init(alloc, &ring_b);
try http_client.start(); // spawn dedicated ring thread
defer http_client.deinit();
```

### Handler — Synchronous (on IO thread)

```zig
fn hello(allocator: Allocator, ctx: *Context) anyerror!void {
    ctx.text(200, "hello");
}
```

### Handler — `Next.go` (fiber, IO thread, no thread switch)

For async I/O (DB io_uring, HTTP client):

```zig
const Ctx = struct { allocator: Allocator, resp: *DeferredResponse };

fn exec(c: *Ctx, complete: *const fn (?*anyopaque, []const u8) void) void {
    defer c.allocator.destroy(c);
    defer c.allocator.destroy(c.resp);
    c.resp.json(200, "[{\"id\":1}]");
    complete(c, "");
}

fn myHandler(allocator: Allocator, ctx: *Context) anyerror!void {
    const s: *AsyncServer = @ptrCast(@alignCast(ctx.server.?));
    const resp = try allocator.create(DeferredResponse);
    resp.* = .{ .server = s, .conn_id = ctx.conn_id, .allocator = allocator };
    ctx.deferred = true;
    Next.go(Ctx, .{ .allocator = allocator, .resp = resp }, exec);
}
```

### Handler — `Next.submit` (worker pool, thread switch)

For offload work (crypto, compression, LLM/GPU inference, blocking I/O):

```zig
const Ctx = struct { allocator: Allocator, resp: *DeferredResponse };

fn exec(c: *Ctx, complete: *const fn (?*anyopaque, []const u8) void) void {
    defer c.allocator.destroy(c);
    defer c.allocator.destroy(c.resp);
    // Offload work here (CPU/GPU/blocking I/O)...
    c.resp.json(200, "{\"done\": true}");
    complete(c, "");
}

fn myHandler(allocator: Allocator, ctx: *Context) anyerror!void {
    const s: *AsyncServer = @ptrCast(@alignCast(ctx.server.?));
    const resp = try allocator.create(DeferredResponse);
    resp.* = .{ .server = s, .conn_id = ctx.conn_id, .allocator = allocator };
    ctx.deferred = true;
    Next.submit(Ctx, .{ .allocator = allocator, .resp = resp }, exec);
}
```

### Worker pool (for Next.submit)

```zig
try server.initPool4NextSubmit(1); // 1 worker thread (recommended)
```

**Recommendations:**
- `1` — default, sufficient for crypto, compression
- `N/2` (e.g. 4 on 8-core) — sustained LLM/GPU inference or blocking I/O

### DeferredResponse

Sends HTTP response from any thread (CAS-based lock-free):

```zig
resp.json(200, "{\"ok\":true}");
resp.text(200, "plain");
```

### Deferred Hooks, Tick Hooks

Execute custom logic before each deferred response is sent, on the IO thread.
Essential for MMORPG / real-time use cases (update game state, leaderboard, broadcast):

```zig
fn updateGameState(server: *AsyncServer, node: *DeferredNode) void {
    const world: *GameWorld = @ptrCast(@alignCast(server.app_ctx.?));
    world.update(node.body);
}

try server.addHookDeferred(updateGameState);
```

**Rules:**
- Hooks run in registration order on the IO thread — safe for IO-thread-exclusive data
- `node.body` is valid during hook execution; do NOT free it
- Do NOT store `node` pointer — the node is destroyed after the hook returns
- Must not panic (log errors instead)

#### Room Auto-Battle Example

Rooms with countdown → auto-battle for hundreds of players. Two hooks cooperate:
`addHookTick` checks deadlines every loop iteration (no deferred node needed);
`addHookDeferred` processes incoming player commands.
Battle CPU work offloaded via `Next.submit`. Zero locks — all state on IO thread.

```zig
const Room = struct {
    id: u64,
    state: enum { waiting, fighting, settle },
    deadline: i64,                  // monotonic timestamp
    teams: [2]std.ArrayList(*Player),
};

const Player = struct { id: u64, hp: u32, atk: u32 };

const BattleCtx = struct {
    blue_team: []PlayerSnapshot,
    red_team:  []PlayerSnapshot,
};

const PlayerSnapshot = struct { hp: u32, atk: u32 };
```

```zig
fn roomTick(server: *AsyncServer) void {
    const app: *GameApp = @ptrCast(@alignCast(server.app_ctx.?));
    for (app.rooms.items) |*room| {
        if (room.state == .waiting and server.monotonic_ms() >= room.deadline) {
            room.state = .fighting;
            startBattle(server, room);
        }
    }
}

fn roomCommand(server: *AsyncServer, node: *DeferredNode) void {
    const app: *GameApp = @ptrCast(@alignCast(server.app_ctx.?));
    app.processCommand(node.body);  // join / ready / action
}

fn startBattle(server: *AsyncServer, room: *Room) void {
    const ctx = server.allocator.create(BattleCtx) catch return;
    ctx.blue_team = snapshotTeam(&room.teams[0], server.allocator) catch return;
    ctx.red_team  = snapshotTeam(&room.teams[1], server.allocator) catch return;
    Next.submit(BattleCtx, ctx, doBattle);
}

fn doBattle(ctx: *BattleCtx, complete: *const fn (?*anyopaque, []const u8) void) void {
    const result = simulateCombat(ctx.blue_team, ctx.red_team);
    var buf: [4096]u8 = undefined;
    const json = result.toJson(&buf);
    server.sendDeferredResponse(room_id, 200, .json, json);
    _ = complete;
}

try server.addHookTick(roomTick);        // tick: fires every IO loop
try server.addHookDeferred(roomCommand); // deferred: fires per-player command
```

### Next.go / Next.submit

```zig
Next.go(Ctx, ctx, exec);       // fiber on IO thread (io_uring I/O)
Next.submit(Ctx, ctx, exec);   // worker pool (offload work)
```

Both are static. `Next.go` works out of the box (auto `setDefault` on first route). `Next.submit` requires `server.initPool4NextSubmit(n)`.

#### GPU / Heavy Compute

GPU compute uses `Next.submit` — worker thread calls CUDA / CANN / Vulkan runtime.
io_uring direct dispatch for GPU is blocked on Linux kernel drivers (missing
`IORING_OP_URING_CMD` for compute queues, NVIDIA / Huawei not yet shipped).

Once drivers add it, `IORegistry` handles GPU with zero code changes —
same `register(id, ptr, on_cqe)` → submit SQE → dispatch CQE pattern.

**Current: fiber + worker pool**

Worker pool always supports fiber. GPU task calls `Fiber.workerYield(poll, ctx)`
after submitting a kernel, freeing the worker thread to process other tasks while
the GPU runs. The worker tick polls parked fibers and resumes when the kernel completes.

```zig
// CPU task — no yield, runs to completion
Next.submit(CpuCtx, ctx, struct {
    fn exec(c: *CpuCtx, complete: ...) void {
        const result = heavyCompute(c.input);
        complete(c, result);
    }
}.exec);

// GPU task — MUST call workerYield after submitting kernel
//                                 ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
Next.submit(GpuCtx, ctx, struct {
    fn exec(c: *GpuCtx, complete: ...) void {
        cudaLaunchKernel(kernel, stream, args);
        Fiber.workerYield(            // ← THIS LINE makes it a GPU task
            struct { fn poll(s: *anyopaque) bool {
                return cuStreamQuery(@ptrCast(@alignCast(s))) == CUDA_SUCCESS;
            }}.poll,
            @ptrCast(stream),
        );
        // resume point — GPU done
        complete(c, output);
    }
}.exec);
```

**The only difference between CPU and GPU:** GPU tasks call `Fiber.workerYield`.
Without it, the worker thread blocks synchronously until the kernel completes,
defeating fiber multiplexing.

> ⚠️ **GPU tasks MUST use `Next.submit`, never `Next.go`.**
>
> `Next.go` runs on the IO thread. Two failure modes:
> - **Without `workerYield`:** `cuStreamSynchronize` blocks the IO thread —
>   io_uring CQE processing stops, entire server freezes.
> - **With `workerYield`:** fiber yields correctly, IO thread stays alive — but
>   the fiber never wakes up. The IO thread has no poll tick; it only responds to
>   io_uring CQEs. GPU kernels don't produce CQEs, so the IO thread never learns
>   the kernel finished.
>
> Worker threads have a built-in poll tick (`while poll_fn() try resume`) which
> is why GPU works there: `workerYield` → park → tick → poll → resume.

**IMPORTANT: GPU uses `initPool4NextSubmit(1)`.**
GPU drivers are async internally — one worker + fiber can submit N streams
and poll for completion. No extra thread pool needed. io_uring not yet
supported for GPU compute (kernel driver gap).

### RingShared

`RingShared` is the materialization of a single io_uring ring — injected into server and any outbound client, all equal. The ring is driven by one thread per owner (server `run()`, client `runClientThread`), but SQEs may also be submitted from setup threads (e.g. `cs.connect()` in `main()`), so there is no single-thread assertion.

```zig
const rs = server.rs;  // { ring, registry, invoke }
// Any client is injected equally:
var client = try RingSharedClient.init(alloc, rs, ...);
var http   = try HttpClient.init(alloc, ring_b, cache);
```

- `rs.ringPtr()` / `rs.registryPtr()` — plain accessors (the ring is shared across
  submit/drive threads; no single-thread assertion)
- `rs.invoke.push()` — any-thread-safe CAS callback (worker → IO thread)

### RingSharedClient

io_uring-driven outbound TCP client. Glue layer for integrating NATS / Redis / HTTP client
libraries into sws's IO thread — no separate runtime, no locks.

```zig
const RingSharedClient = @import("sws").RingSharedClient;

fn onData(ctx: ?*anyopaque, data: []u8) void {
    const nats: *NatsClient = @ptrCast(@alignCast(ctx));
    nats.feed(data);
}

fn onClose(ctx: ?*anyopaque) void {
    const nats: *NatsClient = @ptrCast(@alignCast(ctx));
    nats.discard();
}

// In main(), before server.run():
var cs = try RingSharedClient.init(allocator, server.rs, onData, onClose, nats_ctx);
defer cs.deinit();
try cs.connect("127.0.0.1", 4222);

// Send data (queued, submitted via io_uring)
try cs.write("PUB subject 5\r\nhello\r\n");
cs.close();  // graceful
```

- All I/O on sws IO thread — `onData` / `onClose` run in the same context as hooks
- `write()` queues data; pending writes auto-flushed as io_uring CQEs arrive
- Protocol layer (NATS / Redis / HTTP) only needs `feed([]u8)` and `write([]const u8)`
- Multiple clients per server; user_data uses a dedicated high bit to avoid collisions

### TinyCache (built into RingB)

Single-entry TTL connection cache for outbound protocols. **Owned by RingB** — all
lifecycle (init, tick, evict, deinit) is managed automatically. Users get connection
reuse for free with `HttpClient`.

- Same host:port connections auto-reused within TTL window
- Expired entries auto-evicted by `RingB.tick()` each event loop iteration
- Connect phase allows retries; read/write phase forbids retries (kernel TCP stack guarantees SQE-level writes)

### Pipe

Adapts RingSharedClient's push model to a pull model (`reader.read` / `writer.write`).
Enables synchronous-protocol libraries (pgz, myzql) to run directly on the IO thread
via fiber yield/resume — no worker threads, no locks.

```zig
// In main(), after AsyncServer.init() and before server.run():
const Pipe = @import("sws").Pipe;
const RingSharedClient = @import("sws").RingSharedClient;

fn onData(ctx: ?*anyopaque, data: []u8) void {
    const p: *Pipe = @ptrCast(@alignCast(ctx));
    p.feed(data) catch {};
}

fn onClose(ctx: ?*anyopaque) void {
    const p: *Pipe = @ptrCast(@alignCast(ctx));
    p.reset();
}

var cs = try RingSharedClient.init(allocator, server.rs, onData, onClose, &pipe);
var pipe = try Pipe.init(allocator, cs);
defer pipe.deinit();

try cs.connect("localhost", 5432);
// ... wait for connect (yield) ...

// Any protocol lib with anytype reader/writer works:
// var conn = try pgz.Connection.init(allocator, pipe.reader(), pipe.writer());
// var result = try conn.query("SELECT 1", struct { u8 });
```

- `feed(data)` pushes bytes from ClientStream → read buffer, resumes waiting fiber
- `reader.read()` blocks the fiber (via yield) until data arrives — looks synchronous to caller
- `writer.write()` queues into buffer; `flushWrite()` sends via ClientStream
- `reset()` clears buffers on disconnect/reconnect
- Requires protocol library to accept `anytype` reader/writer (pgz needs 1-line patch on `WriteBuffer.send`)

### LargeBufferPool

For oversized requests (Content-Length > 32KB) that can't fit in the 256KB shared fiber stack.
Pre-allocated 1MB blocks with O(1) freelist acquire/release. Each block carries an atomic
**IDLE/BUSY state** — release is idempotent via CAS, preventing double-free from io_uring
kernel retries or TTL-close vs. CQE-collision paths.

```zig
const LargeBufferPool = @import("sws").LargeBufferPool;

// 64 blocks × 1MB = 64MB — built into AsyncServer by default
// Usage in oversized body path:
const buf = self.large_pool.acquire() orelse return error.OutOfLargeBuffers;
// io_uring READ CQE writes directly to buf.ptr
// ... process body ...
self.large_pool.release(buf);
```

### IO_QUANTUM — Next task fairness

`drainNextTasks` is capped at 64 tasks per event loop iteration (`IO_QUANTUM`). This prevents
depth-first starvation: when a handler's `Next.go()` spawns new tasks, they don't preempt
the remaining ReadyQueue entries or CQE harvesting. P99 tail latency stays uniform under load.

### HttpRing + HttpClient (Ring B)

Independent io_uring Ring B for outbound HTTP client. Shares the kernel io-wq thread pool
via `IORING_SETUP_ATTACH_WQ`. **TinyCache is built into RingB** — same host:port connections
are automatically reused within the TTL window and evicted by `RingB.tick()`.

```zig
const sws = @import("sws");

// Ring B init (attached to server's Ring A io-wq, 1s cache TTL):
var ring_b = try sws.HttpRing.init(allocator, io, server.ring.fd, 1000);
defer ring_b.deinit();

// HttpClient — cache is automatically managed by RingB:
var http_client = try sws.HttpClient.init(allocator, &ring_b);
try http_client.start(); // spawn dedicated thread
defer http_client.deinit();

// Use from handler:
const resp = try http_client.get("http://api.example.com/data");
defer resp.deinit();

// POST with body:
const resp2 = try http_client.post("http://api.example.com/submit", "{\"key\":\"val\"}");
```

#### c-ares async DNS (optional)

Built-in `DnsResolver` covers basic needs (A record + TTL cache). For truncated UDP (TC bit → TCP retry) or SRV records, switch to c-ares:

```bash
sudo apt install libc-ares-dev
```

Add to `build.zig`:
```zig
exe.linkSystemLibrary("cares");
```

Switch DNS backend:
```zig
const HttpCaresDns = sws.HttpCaresDns;
// ring.dns = HttpCaresDns.init(alloc, ring.rs);
```

### Fiber

Built-in fiber (x86_64 and ARM64 Linux). All handler fibers share a **single pre-allocated stack buffer** (stored in `AsyncServer.shared_fiber_stack`, default 256KB) — sequential execution, no per-request stack allocation, zero contention.

> ⚠️ **Do NOT use `std.Io.async()` / `future.await()` in handlers.**
>
> Zig's `Future` is a **thread-based** design, not fiber-based:
> - `async()` → `std.Thread.spawn` + queued to OS thread pool (`Threaded.zig:2112`)
> - `await()` → `Thread.futexWait` — blocks the **OS thread** (`Threaded.zig:2436`)
>
> On the IO thread, blocking means:
> - io_uring CQE processing stops — no new connections, no reads, no writes
> - The entire server stalls for the duration of the work
>
> ### Why not patch the vtable to support Future on fibers?
>
> `future.await()` requires the caller's **stack frame to persist** across suspension:
> ```
> var future = io.async(work, .{data});
> const result = future.await(io);   // fiber yields here — stack must survive
> ctx.json(200, result);              // resumes here — expects data still intact
> ```
>
> SWS uses a **shared stack** (one 256KB buffer, all fibers reuse it). When a fiber
> yields in `await()`, the next fiber's execution overwrites that same memory. The
> resumed fiber's stack frame is corrupted.
>
> Switching to per-fiber stacks would fix this, but at a steep memory cost:
>
> | Concurrent requests | Per-fiber stack | Shared stack |
> |---|---:|---:|
> | 1K | 16 MB | 256 KB |
> | 20K | 320 MB | 256 KB |
> | 200K | 3.2 GB | 256 KB |
> | 1M | 16 GB | 256 KB |
>
> *(per-fiber stack at 16KB — the practical minimum for HTTP handlers)*
>
> At a typical production load of 200K concurrent requests, shared stack saves ~3GB.
> This directly translates to lower memory pressure and better operational stability.
>
> This is the fundamental tradeoff: **Future API semantics vs. 1M-connection memory model**.
> SWS chooses the latter. All async is done via `Next.go`/`Next.submit` with callbacks
> instead of `await`-style suspension.
> - Fibers are cooperative; OS threads are preemptive. This breaks the fiber model.
>
> | Zig pattern | SWS replacement |
> |---|---|
> | `io.async(cpuWork)` + `future.await(io)` | `Next.submit(Ctx, ctx, exec)` + `DeferredResponse` |
> | `io.async(ioWork)` + `future.await(io)` | `Next.go(Ctx, ctx, exec)` (fiber on IO thread) |
>
> **Pattern**:
> ```zig
> // ❌ Don't do this in handler — blocks IO thread:
> // var future = io.async(heavyWork, .{data});
> // const result = future.await(io);
>
> // ✅ Do this instead — IO thread never blocks:
> fn myHandler(allocator: Allocator, ctx: *Context) anyerror!void {
>     ctx.deferred = true;
>     const resp = try allocator.create(DeferredResponse);
>     resp.* = .{ .server = server, .conn_id = ctx.conn_id, .allocator = allocator };
>     Next.submit(Ctx, .{ .resp = resp, .data = data }, exec);
> }
> ```
>
> See `Next.submit` section above for the full exec/complete callback API.

### Routing / Middleware / WebSocket / Context

See `example/` and `src/example.zig`.

## Memory Model (1M connections target)

| Component | Size | Notes |
|-----------|------|-------|
| StackSlot (per connection) | 384 bytes | 5 cache-line-aligned sub-structures |
| StackPool (1M slots) | ~384 MB | contiguous, warmup-touched |
| Connection hashmap (1M entries) | ~160 MB | AutoHashMap(u64, Connection) |
| Freelist + live list | ~8 MB | 2 × [1M]u32, O(1) acquire/release |
| Read buffer (idle) | 0 bytes | io_uring provided buffers, returned on idle |
| Slab for io_uring reads | 64 MB | 16384 × 4KB blocks, kernel-recycled |
| Tiered write pool | dynamic | 8 size classes (512B–64KB), freelist-recycled |
| Shared fiber stack | 256 KB | All fibers share one pre-allocated stack |
| LargeBufferPool | 64 MB | 64 × 1MB blocks for oversized requests |
| **1M idle connections** | **~680 MB** | No per-thread stack overhead |

Like [greatws](https://github.com/antlabs/greatws), idle connections consume zero buffer memory.

### Cache-line layout rationale

The 384-byte StackSlot is split across independent cache lines:

- **line1 (64B):** fd, gen_id, state, write_offset — only this is touched during CQE dispatch
- **line2 (64B):** conn_id, last_active_ms, active_list_pos — only touched during TTL scanning
- **line3 (64B):** fiber_context, large_buf_ptr — async anchors (Worker Pool / oversized bodies)
- **line4 (128B):** writev_in_flight, response_buf, write_iovs, WS queue — write path, not in the hot path
- **line5 (64B):** sentinel + workspace union — protocol parser scratch, zero extra allocation

The IO loop's hottest path (CQE dispatch → slot lookup) only touches line1. TTL scanning only touches line2. No cache-line ping-pong between unrelated operations.

### WebSocket payload copying

WS handlers may offload frame data asynchronously, so frame payloads must remain valid after handler returns. **WS frame payloads are always duped — never zero-copy.**

**Performance impact (100B text frame):**

| Operation | Cost | Notes |
|-----------|------|-------|
| memcpy(100B) | ~10ns | Copy frame payload |
| GeneralPurposeAllocator alloc/free | ~100ns | One alloc+free per frame |

**~110ns overhead per frame**. 1M connections, 1% active, 10 msg/s each = 100K msg/s:
- CPU: 100K × 110ns = **11ms/s = 1.1% of one core**

## Raw TCP

```zig
fn myTcpHandler(conn_id: u64, data: []u8) void {
    server.tcp_server.send(conn_id, "pong\n");
}

try server.tcp("0.0.0.0:9000", myTcpHandler);
```

Raw TCP connections skip HTTP parsing entirely. Bytes are delivered directly to the handler. Shared `accum_buf` buffer reassembly with WebSocket path. Connections default to keep-alive; set `conn.keep_alive = false` to close after each write.

## Raw UDP

```zig
fn dnsHandler(sender: sws.SenderAddr, data: []u8, ctx: *anyopaque) void {
    const server: *sws.AsyncServer = @ptrCast(@alignCast(ctx));
    server.udp_server.send(sender, response);
}

// Default: framework heap-copies data → safe for Next.go/submit
try server.udp("0.0.0.0:5353", dnsHandler);

// Zero-copy: handler receives pool slab buffer → must complete synchronously
try server.udp4Sync("0.0.0.0:1234", ntpHandler);
```

Single UDP socket via `IORING_OP_RECVMSG`. Pre-allocated slab buffer pool (`UdpBufferPool`, 256 × 64KB) eliminates per-packet heap allocation. Sync mode (`udp4Sync`) delivers pool buffer directly — sub-μs overhead.

## TLS / HTTPS / WSS

TLS is powered by the pure-Zig [tls.zig](lib/tls.zig) library (TLS 1.3 server). Enable at build time:

```bash
zig build -Denable-tls=true
```

### Server TLS

```zig
var server = try sws.AsyncServer.init(alloc, io, "0.0.0.0:9443", null, 64,
    .{ .cert_path = "/etc/ssl/fullchain.pem", .key_path = "/etc/ssl/privkey.pem" }
);
// Pass null to disable TLS
```

### Client TLS

```zig
var client = try sws.HttpClient.init(alloc, &ring_b);
try client.enableTls();
const resp = try client.get("https://api.example.com/data");
```

**Certificate formats:** PEM (PKCS#8 private key), ECDSA P-256/P-384, RSA 2048/3072/4096. Let's Encrypt compatible.

## Config

| key | default | description |
|-----|---------|-------------|
| `fiber_stack_size_kb` | 256 | fiber stack size (KB). 0 = 256 |
| `io_cpu` | null | pin IO thread to CPU core |
| `idle_timeout_ms` | 30000 | close idle connections |
| `write_timeout_ms` | 5000 | close stuck-write connections |
| `buffer_size` | 4096 | io_uring buffer block size |
| `buffer_pool_size` | 16384 | number of buffer blocks |
| `max_fixed_files` | 65535 | registered fixed-file slots (beyond this uses plain-fd I/O) |

## invokeOnIoThread

Cross-thread safe callback to IO thread. Underneath is `rs.invoke` (CAS lock-free linked list), drained automatically in `drainTick`.

```zig
server.invokeOnIoThread(MyCtx, ctx, struct {
    fn run(allocator, c: *MyCtx) void {
        // Runs on IO thread — safe to access ring/registry
        c.client.write("PUB ...");
        allocator.free(c.data);
    }
}.run);
```

## Advanced: io_uring-native DB Pool

Wire your DB driver's TCP fd into io_uring directly:

```
handler (fiber on IO thread):
  └── db.query(sql)
        └── io_uring write(fd, query) → CQE → io_uring read(fd) → CQE → parse
              → ctx.json(200, result)
```

For connection pooling: maintain a pool of connected TCP fds in a ringbuffer. Handler pops fd, issues `write(sql)` + `read()` via io_uring, parses result, pushes fd back.

## License

MIT
