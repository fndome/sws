# sws — Single Worker Server

[中文文档](README_CN.md)

`io_uring` based Single Worker Server (HTTP + WebSocket) on Linux, in Zig 0.16.0.

## Project Goal

`sws` is not just a `req/s` demo. It is a small Linux-only network runtime built
around Zig, `io_uring`, fibers, explicit buffer ownership, and one IO-thread
event loop. The immediate goal is to make the HTTP/WebSocket/DNS/client paths
correct, measurable, and easy to audit before chasing larger benchmark numbers.

Current scope:

- HTTP/1.1 server: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, JSON/text/html
  responses, request body helpers, middleware, keep-alive boundaries.
- WebSocket: HTTP/1.1 upgrade, frame parse/write, ping/pong/close handling.
- DNS and outbound HTTP client: async UDP DNS, small TTL cache, keep-alive
  connection reuse.
- Linux + `io_uring` only. TLS is not built in; put a TLS proxy in front or add a
  dedicated TLS layer.

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
  ├── FiberShared.tick() — harvest outbound rings (Ring B/C/D...)
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

**Never use FUSE filesystem reads or writes within handler code running on
sws.** The IO thread's io_uring event loop runs on a single thread. A blocking
FUSE operation will stall the entire server, including all active connections.

If your application needs to read from or write to remote storage (S3, OSS,
MinIO, etc.), use **non-blocking network sockets directly at the io_uring
level** — issue `OP_SEND` / `OP_RECV` (or the equivalent in your DB/HTTP
client) targeting the remote API endpoint. Do not route I/O through FUSE
even if the remote storage provides a FUSE mount option.

The pattern is:

```
Application handler → OP_SEND/OP_RECV → remote S3/OSS API endpoint
                      ↑ io_uring native, non-blocking
```

Not:

```
Application handler → FUSE read/write → blocks IO thread → server stalls
```

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

### Source Layout (refactored)

```
src/http/
├── async_server.zig   (526)  facade — init/deinit + public API forwarding
├── event_loop.zig     (215)  run / dispatchCqes / drain* / TTL
├── http_routing.zig   (310)  use / GET/POST / processBodyRequest + fiber dispatch
├── http_response.zig  (163)  respond / respondJson / respondZeroCopy
├── http_fiber.zig     (182)  HttpTaskCtx + httpTaskExec/Cleanup/Complete
├── http_body.zig      (110)  submitBodyRead / onBodyChunk / onStreamRead
├── ws_handler.zig     (381)  tryWsUpgrade / onWsFrame / sendWsFrame / write queue
├── ws_fiber.zig       ( 50)  WsTaskCtx + wsTaskExec/Cleanup/Complete
├── tcp_accept.zig     (114)  onAcceptComplete / allocFixedIndex
├── tcp_read.zig       (367)  submitRead / onReadComplete (header parse + body route)
├── tcp_write.zig      (128)  submitWrite / onWriteComplete
├── connection_mgr.zig ( 82)  closeConn / getConn / nextUserData
├── hook_system.zig    ( 48)  DeferredNode / addHook* / sendDeferredResponse
├── connection.zig     ( 51)  Connection type
├── context.zig        (118)  Context type
├── types.zig          (  5)  Middleware / Handler types
├── http_helpers.zig   ( 87)  request parsing utilities
└── middleware_store.zig( 28)  MiddlewareStore
```

Extracted from a 2725-line God Object in 5 sessions. Each module ≤381 lines, single responsibility. `async_server.zig` is now 526 lines of pure struct definition + init/deinit + forwarding shell.

### Single IO thread + fiber

The entire event loop runs on **one IO thread**. Handlers execute as **fibers** (user-space coroutines) on the same thread.

```
IO thread (single):
  io_uring.submit_and_wait(1)
    → CQE dispatch (via StackPool sticker)
    → fiber → handler → ctx.text/json/html
    → drainPendingResumes (fiber resume queue)
    → drainNextTasks (Next.go ringbuffer tasks)
    → drainTick (DNS tick + invoke.drain + tick_hooks)
    → FiberShared.tick() (outbound Ring B/C/D harvest)
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

### Ring A + FiberShared — multi-ring architecture

**Ring A** (built-in): the main server's `io_uring` ring — accept, connection read/write, DNS, invoke.

**Outbound rings** (Ring B, Ring C...): independent io_uring rings for outbound protocols. Registered with `FiberShared`, which the IO thread harvests every event loop iteration — zero extra threads, zero locks.

```
Ring A (main server, IO thread):
  ├── accept / read / write / close
  ├── io_registry (client callbacks)
  ├── dns_resolver (async UDP DNS)
  ├── rs.invoke (cross-thread push → IO thread callback)
  └── FiberShared.tick()
        ├── Ring B (HTTP client) : ATTACH_WQ → shared io-wq
        │     ├── DnsResolver
        │     ├── IORegistry
        │     ├── InvokeQueue
        │     └── TinyCache
        ├── Ring C (NATS client futures)
        └── Ring D (MySQL client futures)
```

#### FiberShared

Pure scheduling glue layer. Holds tick handles for all outbound rings. IO thread calls `tick()` every loop iteration to non-blocking harvest CQEs from all registered rings.

```zig
const FiberShared = @import("sws").FiberShared;
const RingTrait = @import("sws").RingTrait;

var fiber_shared = try FiberShared.init(allocator);
defer fiber_shared.deinit();

// Ring B (HTTP client) registers itself
try ring_b.registerWith(&fiber_shared);

// Any new ring just implements RingTrait:
//   ptr: *anyopaque  — pointer to ring instance
//   tickFn: fn(*anyopaque) void  — dns.tick + invoke.drain + submit + copy_cqes + dispatch
```

#### RingTrait

Contract that every outbound ring must implement:

1. `dns.tick()` — drive DNS query state machine
2. `invoke.drain()` — process cross-thread task dispatch
3. `ring.submit()` — submit pending SQEs
4. `ring.copy_cqes()` — non-blocking harvest CQEs
5. `registry.dispatch(ud, res)` — dispatch CQEs to registered callbacks

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

To add outbound rings (HTTP/NATS/MySQL), inject `FiberShared`:

```zig
const FiberShared = @import("sws").FiberShared;
const RingB = @import("sws").HttpRing;   // same as RingB
const HttpClient = @import("sws").HttpClient;

var fiber_shared = try FiberShared.init(alloc);
defer fiber_shared.deinit();

// Ring B with 1s built-in TinyCache TTL:
var ring_b = try RingB.init(alloc, io, server.ring.fd, 1000);
defer ring_b.deinit();
try ring_b.registerWith(&fiber_shared);

// HttpClient auto-uses RingB's built-in cache:
var http_client = try HttpClient.init(alloc, &ring_b);
defer http_client.deinit();

// Set fiber_shared on server so IO thread harvests outbound CQEs
server.fiber_shared = &fiber_shared;
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

`RingShared` is the materialization of a single io_uring ring + single thread — injected into server and any outbound client, all equal.

```zig
const rs = server.rs;  // { ring, registry, invoke, io_tid }
// Any client is injected equally:
var client = try RingSharedClient.init(alloc, rs, ...);
var http   = try HttpClient.init(alloc, ring_b, cache);
```

- `rs.ringPtr()` / `rs.registryPtr()` — IO-thread assertion guard (non-IO thread access → @panic)
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
try ring_b.registerWith(&fiber_shared);

// HttpClient — cache is automatically managed by RingB:
var http_client = try sws.HttpClient.init(allocator, &ring_b);
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
