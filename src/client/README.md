# sws/client — Built-in io_uring HTTP Client

## Why sws ships its own HTTP client

In most web frameworks, the HTTP server and outbound HTTP client are separate
concerns. sws is different: **the HTTP client exists to defend the server's
performance model**, not because outbound HTTP is inherently a framework
responsibility.

A single-threaded io_uring event loop will stall if any operation on the IO
thread performs a blocking syscall. Every outbound HTTP request made from a
handler runs the risk of becoming that stall — DNS resolution, TCP connect,
TLS handshake, and response reading must all be non-blocking.

There is no drop-in io_uring-native HTTP client for Zig. If sws did not
provide one, every application would have to either:

1. Offload every outbound call to a worker thread (paying a thread-switch +
   context-dispatch penalty on every request), or
2. Write raw `linux.socket()` + `getaddrinfo()` (blocking the IO thread on
   DNS and connect, exactly what must be avoided).

Both degrade the performance of the single-threaded event loop that sws exists
to uphold.

## The io_uring + TinyCache combination

### RingB (HttpRing)

A dedicated io_uring ring with:

- **Async DNS** — io_uring UDP SQEs, fiber-yield during resolution, zero
  blocking on the IO thread
- **Async TCP connect** — `IORING_OP_CONNECT` with `IORING_OP_LINK_TIMEOUT`
  (5s default), fiber-yield until CQE
- **Async read/write** — `IORING_OP_READ` / `IORING_OP_WRITE`, non-blocking
- **Cross-thread dispatch** — `InvokeQueue` for caller → ring thread handoff
- **Dedicated OS thread** — drives its own `submit_and_wait` loop, keeps IO
  thread latency stable regardless of outbound volume

### TinyCache (Connection Pool)

A per-(host, port) keep-alive connection pool with:

- TTL-based expiry (configurable, default 2000ms)
- Per-host connection limit (`MAX_CONNS_PER_HOST = 12`)
- Transparent acquire / release / evict lifecycle
- No thread synchronization needed (single ring thread)

### Why a third-party io_uring HTTP client would not be enough

Even if a standalone io_uring HTTP client existed for Zig, it would still
leave a critical gap: **connection pooling is not a feature — it is a
prerequisite for sustained performance under load.**

Every cold HTTP request pays:

- DNS resolution (~1-5ms async)
- TCP three-way handshake (~100µs in DC, ~1ms cross-AZ)
- TLS handshake (~1-5ms, not yet implemented in sws)

For a single request this is negligible. For a handler that calls an
external service on every WebSocket message at 20K msg/s, the cost of
connecting + disconnecting on every call would saturate the outbound ring
with SQE churn and inflate P99 latency by orders of magnitude.

TinyCache absorbs this by keeping idle connections alive across requests.
A handler that calls the same filter/db/auth service 100,000 times per
second pays the connection cost once (on the first cold call), then
reuses the connection for the remaining 99,999 calls. Without this pool,
the io_uring ring would spend the majority of its SQE budget on
`IORING_OP_CONNECT` instead of `IORING_OP_WRITE`.

**An io_uring HTTP client without a connection pool is a benchmark toy.**
It will post impressive single-connection throughput numbers and collapse
under production fan-out. The combination of io_uring transport + per-host
connection pool is what makes sws's outbound path viable at scale.

```
handler (IO thread fiber)
  │
  ├── HttpClient.request("POST", "http://filter.svc/check", body)
  │     │
  │     ├── invoke.push → RingB thread picks up
  │     │
  │     ├── RingB thread
  │     │     ├── cache.acquire(host, port)
  │     │     │     ├── HIT  → reuse connection (skip DNS, skip TCP)
  │     │     │     └── MISS → dns.resolve() → connectRawTimeout() → fiber-yield
  │     │     ├── write request → fiber-yield
  │     │     ├── readPipe.read() → fiber-yield
  │     │     ├── cache.release(pipe) or cache.evictPipe(pipe)
  │     │     └── notify → caller thread wakes
  │     │
  │     └── return response
  │
  └── IO thread continues processing other connections (never blocked)
```

Without TinyCache, every outbound call pays DNS + TCP connect latency.
Without the io_uring client, every outbound call threads-out or blocks.
The combination ensures that sws's IO thread never waits for external
services, and repeated calls to the same target reuse connections with
near-zero setup cost.

## Usage

```zig
var client = try sws.HttpClient.init(alloc, &ring_b);
try client.start(); // spawn dedicated ring thread
defer client.deinit();

const resp = try client.get("http://api.example.com/data");
defer resp.deinit();
```

## When NOT to use

If your handler never makes outbound HTTP calls, don't initialize
`HttpClient`. The ring, thread, and pool carry zero overhead until
`start()` is called. There is no hidden dependency or automatic
instantiation.
