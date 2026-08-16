# AGENTS.md

Guidance for agents (and humans) working on this repository.

## Build & test

Requires Zig **0.16.0**.

```bash
zig build                              # default target = x86_64-linux (io_uring production build)
zig build -Dtarget=x86_64-windows      # non-Linux dev server (uses src/root_dev.zig)
zig build -Denable-tls                 # enable TLS (requires the tls_zig dependency)

zig build test -Dtarget=x86_64-windows # host-runnable pure-module tests
zig test src/<pure_module>.zig         # run a single pure module's tests directly
```

Notes:

- The default target is `x86_64-linux` (see `build.zig`). On Windows, pass `-Dtarget` explicitly; `zig build test` with the default Linux target compiles but cannot *run* on the Windows host.
- io_uring / `std.os.linux` code only compiles for Linux. To typecheck the full production build on any host, use `zig build -Dtarget=x86_64-linux`.

## Conventions

- **Pure logic stays testable.** Any code that does not import `std.os.linux` / io_uring / `AsyncServer` should live in its own module with inline `test` blocks so it runs on the host via `zig test`.
- When you add a new pure module with tests, register it in the `test {}` blocks of both `src/root.zig` and `src/root_dev.zig`.
- Comments are written in English.
- Split large functions/files by responsibility; move pure logic out first (see `LARGE_FILE_SPLIT_PLAN.md`).

## Where things live

- `src/http` — `AsyncServer` + HTTP routing / read / write / websocket handler
- `src/client` — outbound `HttpClient` + async DNS
- `src/shared` — ring / buffer pool / outbound tcp_stream shared runtime
- `src/next` — fiber + worker-pool scheduler
- `src/dns`, `src/ws`, `src/tcp`, `src/udp`, `src/tls`
- `src/dev` — non-Linux dev server (`root_dev.zig`)

## Deferred

- Multi-crate split (`sw-core` / `sw-httpclient` / `sws`) waits for Zig 1.0 — see `ROADMAP.md`.
- Code-quality backlog is tracked in `NOT_GOOD_CODE.md` and `CODE_QUALITY_PLAN.md`.
