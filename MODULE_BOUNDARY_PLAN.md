# Module Boundary Plan

Status: **deferred**. Do not split the monorepo into build modules or crates yet.

This document records the sequencing decision and the dependency reality that must
hold before any module boundary is frozen. The target crate layout itself lives in
`ROADMAP.md`; this file is about *when* and *in what order* to get there.

## Decision

The project is in a high-churn phase: the runtime, fiber scheduler, WebSocket
state machine, and write path are still moving. Defining module boundaries now
would lock in relationships that are not stable yet. Moving a directory later is
cheap; moving a module boundary later is expensive because it changes package
identity, build graph, public imports, and test wiring.

Therefore:

- Keep the current monorepo and the current `src/` layout.
- Do not add `b.addModule` slices, separate packages, or directory moves for
  boundary reasons.
- Do not perform a big-bang rename or a "cleanup while we're here" pass.
- Every step below must be behavior-preserving and independently testable.

## Required order

1. **Let churn drop.** Finish the in-flight protocol/runtime work first.
2. **Record the real dependency direction.** Derive it from imports, not from
   directory names or intended architecture.
3. **Remove reverse edges.** In particular `next -> http`; also any other
   core/runtime -> HTTP edges.
4. **Only then define module boundaries.**

Skipping to step 4 is the failure mode this document exists to prevent.

## Phase 1: wait for churn to settle

Do not pick a numeric commit threshold in advance. Use these signals instead:

- The public surface exported by `src/root.zig` / `src/root_dev.zig` stops
  changing shape between related fixes.
- The same subsystem stops producing the same class of bug repeatedly.
- The fiber/yield lifecycle and the CQE dispatch rules are documented and stable.
- There is no large in-flight refactor waiting to land.
- `zig build`, the Windows dev build, the Linux build, TLS build, and the test
  suite are green together.

Until most of these hold, boundary work is premature.

## Phase 2: dependency snapshot

Re-generate the edge list before making decisions. On Windows PowerShell:

```powershell
# runtime -> HTTP (reverse edges)
Select-String -Path src\next\*.zig -Pattern '@import\("\.\./' 
Select-String -Path src\*.zig -Pattern '@import\("\./http/|@import\("http/'

# HTTP -> runtime (forward edges)
Select-String -Path src\http\*.zig -Pattern '@import\("\.\./next/'
```

Equivalent grep:

```bash
rg -n '@import\("\.\./' src/next
rg -n '@import\("\./http/|@import\("http/' src/*.zig
rg -n '@import\("\.\./next/' src/http
```

### Snapshot at commit `8583b41` (2026-11-25)

Allowed forward direction:

- `http/* -> next/*` (`Fiber`, `Next`, `queue`, `chunk_stream`)
- `http/* -> core/*` (`stack_pool`, `buffer_pool`, `shared/*`, `constants`)

Reverse / cyclic edges that must be removed before any module split:

| Edge | Location | Nature |
|------|----------|--------|
| `next -> http/context`, `next -> http/async_server` | `src/next/next.zig:298-300` | `Next.chainGoSubmit` is HTTP-specific and lives inside the generic scheduler |
| `next -> deferred -> http/async_server` | `src/next/next.zig:298`, `src/deferred.zig:8` | `DeferredResponse` owns an `AsyncServer` pointer |
| `next/chunk_stream -> deferred -> http/async_server` | `src/next/chunk_stream.zig:3` | streaming helper depends on the HTTP response type |
| `core -> http/connection` | `src/stack_pool.zig:4` | core slot pool imports `ConnState` from the HTTP layer |

`src/deferred.zig` is the main coupling point: it sits at the repository root,
but it is an HTTP response object and directly imports `http/async_server.zig`.

## Phase 3: untangle reverse edges

Do these in small, independently reviewable steps. No directory moves yet.

### 3a. Move `chainGoSubmit` out of `next`

`Next.chainGoSubmit` is built on top of the generic `Next.go` / `Next.submit`
API and only exists for HTTP request chains. Move it to the HTTP side (for
example `src/http/chain.zig`) together with `ChainWrap`, `ChainGoCtx`, and
`ChainSubmitCtx`. Update the `src/root.zig` re-export.

Acceptance: `src/next/next.zig` no longer imports `http/context.zig`,
`http/async_server.zig`, or `deferred.zig`.

### 3b. Decouple `DeferredResponse` from `AsyncServer`

Preferred: give `DeferredResponse` a function pointer plus an opaque context
instead of a concrete `*AsyncServer`:

```zig
pub const DeferredResponse = struct {
    ctx: *anyopaque,
    send_fn: *const fn (
        ctx: *anyopaque,
        conn_id: u64,
        status: u16,
        ct: ContentType,
        body: []u8,
    ) void,
    conn_id: u64,
    allocator: Allocator,
};
```

The HTTP layer installs the callback and owns the `AsyncServer` cast. This keeps
`deferred.zig` protocol-agnostic.

Alternative: move `DeferredResponse` into the HTTP layer. That is only viable
after `next/chunk_stream.zig` stops referencing it (see 3c).

### 3c. Decide the home of `chunk_stream`

`next/chunk_stream.zig` is an HTTP streaming helper (it takes `DeferredResponse`
and is consumed by `http/http_body.zig`). Either:

- move it to the HTTP layer, or
- make it generic over a response sink and keep it in the runtime layer.

Pick one only after 3a/3b; do not decide it from the current directory name.

### 3d. Move `ConnState` out of `http/connection.zig`

`stack_pool.zig` is a core primitive but needs the connection state enum. Move
`ConnState` to a core-level types file (or parameterize `StackSlot` over the
state type). This is a pure type move and should stay separate from the fiber /
WebSocket work.

Acceptance for Phase 3:

```powershell
Select-String -Path src\next\*.zig -Pattern 'http/|deferred\.zig'
Select-String -Path src\stack_pool.zig -Pattern 'http/'
```

Both should return no relevant matches (logger and other core-level imports are
fine). Until then, do not create module boundaries.

## Phase 4: module boundaries

Only after Phase 3 and after Zig's build/package APIs stabilize enough for the
layout in `ROADMAP.md`:

- Derive the crate boundary from the cleaned dependency graph, not from the old
  directory tree.
- Move one crate at a time, with the monorepo build and tests still passing.
- Keep `sw-core` protocol-agnostic; HTTP types must not appear in its imports.

## Guardrails

- No directory moves "to prepare for" a boundary that is not decided yet.
- No `build.zig` module split while the graph still has reverse edges.
- No commit that mixes dependency untangling with behavior changes.
- If a reverse edge looks hard to remove, record it here first; do not hide it
  behind a re-export or a forward declaration.

## References

- `ROADMAP.md` — target crates and why the split waits for Zig 1.0.
- `AGENTS.md` — build/test conventions.
- `README.md` — runtime invariants (`shared_fiber_active`, IO-thread-only state).
