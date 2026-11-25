# Bug Review Checklist

A short, repeatable audit guide for the bugs that have already escaped once.
Use it when touching the fiber scheduler, the WebSocket read path, the write
buffer path, or CQE dispatch.

Each item is phrased as a question that must be answered with **yes**. If the
answer is "not sure", the code is not ready.

Known-good baseline: commit `8583b41` fixed items 1-4 below. Later changes must
not regress them.

---

## 1. Fiber yield/resume: is the saved context the same object that resume restores?

**Failure mode**

`contextSwitch(.{ .old = &saved, .new = &next })` writes the suspended CPU state
into `saved`. If a later resume passes a *different* object as `.new`, the fiber
jumps back to its trampoline entry and re-runs `execFn` from the beginning
instead of continuing after the yield.

**Audit**

- Find every yield site and its matching resume site. Pair them.
- `src/next/fiber.zig`: `currentYield`, `yieldCurrent`, `workerYield`,
  `resumeYielded`, `resumeContext`, `dnsYield`, `dnsResume`.
- For each: the object passed as `.old` at yield must be the same object later
  passed as `.new` at resume. Not a copy, not a stack local.

**Correct pattern**

```zig
// yield: save into the object resume will use
_ = IoFiber.contextSwitch(&.{ .old = ctx, .new = caller_context.? });

// resume: restore that same object
_ = IoFiber.contextSwitch(&.{ .old = &resume_caller, .new = target });
```

**Regression test**

`src/next/fiber.zig`: `"resume continues after the yield point instead of
re-running execFn"`.

**Traps**

- `var tmp: Context = undefined; .old = &tmp` — `tmp` dies with the fiber frame.
- `YieldInfo.ctx` is a snapshot; the live resumable state is `Fiber.context`.
  `exec` / `resumeContext` refresh the snapshot, but resume must use
  `Fiber.context`.
- `yielded_fiber` and `yield_cleanup` are single threadlocal slots. Do not assume
  two fibers may be parked at once; see item 6.

---

## 2. WebSocket read: are all complete frames in the buffer processed?

**Failure mode**

A TCP read can contain several WebSocket frames (`[text][ping]`, `[close]` after
a data frame, two messages in one `send()`). Calling `parseFrame` once and then
recycling the read buffer silently drops every byte after the first frame.

**Audit**

- `src/http/ws_handler.zig`, `onWsFrame`: is parsing inside a loop over
  `frame_input`?
- Does the parser return how many bytes were consumed?
  (`ws/frame.zig`: `parseFrameWithLength` -> `{ frame, consumed }`.)
- On `IncompleteFrame`, is only the **unconsumed tail** saved to `accum_buf`,
  not the whole buffer?
- Is the read bid recycled exactly **once**, regardless of how many frames were
  in the read?
- If a handler yields mid-read, is the remaining tail copied before returning?

**Correct pattern**

```zig
var offset: usize = 0;
while (offset < frame_input.len) {
    const parsed = try parseFrameWithLength(frame_input[offset..]);
    offset += parsed.consumed;
    // ... process parsed.frame ...
}
// recycle the read bid once here or on every early-return path
```

**Regression test**

`src/ws/frame.zig`: `"parseFrameWithLength reports consumed bytes for
back-to-back frames"`.

**Traps**

- Giving the same read bid to multiple WS tasks; only one owner may recycle it.
- Storing the whole combined buffer as `accum_buf` after earlier frames were
  already processed (replays the prefix).
- Control frames that share a read with a data frame must be queued when a write
  is already in flight; see item 3.
- The complete end-to-end path needs io_uring, so the frame parser test alone
  does not cover the handler loop. Review the loop explicitly.

---

## 3. Write buffer: is every acquisition guarded by the in-flight check?

**Failure mode**

`ensureWriteBuf` used to return early when the existing buffer was already large
enough, skipping `writev_in_flight`. A control frame (pong/close) could then
overwrite bytes belonging to a write SQE still in the kernel. The next submit
sees `WriteInFlight` and closes the connection.

**Audit**

- `src/http/http_response.zig`, `ensureWriteBuf`: is the `writev_in_flight`
  check at the **top**, before the `existing.len >= min_size` early return?
- List every caller of `ensureWriteBuf`; confirm none can run while a write is
  in flight, or that they handle `false` safely.
- `src/http/ws_handler.zig`: do ping/close responses check
  `shouldQueueWsSend(conn)` and enqueue instead of writing `response_buf`
  directly?
- `flushWsWriteQueue`: for a queued close, is `keep_alive = false` set when the
  close frame is actually submitted, not when it is enqueued?
- `finishWriteCleanup` / `failWrite` / `retryWrite`: is `writev_in_flight`
  cleared on every completion, retry, and failure path?

**Correct pattern**

```zig
if (self.connSlot(conn)) |slot| {
    if (slot.line4.writev_in_flight != 0) return false;
}
if (conn.response_buf) |existing| {
    if (existing.len >= min_size) return true;
    // ... replace ...
}
```

**Traps**

- Do not add a "buffer is big enough, so reuse it" path that bypasses the
  in-flight check.
- Queued close must not set `keep_alive = false` at enqueue time; that would make
  an earlier write's completion close the connection and drop the queued close.
- `writev_in_flight` and `response_buf` are IO-thread-only state; the question is
  ordering, not locking.

---

## 4. CQE dispatch: can read and write completions be told apart?

**Failure mode**

`dispatchCqes` used to route by `conn.state` alone. A read completion can arrive
while `state == .ws_writing` (read was armed before an async handler wrote),
which made the read look like a write completion: `write_offset` was advanced by
the read length, the read buffer was leaked, and the connection could be closed.

**Audit**

- `src/http/event_loop.zig`, `dispatchCqes`: is there a write marker decoded from
  `user_data`?
- Are **all** server write submissions tagged? Search for `ring.write` /
  `ring.writev` under `src/http` and `src/*.zig`.
- `src/stack_pool.zig`: is `WRITE_USER_DATA_FLAG` reserved above the gen_id field
  and non-conflicting with accept/client/close markers?
- For read CQEs, are write sub-states collapsed back to the protocol read
  handler? (`writing -> onReadComplete`, `ws_writing -> onWsFrame`,
  `tcp_writing -> onRawData`.)

**Correct pattern**

Tag writes at submission with `WRITE_USER_DATA_FLAG`; in dispatch, decode
`is_write` and use the tag, not just `conn.state`.

**Traps**

- Adding a new write submission without the flag.
- Reusing bit 61 for something else (it is the server write marker).
- A write CQE arriving after state has moved to a *read* sub-state; verify the
  write path's state transitions before changing routing.

---

## 5. Per-task wrappers must not own `shared_fiber_active`

**Question**

Does a per-task-stack wrapper (`httpTaskExecWrapperWithOwnership`,
`wsTaskExecWrapperWithOwnership`, `*TaskCleanup`) read or write
`shared_fiber_active`?

It must not. The flag belongs to the shared-stack fiber: set before
`Fiber.init(...).exec(...)`, cleared by that fiber's completion callback
(`httpTaskComplete` / `wsTaskComplete`). Async Next tasks never set it, so they
must not clear it either.

**Audit**

- `rg -n "shared_fiber_active" src`.
- Every write must be paired: one `= true` around a shared-stack `exec`, one
  `= false` in the matching complete callback.
- A flag stuck `true` because a fiber never resumes is a documented degraded
  mode (subsequent work uses the Next queue), not a reason to clear it from an
  async wrapper.

---

## 6. Single-slot fiber state (known constraint, still worth checking)

**Question**

Can more than one `currentYield`-parked fiber exist on the same IO thread at the
same time?

`yielded_fiber`, `saved_call`, `yield_cleanup`, and the resume queue are single
threadlocal slots; `pushResume` carries no fiber identity. Do not add a code path
that assumes two parked fibers can be resumed independently without first
changing this design.

**Audit**

- `rg -n "yielded_fiber|yield_cleanup|pushResume|resumeYielded" src`.
- If a new async path can park a fiber, trace who resumes it and whether another
  fiber can already be parked.

This is a design-level invariant, not a per-call bug. Do not "fix" it in a
drive-by patch.

---

## Quick commands

```powershell
# 1. yield/resume pairs
Select-String -Path src\next\fiber.zig -Pattern 'contextSwitch|yielded_fiber|resume'

# 2. frame parsing
Select-String -Path src\http\ws_handler.zig,src\ws\frame.zig -Pattern 'parseFrame|accum_buf|read_bid'

# 3. write buffer
Select-String -Path src\http\*.zig -Pattern 'ensureWriteBuf|writev_in_flight|response_buf'

# 4. CQE tagging
Select-String -Path src\http\*.zig,src\*.zig -Pattern 'packUserData|WRITE_USER_DATA_FLAG|ring\.(write|writev)'

# 5. shared fiber flag
Select-String -Path src\**\*.zig -Pattern 'shared_fiber_active'
```

Equivalent with ripgrep:

```bash
rg -n 'contextSwitch|yielded_fiber|resume' src/next/fiber.zig
rg -n 'parseFrame|accum_buf|read_bid' src/http/ws_handler.zig src/ws/frame.zig
rg -n 'ensureWriteBuf|writev_in_flight' src/http
rg -n 'packUserData|WRITE_USER_DATA_FLAG' src
rg -n 'shared_fiber_active' src
```

## Sign-off

- [ ] Item 1: every yield stores into the object its resume restores.
- [ ] Item 2: all complete frames in a read are processed; only the tail is kept.
- [ ] Item 3: all write-buffer acquisitions check `writev_in_flight` first.
- [ ] Item 4: every write SQE is tagged; dispatch uses the tag.
- [ ] Item 5: per-task wrappers leave `shared_fiber_active` alone.
- [ ] Item 6: no new code assumes multiple parked fibers without redesign.
- [ ] Builds: Windows dev, Linux, Linux+TLS.
- [ ] Tests: `zig build test -Dtarget=x86_64-windows` (host) plus Linux CI.
