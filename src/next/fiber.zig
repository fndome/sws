const std = @import("std");
const IoFiber = std.Io.fiber;
const logErr = @import("../async_logger.zig").logErr;

pub const FiberCall = struct {
    userCtx: ?*anyopaque,
    complete: *const fn (?*anyopaque, []const u8) void,
    execFn: *const fn (?*anyopaque, *const fn (?*anyopaque, []const u8) void) void,
};

/// Yield out-params returned by `Fiber.exec`. When a worker fiber calls
/// `workerYield`, it parks itself and communicates the suspension point plus
/// the poll callback through this struct — no process-wide globals.
pub const YieldInfo = struct {
    ctx: IoFiber.Context,
    call: FiberCall,
    poll: ?*const fn (*anyopaque) bool,
    poll_ctx: ?*anyopaque,
};

threadlocal var active_call: ?FiberCall = null;
threadlocal var caller_context: ?*IoFiber.Context = null;

/// The currently executing fiber context, used by components like Pipe for yield
threadlocal var current_context: ?*IoFiber.Context = null;
/// The currently executing fiber instance (set by exec); workerYield writes its
/// yield out-params here so exec can return them instead of using globals.
threadlocal var current_fiber: ?*Fiber = null;

/// ── yield/resume state ──
threadlocal var yielded_fiber: ?*IoFiber.Context = null;
threadlocal var yielded_result: ?[]const u8 = null;
pub threadlocal var saved_call: ?FiberCall = null;
threadlocal var yield_seq: u64 = 0;

/// ── yield cleanup callback: invoked when the fiber fully completes (resumed and did not yield again) ──
pub const YieldCleanup = struct {
    data: *anyopaque,
    free_fn: *const fn (*anyopaque) void,
};

pub threadlocal var yield_cleanup: ?YieldCleanup = null;

fn trampoline() void {
    const c = active_call.?;
    c.execFn(c.userCtx, c.complete);
    var fiber_ctx: IoFiber.Context = undefined;
    _ = IoFiber.contextSwitch(&.{ .old = &fiber_ctx, .new = caller_context.? });
    unreachable;
}

pub const Fiber = struct {
    context: IoFiber.Context,
    /// Yield out-params written by workerYield before suspension; exec returns them.
    yield_info: ?YieldInfo = null,

    pub fn init(stack: []u8) Fiber {
        const sp = @intFromPtr(stack.ptr + stack.len);
        // Defensive: x86_64 enters the trampoline via jmp (no call pushes a return address), so rsp must emulate the ABI's -8 alignment.
        const aligned_sp = (sp & ~@as(u64, 15)) - 8;
        return .{
            .context = .{
                .rsp = aligned_sp,
                .rbp = 0,
                .rip = @intFromPtr(&trampoline),
            },
        };
    }

    pub fn exec(self: *Fiber, c: FiberCall) ?YieldInfo {
        active_call = c;
        current_context = &self.context;
        current_fiber = self;
        self.yield_info = null;
        var caller = Fiber{ .context = undefined };
        caller_context = &caller.context;
        _ = IoFiber.contextSwitch(&.{ .old = &caller.context, .new = &self.context });
        current_fiber = null;
        current_context = null;
        active_call = null;
        caller_context = null;
        return self.yield_info;
    }

    pub fn currentYield() void {
        const ctx = current_context orelse return;
        yielded_fiber = ctx;
        saved_call = active_call;
        yield_seq +%= 1;
        var tmp: IoFiber.Context = undefined;
        _ = IoFiber.contextSwitch(&.{ .old = &tmp, .new = caller_context.? });
    }

    pub fn yieldCurrent(self: *Fiber) void {
        yielded_fiber = &self.context;
        saved_call = active_call;
        yield_seq +%= 1;
        var tmp: IoFiber.Context = undefined;
        _ = IoFiber.contextSwitch(&.{ .old = &tmp, .new = caller_context.? });
    }

    /// Deferred resume queue: during CQE processing fibers are not resumed directly; they are enqueued and resumed in batch by the main loop.
    /// The queue stores slot_idx so the workspace can be prefetched before resume.
    pub const ResumeEntry = struct {
        slot_idx: u32,
        gen_id: u32,
        data: []const u8,
    };

    const RESUME_QUEUE_CAP = 1024;
    pub threadlocal var resume_queue: [RESUME_QUEUE_CAP]ResumeEntry = [_]ResumeEntry{.{ .slot_idx = 0, .gen_id = 0, .data = "" }} ** RESUME_QUEUE_CAP;
    pub threadlocal var resume_head: u16 = 0;
    pub threadlocal var resume_tail: u16 = 0;

    pub fn pushResume(slot_idx: u32, gen_id: u32, data: []const u8) void {
        const next = resume_tail +% 1;
        if (next == resume_head) {
            logErr("Fiber.pushResume: resume queue full (cap={d}), entry dropped — slot={d} gen={d}", .{ RESUME_QUEUE_CAP -| 1, slot_idx, gen_id });
            return;
        }
        resume_queue[resume_tail] = .{ .slot_idx = slot_idx, .gen_id = gen_id, .data = data };
        resume_tail = next;
    }

    pub fn popResume() ?ResumeEntry {
        if (resume_head == resume_tail) return null;
        const entry = resume_queue[resume_head];
        resume_head +%= 1;
        return entry;
    }

    pub fn hasPendingResume() bool {
        return resume_head != resume_tail;
    }

    pub fn resumeYielded(data: []const u8) void {
        const target = yielded_fiber orelse return;
        yielded_result = data;
        active_call = saved_call;
        current_context = target;

        const seq_before = yield_seq;

        var resume_caller: IoFiber.Context = undefined;
        caller_context = &resume_caller;

        _ = IoFiber.contextSwitch(&.{ .old = &resume_caller, .new = target });

        if (yield_seq == seq_before) {
            current_context = null;
            caller_context = null;
            yielded_fiber = null;
            yielded_result = null;
            active_call = null;
            saved_call = null;
            if (yield_cleanup) |cleanup| {
                yield_cleanup = null;
                cleanup.free_fn(cleanup.data);
            }
        } else {
            current_context = null;
            caller_context = null;
        }
    }

    pub fn yieldResult() ?[]const u8 {
        const r = yielded_result;
        yielded_result = null;
        return r;
    }

    pub fn isYielded() bool {
        return yielded_fiber != null;
    }

    /// Called inside a worker fiber: yields the current fiber and registers a poll callback.
    /// The worker thread's tick periodically calls pollFn; when it returns true this fiber is resumed.
    pub fn workerYield(pollFn: *const fn (*anyopaque) bool, pollCtx: *anyopaque) void {
        const self = current_fiber orelse return;
        self.yield_info = .{
            .ctx = self.context,
            .call = active_call.?,
            .poll = pollFn,
            .poll_ctx = pollCtx,
        };
        currentYield();
    }

    /// Called from the worker thread's tick: resumes a parked fiber instance.
    /// Re-establishes `current_fiber` so a subsequent workerYield can write its
    /// yield out-params back to this fiber's `yield_info` field.
    pub fn resumeContext(fiber: *Fiber) void {
        current_fiber = fiber;
        yielded_fiber = &fiber.context;
        resumeYielded("");
        current_fiber = null;
    }

    /// Fiber yield/resume slot used by the DNS resolver on the IO thread.
    pub const DnsYieldSlot = struct {
        ctx: IoFiber.Context,
        call: FiberCall,
    };

    /// DNS resolver: suspends the current fiber and saves its state into slot.ctx.
    /// Context switches back to caller_context (the caller set by exec).
    /// The caller must hand control back to the IO event loop immediately after dnsYield returns.
    pub fn dnsYield(slot: *DnsYieldSlot) void {
        slot.call = active_call.?;
        _ = IoFiber.contextSwitch(&.{ .old = &slot.ctx, .new = caller_context.? });
    }

    /// DNS resolver CQE handler: resumes the fiber suspended by dnsYield.
    /// dnsYield saves register state directly into slot.ctx, so it can be safely resumed across exec stack frames.
    pub fn dnsResume(slot: *const DnsYieldSlot) void {
        saved_call = slot.call;
        active_call = slot.call;
        current_context = @constCast(&slot.ctx);
        var resume_caller: IoFiber.Context = undefined;
        caller_context = &resume_caller;
        _ = IoFiber.contextSwitch(&.{ .old = &resume_caller, .new = @constCast(&slot.ctx) });
        current_context = null;
        caller_context = null;
    }
};
