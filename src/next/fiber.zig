const std = @import("std");
const IoFiber = std.Io.fiber;
const logErr = @import("../async_logger.zig").logErr;

pub const FiberCall = struct {
    userCtx: ?*anyopaque,
    complete: *const fn (?*anyopaque, []const u8) void,
    execFn: *const fn (?*anyopaque, *const fn (?*anyopaque, []const u8) void) void,
};

threadlocal var active_call: ?FiberCall = null;
threadlocal var caller_context: ?*IoFiber.Context = null;

/// 当前正在执行的 fiber context，供 Pipe 等组件 yield 使用
threadlocal var current_context: ?*IoFiber.Context = null;

/// ── yield/resume 状态 ──
threadlocal var yielded_fiber: ?*IoFiber.Context = null;
threadlocal var yielded_result: ?[]const u8 = null;
pub threadlocal var saved_call: ?FiberCall = null;
threadlocal var yield_seq: u64 = 0;

/// ── worker 线程 parking 状态（transient，fiber.exec 返回后由 workerLoop 读取） ──
pub threadlocal var parked_ctx: ?*IoFiber.Context = null;
pub threadlocal var parked_call: ?FiberCall = null;
pub threadlocal var parked_poll: ?*const fn (*anyopaque) bool = null;
pub threadlocal var parked_poll_ctx: ?*anyopaque = null;

/// ── yield 清理回调：fiber 完全完成（resume 后未再 yield）时调用 ──
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

    pub fn init(stack: []u8) Fiber {
        const sp = @intFromPtr(stack.ptr + stack.len);
        // 修改原因：x86_64 通过 jmp 进入 trampoline，没有 call 压入返回地址，rsp 需模拟 ABI 的 -8 对齐。
        const aligned_sp = (sp & ~@as(u64, 15)) - 8;
        return .{
            .context = .{
                .rsp = aligned_sp,
                .rbp = 0,
                .rip = @intFromPtr(&trampoline),
            },
        };
    }

    pub fn exec(self: *Fiber, c: FiberCall) void {
        active_call = c;
        current_context = &self.context;
        var caller = Fiber{ .context = undefined };
        caller_context = &caller.context;
        _ = IoFiber.contextSwitch(&.{ .old = &caller.context, .new = &self.context });
        current_context = null;
        active_call = null;
        caller_context = null;
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

    /// 延迟恢复队列：CQE 处理期间不直接 resume，而是入队后由主循环统一恢复。
    /// 队列存储 slot_idx 用于 resume 前对 workspace 做 prefetch。
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

    /// Worker fiber 内调用：yield 当前 fiber，注册 poll 回调。
    /// worker 线程的 tick 里周期调 pollFn，返回 true 时 resume 本 fiber。
    pub fn workerYield(pollFn: *const fn (*anyopaque) bool, pollCtx: *anyopaque) void {
        parked_poll = pollFn;
        parked_poll_ctx = pollCtx;
        currentYield();
        parked_ctx = yielded_fiber;
        parked_call = saved_call;
    }

    /// Worker 线程 tick 调用：resume 一个已保存的 fiber context
    pub fn resumeContext(ctx: *IoFiber.Context) void {
        yielded_fiber = ctx;
        // saved_call should already be set by the caller or stored alongside
        resumeYielded("");
    }

    /// DNS resolver 在 IO 线程上使用的 fiber yield/resume 槽位。
    pub const DnsYieldSlot = struct {
        ctx: IoFiber.Context,
        call: FiberCall,
    };

    /// DNS resolver: 挂起当前 fiber，将状态保存到 slot.ctx 中。
    /// 上下文会切换回 caller_context（exec 设置的调用者）。
    /// 调用者必须在 dnsYield 返回后立即将控制权交还给 IO 事件循环。
    pub fn dnsYield(slot: *DnsYieldSlot) void {
        slot.call = active_call.?;
        _ = IoFiber.contextSwitch(&.{ .old = &slot.ctx, .new = caller_context.? });
    }

    /// DNS resolver CQE handler: 恢复由 dnsYield 挂起的 fiber。
    /// dnsYield 直接保存寄存器状态到 slot.ctx，故可跨 exec 栈帧安全恢复。
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
