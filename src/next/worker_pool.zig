const std = @import("std");
const Allocator = std.mem.Allocator;
const Fiber = @import("fiber.zig").Fiber;

/// ── WorkerPool ──────────────────────────────────────────
pub const PoolTask = struct {
    next: ?*PoolTask,
    exec: *const fn (?*anyopaque, Allocator) void,
    ctx: ?*anyopaque,
    alloc: Allocator,
};

const ParkedTask = struct {
    fiber_ctx: std.Io.fiber.Context,
    task: *PoolTask,
    poll_fn: *const fn (*anyopaque) bool,
    poll_ctx: *anyopaque,
    /// 堆分配的 fiber 栈（64KB），跨 yield 保持存活。
    /// resume 完成后由 resumeParked 释放。
    stack: []u8,
};

const FIBER_STACK: u32 = 262144; // 256KB

fn makeFiberCall(task: *PoolTask) @import("fiber.zig").FiberCall {
    return .{
        .userCtx = @ptrCast(task),
        .complete = struct {
            fn done(_: ?*anyopaque, _: []const u8) void {}
        }.done,
        .execFn = struct {
            fn run(c: ?*anyopaque, _: *const fn (?*anyopaque, []const u8) void) void {
                const t: *PoolTask = @ptrCast(@alignCast(c));
                t.exec(t.ctx, t.alloc);
            }
        }.run,
    };
}

pub const WorkerPool = struct {
    const STACK_POOL_SIZE = 64;

    allocator: Allocator,
    workers: []std.Thread,
    head: ?*PoolTask,
    tail: ?*PoolTask,
    mutex: std.Io.Mutex,
    stop: bool,

    stack_pool: [STACK_POOL_SIZE][]u8,
    stack_freelist: [STACK_POOL_SIZE]usize,
    stack_freelist_top: usize,

    fn lockMutex(m: *std.Io.Mutex) void {
        while (!m.tryLock()) std.Thread.yield() catch {};
    }

    fn unlockMutex(m: *std.Io.Mutex) void {
        m.state.store(.unlocked, .release);
    }

    pub fn init(allocator: Allocator, count: u8) !WorkerPool {
        const workers = try allocator.alloc(std.Thread, count);
        errdefer allocator.free(workers);
        var stack_pool: [STACK_POOL_SIZE][]u8 = undefined;
        var stack_count: usize = 0;
        errdefer {
            // 修改原因：初始化中途失败时 WorkerPool 还没有交给调用方，已分配的 fiber 栈必须在这里回收。
            for (stack_pool[0..stack_count]) |stack| {
                allocator.free(stack);
            }
        }
        var stack_freelist: [STACK_POOL_SIZE]usize = undefined;
        for (0..STACK_POOL_SIZE) |i| {
            stack_pool[i] = try allocator.alloc(u8, FIBER_STACK);
            stack_count += 1;
            stack_freelist[i] = STACK_POOL_SIZE - 1 - i;
        }
        var pool = WorkerPool{
            .allocator = allocator,
            .workers = workers,
            .head = null,
            .tail = null,
            .mutex = .init,
            .stop = false,
            .stack_pool = stack_pool,
            .stack_freelist = stack_freelist,
            .stack_freelist_top = STACK_POOL_SIZE,
        };
        for (workers, 0..) |*w, i| {
            w.* = std.Thread.spawn(.{}, workerLoop, .{ &pool, @as(u8, @intCast(i)) }) catch {
                @atomicStore(bool, &pool.stop, true, .release);
                for (workers[0..i]) |pw| pw.join();
                // 修改原因：线程创建失败时先收停并 join 已启动线程，再交给 errdefer 统一释放栈和 workers。
                return error.ThreadSpawnFailed;
            };
        }
        return pool;
    }

    pub fn deinit(self: *WorkerPool) void {
        WorkerPool.lockMutex(&self.mutex);
        @atomicStore(bool, &self.stop, true, .release);
        WorkerPool.unlockMutex(&self.mutex);
        while (self.pop()) |task| {
            self.allocator.destroy(task);
        }
        for (self.workers) |w| w.join();
        for (self.stack_pool[0..]) |stack| {
            self.allocator.free(stack);
        }
        self.allocator.free(self.workers);
    }

    fn acquireStack(self: *WorkerPool) ?[]u8 {
        WorkerPool.lockMutex(&self.mutex);
        defer WorkerPool.unlockMutex(&self.mutex);
        if (self.stack_freelist_top == 0) return null;
        self.stack_freelist_top -= 1;
        return self.stack_pool[self.stack_freelist[self.stack_freelist_top]];
    }

    fn releaseStack(self: *WorkerPool, stack: []u8) void {
        WorkerPool.lockMutex(&self.mutex);
        defer WorkerPool.unlockMutex(&self.mutex);
        for (self.stack_pool, 0..) |s, i| {
            if (s.ptr == stack.ptr) {
                self.stack_freelist[self.stack_freelist_top] = i;
                self.stack_freelist_top += 1;
                return;
            }
        }
    }

    pub fn submit(self: *WorkerPool, task: *PoolTask) void {
        WorkerPool.lockMutex(&self.mutex);
        if (self.tail) |t| {
            t.next = task;
        } else {
            self.head = task;
        }
        self.tail = task;
        WorkerPool.unlockMutex(&self.mutex);
    }

    fn pop(self: *WorkerPool) ?*PoolTask {
        WorkerPool.lockMutex(&self.mutex);
        const task = self.head orelse {
            WorkerPool.unlockMutex(&self.mutex);
            return null;
        };
        self.head = task.next;
        if (self.head == null) self.tail = null;
        WorkerPool.unlockMutex(&self.mutex);
        task.next = null;
        return task;
    }

    fn workerLoop(pool: *WorkerPool, _: u8) void {
        var parked = std.ArrayList(ParkedTask).empty;

        while (true) {
            if (@atomicLoad(bool, &pool.stop, .acquire)) return;

            var i: usize = 0;
            while (i < parked.items.len) {
                if (parked.items[i].poll_fn(parked.items[i].poll_ctx)) {
                    var pt = parked.swapRemove(i);
                    resumeParked(pool, &pt, &parked);
                } else {
                    i += 1;
                }
            }

            if (pool.pop()) |task| {
                runTask(pool, task, &parked);
            } else {
                std.Thread.yield() catch {};
            }
        }
    }
};

fn runTask(pool: *WorkerPool, task: *PoolTask, parked: *std.ArrayList(ParkedTask)) void {
    const stack = pool.acquireStack() orelse {
        task.exec(task.ctx, task.alloc); // 池满退化: 无 fiber 直接跑
        pool.allocator.destroy(task);
        return;
    };
    var fiber = Fiber.init(stack);
    const call = makeFiberCall(task);
    fiber.exec(call);

    if (Fiber.isYielded()) {
        const ctx = @import("fiber.zig").parked_ctx orelse {
            pool.releaseStack(stack);
            pool.allocator.destroy(task);
            return;
        };
        const poll = @import("fiber.zig").parked_poll orelse {
            pool.releaseStack(stack);
            pool.allocator.destroy(task);
            return;
        };
        const poll_ctx = @import("fiber.zig").parked_poll_ctx orelse {
            pool.releaseStack(stack);
            pool.allocator.destroy(task);
            return;
        };
        parked.append(pool.allocator, .{
            .fiber_ctx = ctx.*,
            .task = task,
            .poll_fn = poll,
            .poll_ctx = poll_ctx,
            .stack = stack,
        }) catch {
            // OOM: resume the fiber to completion. If it yields again after
            // the resume, the task and stack are leaked (cannot re-append
            // under memory pressure). Release them to bound the damage.
            @import("fiber.zig").saved_call = call;
            Fiber.resumeContext(ctx);
            if (Fiber.isYielded()) {
                pool.releaseStack(stack);
                pool.allocator.destroy(task);
            }
        };
        @import("fiber.zig").parked_ctx = null;
        @import("fiber.zig").parked_poll = null;
        @import("fiber.zig").parked_poll_ctx = null;
    } else {
        pool.releaseStack(stack);
        pool.allocator.destroy(task);
    }
}

fn resumeParked(pool: *WorkerPool, pt: *ParkedTask, parked: *std.ArrayList(ParkedTask)) void {
    @import("fiber.zig").saved_call = makeFiberCall(pt.task);
    Fiber.resumeContext(&pt.fiber_ctx);

    if (Fiber.isYielded()) {
        const ctx = @import("fiber.zig").parked_ctx orelse {
            pool.releaseStack(pt.stack);
            pool.allocator.destroy(pt.task);
            return;
        };
        const poll = @import("fiber.zig").parked_poll orelse {
            pool.releaseStack(pt.stack);
            pool.allocator.destroy(pt.task);
            return;
        };
        const poll_ctx = @import("fiber.zig").parked_poll_ctx orelse {
            pool.releaseStack(pt.stack);
            pool.allocator.destroy(pt.task);
            return;
        };
        parked.append(pool.allocator, .{
            .fiber_ctx = ctx.*,
            .task = pt.task,
            .poll_fn = poll,
            .poll_ctx = poll_ctx,
            .stack = pt.stack, // 栈随任务跨 yield 存活
        }) catch {
            // OOM: cannot re-park the fiber. Release stack and task
            // to avoid leaking resources since the poll may never trigger.
            pool.releaseStack(pt.stack);
            pool.allocator.destroy(pt.task);
        };
        @import("fiber.zig").parked_ctx = null;
        @import("fiber.zig").parked_poll = null;
        @import("fiber.zig").parked_poll_ctx = null;
    } else {
        pool.releaseStack(pt.stack);
        pool.allocator.destroy(pt.task);
    }
}
