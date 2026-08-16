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
    fiber: *Fiber,
    task: *PoolTask,
    poll_fn: *const fn (*anyopaque) bool,
    poll_ctx: *anyopaque,
    /// Heap-allocated fiber stack (64KB), kept alive across yield.
    /// Freed by resumeParked after resume completes.
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
            // Defensive: if init fails partway, the WorkerPool has not yet been handed to the caller, so the already-allocated fiber stacks must be reclaimed here.
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
                // Defensive: on thread-spawn failure, signal stop and join the threads already started, then let the errdefer release stacks and workers uniformly.
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
        task.exec(task.ctx, task.alloc); // pool-full fallback: run directly with no fiber
        pool.allocator.destroy(task);
        return;
    };
    const fiber = pool.allocator.create(Fiber) catch {
        pool.releaseStack(stack);
        pool.allocator.destroy(task);
        return;
    };
    fiber.* = Fiber.init(stack);
    const call = makeFiberCall(task);

    var yield_info = fiber.exec(call);
    if (yield_info) |*yi| {
        const poll = yi.poll orelse {
            pool.allocator.destroy(fiber);
            pool.releaseStack(stack);
            pool.allocator.destroy(task);
            return;
        };
        const poll_ctx = yi.poll_ctx orelse {
            pool.allocator.destroy(fiber);
            pool.releaseStack(stack);
            pool.allocator.destroy(task);
            return;
        };
        parked.append(pool.allocator, .{
            .fiber = fiber,
            .task = task,
            .poll_fn = poll,
            .poll_ctx = poll_ctx,
            .stack = stack,
        }) catch {
            // OOM: resume the fiber to completion. If it yields again after
            // the resume, the task and stack are leaked (cannot re-append
            // under memory pressure). Free what we own to bound the damage.
            @import("fiber.zig").saved_call = call;
            Fiber.resumeContext(fiber);
            pool.allocator.destroy(fiber);
            pool.releaseStack(stack);
            pool.allocator.destroy(task);
        };
    } else {
        pool.allocator.destroy(fiber);
        pool.releaseStack(stack);
        pool.allocator.destroy(task);
    }
}

fn resumeParked(pool: *WorkerPool, pt: *ParkedTask, parked: *std.ArrayList(ParkedTask)) void {
    @import("fiber.zig").saved_call = makeFiberCall(pt.task);
    Fiber.resumeContext(pt.fiber);

    if (Fiber.isYielded()) {
        const yield_info = pt.fiber.yield_info orelse {
            pool.allocator.destroy(pt.fiber);
            pool.releaseStack(pt.stack);
            pool.allocator.destroy(pt.task);
            return;
        };
        const poll = yield_info.poll orelse {
            pool.allocator.destroy(pt.fiber);
            pool.releaseStack(pt.stack);
            pool.allocator.destroy(pt.task);
            return;
        };
        const poll_ctx = yield_info.poll_ctx orelse {
            pool.allocator.destroy(pt.fiber);
            pool.releaseStack(pt.stack);
            pool.allocator.destroy(pt.task);
            return;
        };
        parked.append(pool.allocator, .{
            .fiber = pt.fiber,
            .task = pt.task,
            .poll_fn = poll,
            .poll_ctx = poll_ctx,
            .stack = pt.stack, // stack stays alive across yield with the task
        }) catch {
            // OOM: cannot re-park the fiber. Release stack and task
            // to avoid leaking resources since the poll may never trigger.
            pool.allocator.destroy(pt.fiber);
            pool.releaseStack(pt.stack);
            pool.allocator.destroy(pt.task);
        };
    } else {
        pool.allocator.destroy(pt.fiber);
        pool.releaseStack(pt.stack);
        pool.allocator.destroy(pt.task);
    }
}
