const std = @import("std");
const Allocator = std.mem.Allocator;
const SubmitQueue = @import("queue.zig").SubmitQueue;
const Item = @import("queue.zig").Item;
const fiber_mod = @import("fiber.zig");
const logErr = @import("../async_logger.zig").logErr;
const Fiber = fiber_mod.Fiber;
const worker_pool = @import("worker_pool.zig");
const PoolTask = worker_pool.PoolTask;
const WorkerPool = worker_pool.WorkerPool;

const TaskCtx = struct {
    next: *Next,
    userCtx: ?*anyopaque,
    stack_size: u32,
};

var default_next: ?*Next = null;

/// ── Next ──────────────────────────────────────────────────
pub const Next = struct {
    ringbuffer: *SubmitQueue,
    allocator: Allocator,
    default_stack_size: u32,
    pool: ?*WorkerPool,
    submit_threads: std.ArrayList(std.Thread),

    pub fn init(alloc: Allocator, stack_size: u32) !Next {
        const q = try alloc.create(SubmitQueue);
        q.* = SubmitQueue.init();
        return .{
            .ringbuffer = q,
            .allocator = alloc,
            .default_stack_size = stack_size,
            .pool = null,
            .submit_threads = try std.ArrayList(std.Thread).initCapacity(alloc, 0),
        };
    }

    pub fn deinit(self: *Next) void {
        if (self.pool) |p| p.deinit();
        for (self.submit_threads.items) |t| t.join();
        self.submit_threads.deinit(self.allocator);
        self.allocator.destroy(self.ringbuffer);
    }

    pub fn initPool4NextSubmit(self: *Next, count: u8) !void {
        if (self.pool != null) return;
        const n = if (count == 0) @as(u8, 1) else count;
        const p = try self.allocator.create(WorkerPool);
        errdefer self.allocator.destroy(p);
        p.* = try WorkerPool.init(self.allocator, n);
        self.pool = p;
    }

    pub fn setDefault(self: *Next) void {
        @atomicStore(?*Next, &default_next, self, .release);
    }

    pub fn submit(
        comptime T: type,
        ctx: T,
        comptime execFn: fn (*T, *const fn (?*anyopaque, []const u8) void) void,
    ) void {
        _ = trySubmit(T, ctx, execFn);
    }

    pub fn trySubmit(
        comptime T: type,
        ctx: T,
        comptime execFn: fn (*T, *const fn (?*anyopaque, []const u8) void) void,
    ) bool {
        const n = @atomicLoad(?*Next, &default_next, .acquire) orelse {
            logErr("Next.submit: no default Next instance set", .{});
            return false;
        };
        const user = n.allocator.create(T) catch return false;
        user.* = ctx;

        if (n.pool) |p| {
            const task = n.allocator.create(PoolTask) catch {
                n.allocator.destroy(user);
                return false;
            };
            task.* = .{
                .next = null,
                .exec = struct {
                    fn run(ctx2: ?*anyopaque, alloc: Allocator) void {
                        const u: *T = @ptrCast(@alignCast(ctx2));
                        defer alloc.destroy(u);
                        const complete = struct {
                            fn done(_: ?*anyopaque, _: []const u8) void {}
                        }.done;
                        execFn(u, complete);
                    }
                }.run,
                .ctx = user,
                .alloc = n.allocator,
            };
            p.submit(task);
            return true;
        }

        // No pool — log error, destroy user ctx
        logErr("Next.submit: no worker pool configured. Call initPool4NextSubmit(n) first.", .{});
        n.allocator.destroy(user);
        return false;
    }

    pub fn go(
        comptime T: type,
        ctx: T,
        comptime execFn: fn (*T, *const fn (?*anyopaque, []const u8) void) void,
    ) bool {
        const n = @atomicLoad(?*Next, &default_next, .acquire) orelse {
            logErr("Next.go: no default Next instance set", .{});
            return false;
        };
        return n.push(T, ctx, execFn, n.default_stack_size);
    }

    pub fn goWithStackConfigurable(
        comptime T: type,
        ctx: T,
        comptime execFn: fn (*T, *const fn (?*anyopaque, []const u8) void) void,
        stack_size: u32,
    ) bool {
        const n = @atomicLoad(?*Next, &default_next, .acquire) orelse {
            logErr("Next.goWithStackConfigurable: no default Next instance set", .{});
            return false;
        };
        return n.push(T, ctx, execFn, stack_size);
    }

    pub fn push(
        self: *Next,
        comptime T: type,
        ctx: T,
        comptime execFn: fn (*T, *const fn (?*anyopaque, []const u8) void) void,
        stack_size: u32,
    ) bool {
        const user = self.allocator.create(T) catch return false;
        user.* = ctx;

        const gc = self.allocator.create(TaskCtx) catch {
            self.allocator.destroy(user);
            return false;
        };
        gc.* = .{ .next = self, .userCtx = user, .stack_size = stack_size };

        if (!self.ringbuffer.push(.{
            .ctx = gc,
            .execute = struct {
                fn exec(caller_ctx: ?*anyopaque, complete: *const fn (?*anyopaque, []const u8) void) void {
                    const g: *TaskCtx = @ptrCast(@alignCast(caller_ctx));
                    const u: *T = @ptrCast(@alignCast(g.userCtx));

                    const stack = g.next.allocator.alloc(u8, g.stack_size) catch {
                        g.next.allocator.destroy(u);
                        g.next.allocator.destroy(g);
                        return;
                    };

                    var temp_fiber = Fiber.init(stack);
                    temp_fiber.exec(.{
                        .userCtx = u,
                        .complete = complete,
                        .execFn = struct {
                            fn call(ptr: ?*anyopaque, c: *const fn (?*anyopaque, []const u8) void) void {
                                execFn(@ptrCast(@alignCast(ptr)), c);
                            }
                        }.call,
                    });

                    if (Fiber.isYielded()) {
                        const CleanupData = struct {
                            g: *TaskCtx,
                            u: *T,
                            stack: []u8,
                            allocator: Allocator,

                            fn free(ptr: *anyopaque) void {
                                const data: *@This() = @ptrCast(@alignCast(ptr));
                                data.allocator.destroy(data.u);
                                data.allocator.free(data.stack);
                                data.allocator.destroy(data.g);
                                data.allocator.destroy(data);
                            }
                        };
                        const cd = g.next.allocator.create(CleanupData) catch {
                            g.next.allocator.destroy(u);
                            g.next.allocator.free(stack);
                            g.next.allocator.destroy(g);
                            return;
                        };
                        cd.* = .{ .g = g, .u = u, .stack = stack, .allocator = g.next.allocator };
                        fiber_mod.yield_cleanup = .{
                            .data = @ptrCast(cd),
                            .free_fn = CleanupData.free,
                        };
                    } else {
                        g.next.allocator.destroy(u);
                        g.next.allocator.free(stack);
                        g.next.allocator.destroy(g);
                    }
                }
            }.exec,
            .on_complete = struct {
                fn done(_: ?*anyopaque, _: []const u8) void {}
            }.done,
        })) {
            // Ring full → yield + 1 retry built into ringbuffer.push()
            self.allocator.destroy(gc);
            self.allocator.destroy(user);
            logErr("Next.push: ringbuffer full after retry, task dropped", .{});
            return false;
        }
        // 修改原因：HTTP/WS 调用方需要知道是否入队成功，失败时才能回收请求缓冲。
        return true;
    }

    /// ── Next.chainGoSubmit ─────────────────────────────────
    ///
    /// 编程模型：Go（IO 线程 fiber，异步 DB/NATS 等）→ Submit（worker 池）→ 响应。
    /// 同一 Ctx 流经两个阶段。execGo 异步收集全部数据后才触发 execSubmit，
    /// 无需手动分配 DeferredResponse。
    ///
    /// 用法（handler 中一行搞定）：
    ///   try Next.chainGoSubmit(ctx, myCtx,
    ///       execDb,       // fn(*MyCtx, complete) — IO 线程 fiber，collect 500 rows 后调 complete
    ///       execCompute,  // fn(*MyCtx) — worker 池
    ///       sendJson,     // fn(*MyCtx, *DeferredResponse) — 响应
    ///   );
    ///
    /// execGo 通过 complete 回调通知"已集齐所有数据"，此时自动切到 execSubmit。
    pub fn chainGoSubmit(
        comptime T: type,
        http_ctx: *Context,
        user_ctx: T,
        comptime execGo: fn (*T, *const fn (?*anyopaque, []const u8) void) void,
        comptime execSubmit: fn (*T) void,
        comptime respond: fn (*T, *DeferredResponse) void,
    ) !void {
        const svr = http_ctx.server orelse return;
        const server: *AsyncServer = @ptrCast(@alignCast(svr));
        const alloc = http_ctx.allocator;

        const resp = try alloc.create(DeferredResponse);
        errdefer alloc.destroy(resp);
        resp.* = .{ .server = server, .conn_id = http_ctx.conn_id, .allocator = alloc };

        // ChainWrap.user 紧邻 chain 字段，execGo 收到 &w.user 后可
        // 通过 @fieldParentPtr("user", user_ptr) 回到 ChainWrap
        const w = try alloc.create(ChainWrap(T));
        errdefer alloc.destroy(w);
        w.* = .{ .user = user_ctx, .chain = .{ .resp = resp, .allocator = alloc } };

        http_ctx.deferred = true;

        if (!go(
            ChainWrap(T),
            w.*,
            struct {
                fn run(
                    wrap: *ChainWrap(T),
                    complete: *const fn (?*anyopaque, []const u8) void,
                ) void {
                    execGo(&wrap.user, struct {
                        fn done(caller_ctx: ?*anyopaque, data: []const u8) void {
                            const uptr: *T = @ptrCast(@alignCast(caller_ctx.?));
                            const w2: *ChainWrap(T) = @fieldParentPtr("user", uptr);
                            const alloc2 = w2.chain.allocator;
                            const resp2 = w2.chain.resp;

                            const sc = alloc2.create(ChainSubmitCtx(T)) catch {
                                resp2.json(500, "{\"error\":\"OOM\"}");
                                alloc2.destroy(resp2);
                                return;
                            };
                            sc.* = .{ .user = w2.user, .resp = resp2, .allocator = alloc2 };

                            submit(
                                ChainSubmitCtx(T),
                                sc.*,
                                struct {
                                    fn run2(
                                        s: *ChainSubmitCtx(T),
                                        _: *const fn (?*anyopaque, []const u8) void,
                                    ) void {
                                        defer s.allocator.destroy(s.resp);
                                        execSubmit(&s.user);
                                        respond(&s.user, s.resp);
                                    }
                                }.run2,
                            );

                            _ = data;
                        }
                    }.done);

                    _ = complete;
                }
            }.run,
        )) {
            http_ctx.deferred = false;
            return error.QueueFull;
        }
        alloc.destroy(w);
    }

    const DeferredResponse = @import("../deferred.zig").DeferredResponse;
    const Context = @import("../http/context.zig").Context;
    const AsyncServer = @import("../http/async_server.zig").AsyncServer;
};

fn ChainWrap(comptime T: type) type {
    return struct {
        user: T,
        chain: ChainGoCtx,
    };
}

const ChainGoCtx = struct {
    resp: *Next.DeferredResponse,
    allocator: Allocator,
};

fn ChainSubmitCtx(comptime T: type) type {
    return struct {
        user: T,
        resp: *Next.DeferredResponse,
        allocator: Allocator,
    };
}
