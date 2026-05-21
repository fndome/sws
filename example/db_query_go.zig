/// ── Next.go 查数据库（自然存在，无需 main 里初始化）──
///
/// Next.go: 推 ringbuffer → IO 线程 fiber 执行，不切线程。
/// server.GET 首次调用时自动 setDefault()，开箱即用。
///
/// 适用：io_uring 异步 DB

const std = @import("std");

const sws = @import("sws");
const Context = sws.Context;
const DeferredResponse = sws.DeferredResponse;
const AsyncServer = sws.AsyncServer;
const Next = sws.Next;

const Ctx = struct {
    allocator: std.mem.Allocator,
    resp: *DeferredResponse,
    sql: []const u8,
};

fn exec(c: *Ctx, complete: *const fn (?*anyopaque, []const u8) void) void {
    defer c.allocator.destroy(c);
    defer c.allocator.destroy(c.resp);
    // DB 查询
    c.resp.json(200, "[{\"id\":1}]");
    complete(c, "");
}

pub fn findUsers(allocator: std.mem.Allocator, ctx: *Context) anyerror!void {
    const s: *AsyncServer = @ptrCast(@alignCast(ctx.server.?));

    const resp = try allocator.create(DeferredResponse);
    resp.* = .{ .server = s, .conn_id = ctx.conn_id, .allocator = allocator };

    ctx.deferred = true;
    if (!Next.go(Ctx, .{ .allocator = allocator, .resp = resp, .sql = "SELECT * FROM users" }, exec)) {
        ctx.deferred = false;
        allocator.destroy(resp);
        return error.QueueFull;
    }
}
