/// ── Next.go queries the database (naturally available, no init in main needed) ──
///
/// Next.go: pushes to the ringbuffer → runs on an IO thread fiber, no thread switch.
/// The scheduler is obtained lazily via `server.scheduler()` — no global instance.
///
/// Suitable for: io_uring async DB

const std = @import("std");

const sws = @import("sws");
const Context = sws.Context;
const DeferredResponse = sws.DeferredResponse;
const AsyncServer = sws.AsyncServer;

const Ctx = struct {
    allocator: std.mem.Allocator,
    resp: *DeferredResponse,
    sql: []const u8,
};

fn exec(c: *Ctx, complete: *const fn (?*anyopaque, []const u8) void) void {
    defer c.allocator.destroy(c);
    defer c.allocator.destroy(c.resp);
    // DB query
    c.resp.json(200, "[{\"id\":1}]");
    complete(c, "");
}

pub fn findUsers(allocator: std.mem.Allocator, ctx: *Context) anyerror!void {
    const s: *AsyncServer = @ptrCast(@alignCast(ctx.server.?));

    const resp = try allocator.create(DeferredResponse);
    resp.* = .{ .server = s, .conn_id = ctx.conn_id, .allocator = allocator };

    ctx.deferred = true;
    const scheduler = try s.scheduler();
    if (!scheduler.go(Ctx, .{ .allocator = allocator, .resp = resp, .sql = "SELECT * FROM users" }, exec)) {
        ctx.deferred = false;
        allocator.destroy(resp);
        return error.QueueFull;
    }
}
