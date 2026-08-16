/// ── Next.submit switches threads for CPU-heavy work (e.g. LLM inference) ──
///
/// Next.submit: runs on the thread pool, switching threads. In main you need:
///   try server.initPool4NextSubmit(2);
///
/// ⚠️ Use submit only for CPU-bound / blocking I/O.
///    For io_uring scenarios use Next.go, don't switch threads.
///
/// Usage: server.POST("/infer", inferHandler)

const std = @import("std");

const sws = @import("sws");
const Context = sws.Context;
const DeferredResponse = sws.DeferredResponse;
const AsyncServer = sws.AsyncServer;
const Next = sws.Next;

const InferCtx = struct {
    allocator: std.mem.Allocator,
    resp: *DeferredResponse,
    prompt: []const u8,
};

/// execFn runs on a thread pool thread (not the IO thread)
fn inferExec(c: *InferCtx, complete: *const fn (?*anyopaque, []const u8) void) void {
    defer c.allocator.destroy(c);
    defer c.allocator.destroy(c.resp);

    // ── CPU-heavy work: model inference ──
    // const output = llm.generate(c.prompt);   // blocks for tens of seconds

    const output = std.fmt.allocPrint(c.allocator,
        "{{\"reply\":\"Hello, you said: {s}\"}}", .{c.prompt}
    ) catch "{\"error\":\"oom\"}";
    defer c.allocator.free(output);

    c.resp.json(200, output);
    complete(c, "");
}

pub fn inferHandler(allocator: std.mem.Allocator, ctx: *Context) anyerror!void {
    const s: *AsyncServer = @ptrCast(@alignCast(ctx.server.?));

    const resp = try allocator.create(DeferredResponse);
    resp.* = .{ .server = s, .conn_id = ctx.conn_id, .allocator = allocator };

    ctx.deferred = true;
    Next.submit(InferCtx, .{
        .allocator = allocator,
        .resp = resp,
        .prompt = "Hello, how are you?",
    }, inferExec);
}
