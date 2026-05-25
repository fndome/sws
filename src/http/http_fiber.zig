const std = @import("std");
const Allocator = std.mem.Allocator;

const AsyncServer = @import("async_server.zig").AsyncServer;
const Context = @import("context.zig").Context;
const logErr = @import("http_helpers.zig").logErr;
const sticker = @import("../stack_pool_sticker.zig");

pub const HttpTaskCtx = struct {
    tag: u32,
    server: *AsyncServer,
    conn_id: u64,
    read_bid: u16 = 0,
    method_buf: [16]u8 = [_]u8{0} ** 16,
    method_len: u4 = 0,
    path_buf: [256]u8 = [_]u8{0} ** 256,
    path_len: u8 = 0,
    request_data: []u8,
    request_data_owned: bool = false,
    body_data: ?[]u8 = null,
};

fn responseHeaderItems(headers: ?*const std.ArrayList(u8)) []const u8 {
    // 修改原因：响应头只在 respondZeroCopy 同步组包时读取，不能因为复制 OOM 就静默丢掉调用方设置的 headers。
    if (headers) |h| return h.items;
    return "";
}

pub fn httpTaskExec(caller_ctx: ?*anyopaque, complete: *const fn (?*anyopaque, []const u8) void) void {
    const t: *HttpTaskCtx = @ptrCast(@alignCast(caller_ctx));
    std.debug.assert(t.tag == 0x48540001);
    const server = t.server;

    const method = t.method_buf[0..t.method_len];
    const path = t.path_buf[0..t.path_len];
    const req_data = t.request_data;

    var request_body: []const u8 = "";
    if (t.body_data) |bd| {
        // 修改原因：请求体不能占用 ctx.body；ctx.body 是响应体，混用会让中间件误判已响应。
        request_body = bd;
        t.body_data = null;
        defer server.large_pool.release(bd);
    }

    var ctx = Context{
        .request_data = req_data,
        .request_body = request_body,
        .path = path,
        .app_ctx = server.app_ctx,
        .allocator = server.allocator,
        .status = 200,
        .content_type = .plain,
        .body = null,
        .headers = null,
        .conn_id = t.conn_id,
        .server = @ptrCast(server),
    };
    defer ctx.deinit();

    var handled = false;

    // Extract the common iteration pattern: for each middleware in a list,
    // call it, handle errors, and stop on true return or body set.
    // Previously duplicated 3x (global/precise/wildcard) with identical logic.
    const runMiddlewareList = struct {
        fn run(server2: *AsyncServer, ctx2: *Context, handled2: *bool, list: []const @import("types.zig").Middleware) void {
            for (list) |mw| {
                const stop = mw(server2.allocator, ctx2) catch |err| {
                    logErr("middleware error: {s}", .{@errorName(err)});
                    if (ctx2.body == null) ctx2.text(500, @errorName(err)) catch {};
                    handled2.* = true;
                    break;
                };
                if (stop or ctx2.body != null) {
                    handled2.* = true;
                    break;
                }
            }
        }
    }.run;

    if (server.middlewares.has_global) {
        runMiddlewareList(server, &ctx, &handled, server.middlewares.global.items);
    }

    if (!handled) {
        if (server.middlewares.precise.get(path)) |list| {
            runMiddlewareList(server, &ctx, &handled, list.items);
        }
    }

    if (!handled) {
        for (server.middlewares.wildcard.items) |entry| {
            if (entry.rule.match(path)) {
                runMiddlewareList(server, &ctx, &handled, entry.list.items);
                if (handled) break;
            }
        }
    }

    if (!handled) {
        var key_buf: [512]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "{s}:{s}", .{ method, path }) catch null;
        if (key) |k| {
            if (server.handlers.get(k)) |handler| {
                handler(server.allocator, &ctx) catch |err| {
                    logErr("handler error: {s}", .{@errorName(err)});
                    ctx.text(500, @errorName(err)) catch {};
                };
            } else {
                ctx.text(404, "Not Found") catch {};
            }
        } else {
            ctx.text(404, "Not Found") catch {};
        }
    }

    if (ctx.deferred) {
        complete(t, "");
        return;
    }

    const headers_str = responseHeaderItems(if (ctx.headers) |*headers| headers else null);

    const response_body = ctx.body orelse {
        logErr("no response body set for conn_id={d}", .{t.conn_id});
        if (server.connections.getPtr(t.conn_id)) |conn| {
            const body = server.allocator.dupe(u8, "no response body set for conn") catch {
                complete(t, "");
                return;
            };
            server.respondZeroCopy(conn, 500, .plain, body, headers_str);
        }
        complete(t, "");
        return;
    };

    if (server.connections.getPtr(t.conn_id)) |conn| {
        server.respondZeroCopy(conn, ctx.status, ctx.content_type, response_body, headers_str);
    } else {
        server.allocator.free(response_body);
    }
    ctx.body = null;
    complete(t, "");
}

pub fn httpTaskExecWrapperWithOwnership(t: *HttpTaskCtx, complete: *const fn (?*anyopaque, []const u8) void) void {
    httpTaskExec(t, complete);
    httpTaskRecycle(t);
}

fn httpTaskRecycle(t: *HttpTaskCtx) void {
    std.debug.assert(t.tag == 0x48540001);
    // Always return the read buffer bid to io_uring. If the connection
    // was freed before this task completed (close CQE arrived first),
    // skip connection state updates but still replenish the buffer.
    // markReplenish has internal duplicate-bid detection for safety.
    t.server.buffer_pool.markReplenish(t.read_bid);
    if (t.server.connections.getPtr(t.conn_id)) |conn| {
        conn.read_buf_recycled = true;
        conn.read_len = 0;
        const has_stream = conn.pool_idx != 0xFFFFFFFF and
            sticker.getStream(&t.server.pool.slots[conn.pool_idx]) != null;
        if (conn.state == .streaming or has_stream) {
            if (has_stream) conn.state = .streaming;
            t.server.submitRead(t.conn_id, conn) catch {
                t.server.closeConn(t.conn_id, conn.fd);
            };
        }
    }
    if (t.request_data_owned) {
        // 修改原因：跨 TCP 分片重组出来的 request_data 是堆副本，任务结束必须释放。
        t.server.allocator.free(t.request_data);
        t.request_data_owned = false;
    }
    if (t.body_data) |bd| {
        t.server.large_pool.release(bd);
        t.body_data = null;
    }
}

pub fn httpTaskCleanup(t: *HttpTaskCtx) void {
    httpTaskRecycle(t);
    t.server.http_ctx_pool.destroy(t);
}

pub fn httpTaskComplete(caller_ctx: ?*anyopaque, _: []const u8) void {
    const t: *HttpTaskCtx = @ptrCast(@alignCast(caller_ctx));
    std.debug.assert(t.tag == 0x48540001);
    t.server.shared_fiber_active = false;
    httpTaskRecycle(t);
    t.server.http_ctx_pool.destroy(t);
}

test "responseHeaderItems borrows header storage" {
    var headers = std.ArrayList(u8).empty;
    defer headers.deinit(std.testing.allocator);
    try headers.appendSlice(std.testing.allocator, "X-Test: ok\r\n");

    try std.testing.expectEqualStrings("X-Test: ok\r\n", responseHeaderItems(&headers));
    try std.testing.expectEqualStrings("", responseHeaderItems(null));
}
