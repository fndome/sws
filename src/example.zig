const std = @import("std");
const Allocator = std.mem.Allocator;
const logErr = @import("async_logger.zig").logErr;

// ========== Re-exports ==========
pub const constants = @import("constants.zig");
pub const MAX_HEADER_BUFFER_SIZE = constants.MAX_HEADER_BUFFER_SIZE;
pub const MAX_RESPONSE_BUFFER_SIZE = constants.MAX_RESPONSE_BUFFER_SIZE;
pub const MAX_CQES_BATCH = constants.MAX_CQES_BATCH;
pub const RING_ENTRIES = constants.RING_ENTRIES;
pub const TASK_QUEUE_SIZE = constants.TASK_QUEUE_SIZE;
pub const RESPONSE_QUEUE_SIZE = constants.RESPONSE_QUEUE_SIZE;
pub const BUFFER_SIZE = constants.BUFFER_SIZE;
pub const BUFFER_POOL_SIZE = constants.BUFFER_POOL_SIZE;
pub const READ_BUF_COUNT = constants.READ_BUF_COUNT;
pub const READ_BUF_GROUP_ID = constants.READ_BUF_GROUP_ID;
pub const ACCEPT_USER_DATA = constants.ACCEPT_USER_DATA;
pub const MAX_FIXED_FILES = constants.MAX_FIXED_FILES;
pub const MAX_PATH_LENGTH = constants.MAX_PATH_LENGTH;

pub const Connection = @import("http/connection.zig").Connection;
pub const Context = @import("http/context.zig").Context;
pub const Middleware = @import("http/types.zig").Middleware;
pub const Handler = @import("http/types.zig").Handler;
pub const AsyncServer = @import("http/async_server.zig").AsyncServer;

pub const Frame = @import("ws/types.zig").Frame;
pub const WsServer = @import("ws/server.zig").WsServer;

pub const SubmitQueue = @import("next/queue.zig").SubmitQueue;

// ========== 高级范式：用户自定义 io_uring 提交队列 ==========
// 用户在工作线程中创建 SubmitQueue，push Next（含 execute + on_complete 回调），
// 注册到 AsyncServer，IO 线程在每次事件循环中消费队列、提交 SQE、回调 completion。
//
// 典型场景：异步 MySQL 查询（在 io_uring 上执行 READV/WRITEV/SENDTO/RECVFROM）
//
// 用法示意：
// ====================================================================
// const mysql: type = struct {
//     const QueryCtx = struct {
//         fd: i32,            // MySQL TCP 连接 fd
//         buf: [4096]u8,      // 读/写缓冲区
//         done: bool = false,
//     };
//
//     fn submitQuery(server: *AsyncServer, queue: *SubmitQueue, sql: []const u8, fd: i32) !void {
//         var ctx = try server.allocator.create(QueryCtx);
//         ctx.* = .{ .fd = fd, .buf = undefined };
//         @memcpy(ctx.buf[0..sql.len], sql);
//
//         if (!queue.push(.{
//             .prepare = struct {
//                 fn p(sqe: *linux.io_uring_sqe) void {
//                     sqe.* = .{
//                         .opcode = .IORING_OP_WRITEV,
//                         .fd = fd,
//                         .addr = @intFromPtr(&ctx.buf),
//                         .len = sql.len,
//                         .off = 0,
//                         .flags = 0,
//                     };
//                 }
//             }.p,
//             .on_cqe = struct {
//                 fn c(cqe: *const linux.io_uring_cqe) void {
//                     if (cqe.res >= 0) {
//                         // 写成功，提交 READV 读响应
//                         _ = queue.push(.{
//                             .prepare = struct {
//                                 fn p2(sqe2: *linux.io_uring_sqe) void {
//                                     sqe2.* = .{
//                                         .opcode = .IORING_OP_READV,
//                                         .fd = fd,
//                                         .addr = @intFromPtr(&ctx.buf),
//                                         .len = ctx.buf.len,
//                                         .off = 0,
//                                         .flags = 0,
//                                     };
//                                 }
//                             }.p2,
//                             .on_cqe = struct {
//                                 fn c2(cqe2: *const linux.io_uring_cqe) void {
//                                     // MySQL 协议解析 ctx.buf[0..cqe2.res]
//                                     ctx.done = true;
//                                 }
//                             }.c2,
//                         });
//                     }
//                 }
//             }.c,
//         })) {
//             // 队列满，降级或等待
//         }
//     }
// };
// ====================================================================

pub const IoUringUserPattern = struct {
    /// 创建一个 SubmitQueue，注册到 server，在 worker/handler 中 push 任务。
    /// IO 线程自动消费、提交、回调，无需用户干预。
    pub fn createAndRegister(server: *AsyncServer) !*SubmitQueue {
        const q = try server.allocator.create(SubmitQueue);
        q.* = SubmitQueue.init();
        try server.registerSubmitQueue(q);
        return q;
    }
};

// ========== Example ==========
const Example = struct {
    fn jwtMiddleware(allocator: Allocator, ctx: *Context) anyerror!bool {
        _ = allocator;
        std.debug.print("[Middleware] Request: {s}\n", .{ctx.path});
        ctx.text(401, "Unauthorized") catch |err| {
            logErr("jwtMiddleware: ctx.text failed: {s}", .{@errorName(err)});
        };
        return true;
    }

    fn logMiddleware(allocator: Allocator, ctx: *Context) anyerror!bool {
        _ = allocator;
        if (std.mem.startsWith(u8, ctx.path, "/admin")) {
            var it = std.mem.splitSequence(u8, ctx.request_data, "\r\n");
            while (it.next()) |line| {
                if (std.ascii.startsWithIgnoreCase(line, "Authorization:")) {
                    return false;
                }
            }
            std.debug.print("Auth denied for path={s}\n", .{ctx.path});
            return true;
        }
        return false;
    }

    fn helloHandler(allocator: Allocator, ctx: *Context) anyerror!void {
        const body = try std.fmt.allocPrint(allocator, "{{\"message\":\"Hello from worker! path={s}\"}}", .{ctx.path});
        ctx.body = body;
        ctx.content_type = .json;
        ctx.status = 200;
    }

    fn httpMethodHandler(allocator: Allocator, ctx: *Context) anyerror!void {
        const method = ctx.method();
        const request_body = ctx.requestBody();
        // 修改原因：自测需要覆盖常见 HTTP 方法，并验证 PUT/PATCH/POST 的 JSON body 会被业务层读到后按 JSON 返回。
        const body = if (request_body.len > 0)
            try std.fmt.allocPrint(allocator, "{{\"method\":\"{s}\",\"body\":{s}}}", .{ method, request_body })
        else
            try std.fmt.allocPrint(allocator, "{{\"method\":\"{s}\",\"body\":null}}", .{method});
        ctx.body = body;
        ctx.content_type = .json;
        ctx.status = 200;
    }

    fn wsEchoHandler(conn_id: u64, frame: *const Frame, ctx: *anyopaque) void {
        if (frame.opcode == .text or frame.opcode == .binary) {
            const server = @as(*AsyncServer, @ptrCast(@alignCast(ctx)));
            server.ws_server.sendWsFrame(conn_id, frame.opcode, frame.payload) catch |err| {
                std.debug.print("ws send error: {}\n", .{err});
            };
        }
    }

    fn readPortEnv(default_port: u16) u16 {
        const raw = std.c.getenv("SWS_EXAMPLE_PORT") orelse return default_port;
        // 修改原因：自测脚本需要可切换端口，避免旧测试进程占用固定 9090 导致无法验证。
        return std.fmt.parseInt(u16, std.mem.span(raw), 10) catch default_port;
    }

    pub fn main() !void {
        var gpa = std.heap.DebugAllocator(.{}){};
        defer _ = gpa.deinit();
        const alloc = gpa.allocator();

        var io_backend = std.Io.Threaded.init(alloc, .{});
        defer io_backend.deinit();
        const io = io_backend.io();

        const port = readPortEnv(9090);
        const bind_addr = try std.fmt.allocPrint(alloc, "0.0.0.0:{d}", .{port});
        defer alloc.free(bind_addr);

        var server = try AsyncServer.init(alloc, io, bind_addr, null, 64);
        defer server.deinit();

        server.config(.idle_timeout_ms, 30000);

        try server.useThenRespondImmediately("/antpath-verify", jwtMiddleware);
        try server.use("/admin", logMiddleware);
        try server.GET("/hello", helloHandler);
        try server.GET("/http-method", httpMethodHandler);
        try server.POST("/http-method", httpMethodHandler);
        try server.PUT("/http-method", httpMethodHandler);
        try server.PATCH("/http-method", httpMethodHandler);
        try server.DELETE("/http-method", httpMethodHandler);
        try server.GET("/admin/dashboard", helloHandler);
        try server.ws("/echo", wsEchoHandler);

        std.debug.print("Server listening on http://0.0.0.0:{d}\n", .{port});
        try server.run();
    }
};

pub fn main() !void {
    try Example.main();
}
