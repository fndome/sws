const std = @import("std");
const Allocator = std.mem.Allocator;

pub const AsyncServer = @import("example.zig").AsyncServer;
pub const DevServer = @import("dev/server.zig").DevServer;
pub const Connection = @import("example.zig").Connection;
pub const Context = @import("example.zig").Context;
pub const RouteParam = @import("http/context.zig").RouteParam;
pub const Middleware = @import("example.zig").Middleware;
pub const Handler = @import("example.zig").Handler;
pub const PathRule = @import("antpath.zig").PathRule;
pub const RingBuffer = @import("spsc_ringbuffer.zig").RingBuffer;

pub const WsServer = @import("ws/server.zig").WsServer;
pub const WsHandler = @import("ws/server.zig").WsHandler;
pub const Frame = @import("ws/types.zig").Frame;
pub const Opcode = @import("ws/types.zig").Opcode;

pub const TcpServer = @import("tcp/server.zig").TcpServer;
pub const TcpHandler = @import("tcp/types.zig").TcpHandler;

pub const UdpServer = @import("udp/server.zig").UdpServer;
pub const UdpHandler = @import("udp/types.zig").UdpHandler;
pub const SenderAddr = @import("udp/types.zig").SenderAddr;

pub const SubmitQueue = @import("next/queue.zig").SubmitQueue;
pub const QueueItem = @import("next/queue.zig").Item;
pub const Next = @import("next/next.zig").Next;
pub const chainGoSubmit = @import("next/next.zig").Next.chainGoSubmit;
pub const StreamHandle = @import("next/chunk_stream.zig").StreamHandle;
pub const setStream = @import("stack_pool_sticker.zig").setStream;
pub const clearStream = @import("stack_pool_sticker.zig").clearStream;
pub const BufferBlockPool = @import("shared/large_buffer_pool.zig").BufferBlockPool;
pub const DeferredResponse = @import("deferred.zig").DeferredResponse;

pub const Fiber = @import("next/fiber.zig").Fiber;
pub const RingShared = @import("shared/ring_shared.zig").RingShared;
pub const RingSharedClient = @import("shared/tcp_stream.zig").RingSharedClient;
pub const IORegistry = @import("shared/io_registry.zig").IORegistry;
pub const Pipe = @import("next/pipe.zig").Pipe;
pub const DnsCache = @import("dns/cache.zig").DnsCache;
pub const DnsResolver = @import("dns/resolver.zig").DnsResolver;
pub const InvokeQueue = @import("shared/io_invoke.zig").InvokeQueue;
pub const HttpRing = @import("client/ring.zig").HttpRing;
pub const HttpClient = @import("client/http_client.zig").HttpClient;
pub const HttpCaresDns = @import("client/dns.zig").CaresDns;
pub const TinyCache = @import("client/tiny_cache.zig").TinyCache;
pub const StackSlot = @import("stack_pool.zig").StackSlot;
pub const LargeBufferPool = @import("shared/large_buffer_pool.zig").LargeBufferPool;
pub const OVERSIZED_THRESHOLD = @import("stack_pool.zig").OVERSIZED_THRESHOLD;
pub const TlsConfig = @import("tls/tls.zig").TlsConfig;
pub const TlsStream = @import("tls/tls.zig").TlsStream;
pub const TlsAuth = @import("http/async_server.zig").TlsAuth;

pub const CustomTemplate = struct {
    pub fn createAndRegister(server: *AsyncServer) !*SubmitQueue {
        const q = try server.allocator.create(SubmitQueue);
        q.* = SubmitQueue.init();
        try server.registerSubmitQueue(q);
        return q;
    }
};

pub fn deferToQueue(
    comptime T: type,
    ctx: *Context,
    queue: *SubmitQueue,
    userCtx: T,
    comptime execFn: fn (*T, *const fn (?*anyopaque, []const u8) void) void,
    comptime doneFn: fn (*T, *DeferredResponse, []const u8) void,
) !void {
    const s = ctx.server orelse return;
    const server: *AsyncServer = @ptrCast(@alignCast(s));

    const resp = try ctx.allocator.create(DeferredResponse);
    errdefer ctx.allocator.destroy(resp);
    resp.* = .{ .server = server, .conn_id = ctx.conn_id, .allocator = ctx.allocator };

    const user = try ctx.allocator.create(T);
    errdefer ctx.allocator.destroy(user);
    user.* = userCtx;

    const W = struct {
        allocator: Allocator,
        resp: *DeferredResponse,
        user: *T,
    };
    const w = try ctx.allocator.create(W);
    errdefer ctx.allocator.destroy(w);
    w.* = .{ .allocator = ctx.allocator, .resp = resp, .user = user };

    ctx.deferred = true;

    if (!queue.push(QueueItem{
        .ctx = w,
        .execute = struct {
            fn exec(c: ?*anyopaque, complete: *const fn (?*anyopaque, []const u8) void) void {
                const ww: *W = @ptrCast(@alignCast(c));
                execFn(ww.user, complete);
            }
        }.exec,
        .on_complete = struct {
            fn done(c: ?*anyopaque, result: []const u8) void {
                const ww: *W = @ptrCast(@alignCast(c));
                defer ww.allocator.destroy(ww);
                defer ww.allocator.destroy(ww.user);
                defer ww.allocator.destroy(ww.resp);
                doneFn(ww.user, ww.resp, result);
            }
        }.done,
    })) {
        ctx.deferred = false;
        return error.QueueFull;
    }
}

test {
    // Pure modules with host-runnable tests (no io_uring/linux dependency).
    _ = @import("client/http_parse.zig");
    _ = @import("http/route_match.zig");
    _ = @import("http/write_progress.zig");
    _ = @import("shared/tcp_stream_helpers.zig");
    _ = @import("dns/packet.zig");
    _ = @import("dns/cache.zig");
    _ = @import("spsc_ringbuffer.zig");
}
