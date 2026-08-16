const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag == .linux) {
        @compileError("CompatServer is for non-Linux dev. Use the real AsyncServer (io_uring) on Linux.");
    }
}

const Handler = @import("../http/types.zig").Handler;
const Middleware = @import("../http/types.zig").Middleware;
const DevServer = @import("server.zig").DevServer;
const WsHandler = @import("../ws/server.zig").WsHandler;

/// AsyncServer-compatible wrapper around DevServer.
/// Accepts the same init signature, delegates to DevServer internally.
/// Stubs out methods that only make sense for the io_uring server.
pub const CompatServer = struct {
    inner: DevServer,

    pub const TlsAuth = opaque {};

    /// Source-compatible mirror of the production `AsyncServer.Config`.
    /// The DevServer ignores io_uring-specific tunables but accepts them so
    /// non-Linux dev code shares the exact same `init` call shape as production.
    pub const Config = struct {
        listen_addr: []const u8,
        app_ctx: ?*anyopaque = null,
        tls_auth: ?*anyopaque = null,
        max_header_buffer_size: u32 = 0,
        max_response_buffer_size: u32 = 0,
        max_cqes_batch: u32 = 0,
        ring_entries: u32 = 0,
        task_queue_size: u32 = 0,
        response_queue_size: u32 = 0,
        buffer_size: u32 = 0,
        buffer_pool_size: u32 = 0,
        max_fixed_files: u32 = 0,
        max_path_length: u32 = 0,
        idle_timeout_ms: u64 = 0,
        write_timeout_ms: u64 = 0,
        fiber_stack_size_kb: u16 = 256,
        max_connections: u32 = 0,
        large_pool_capacity: u32 = 64,
        io_cpu: ?u6 = null,
        log_cpu: ?u6 = null,
    };

    pub fn init(allocator: Allocator, io: std.Io, config: Config) !CompatServer {
        _ = io;
        _ = config.tls_auth;
        _ = config.fiber_stack_size_kb;
        const inner = try DevServer.init(allocator, config.listen_addr, config.app_ctx);
        return .{ .inner = inner };
    }

    pub fn deinit(self: *CompatServer) void {
        self.inner.deinit();
    }

    pub fn initPool4NextSubmit(self: *CompatServer, count: usize) !void {
        _ = self;
        _ = count;
    }

    pub fn installSigterm(self: *CompatServer) void {
        _ = self;
    }

    pub fn GET(self: *CompatServer, path: []const u8, handler: Handler) !void {
        try self.inner.GET(path, handler);
    }
    pub fn POST(self: *CompatServer, path: []const u8, handler: Handler) !void {
        try self.inner.POST(path, handler);
    }
    pub fn PUT(self: *CompatServer, path: []const u8, handler: Handler) !void {
        try self.inner.PUT(path, handler);
    }
    pub fn PATCH(self: *CompatServer, path: []const u8, handler: Handler) !void {
        try self.inner.PATCH(path, handler);
    }
    pub fn DELETE(self: *CompatServer, path: []const u8, handler: Handler) !void {
        try self.inner.DELETE(path, handler);
    }
    pub fn ws(self: *CompatServer, path: []const u8, handler: WsHandler) !void {
        try self.inner.ws(path, handler);
    }
    pub fn use(self: *CompatServer, pattern: []const u8, middleware: Middleware) !void {
        _ = self;
        _ = pattern;
        _ = middleware;
    }

    pub fn run(self: *CompatServer) !void {
        try self.inner.run();
    }
};
