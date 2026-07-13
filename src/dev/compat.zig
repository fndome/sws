const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag == .linux) {
        @compileError("CompatServer wraps DevServer for macOS development. Use the real AsyncServer on Linux.");
    }
    if (builtin.os.tag == .windows) {
        @compileError("CompatServer on Windows requires Winsock2 bindings (TODO). Use WSL for development.");
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

    pub const InitConfig = struct {
        max_connections: u32 = 0,
        buffer_pool_size: u32 = 0,
        large_pool_capacity: u32 = 0,
    };

    pub fn init(
        allocator: Allocator,
        io: std.Io,
        bind_addr: []const u8,
        app_ctx: ?*anyopaque,
        fiber_stack_size_kb: u16,
        tls_auth: ?*anyopaque,
        init_cfg: InitConfig,
    ) !CompatServer {
        _ = io;
        _ = app_ctx;
        _ = fiber_stack_size_kb;
        _ = tls_auth;
        _ = init_cfg;
        const inner = try DevServer.init(allocator, bind_addr);
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
