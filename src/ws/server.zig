const std = @import("std");
const Allocator = std.mem.Allocator;
const Frame = @import("types.zig").Frame;
const Opcode = @import("types.zig").Opcode;

/// WebSocket message handler, invoked on the I/O thread; must be non-blocking and return quickly.
/// conn_id: unique connection identifier
/// frame:   the received frame (lifetime managed by the caller; the handler should not keep a reference)
/// ctx:     user context (passed in via the WsServer ctx field)
pub const WsHandler = *const fn (conn_id: u64, frame: *const Frame, ctx: *anyopaque) void;

/// Function type for sending a WebSocket frame, provided by the parent server.
pub const SendFn = *const fn (ctx: *anyopaque, conn_id: u64, opcode: Opcode, payload: []const u8) anyerror!void;

pub const WsServer = struct {
    allocator: Allocator,
    handlers: std.StringHashMap(WsHandler),
    active: std.AutoHashMap(u64, WsHandler),
    send_fn: SendFn,
    ctx: *anyopaque,

    pub fn init(allocator: Allocator, send_fn: SendFn) WsServer {
        return WsServer{
            .allocator = allocator,
            .handlers = std.StringHashMap(WsHandler).init(allocator),
            .active = std.AutoHashMap(u64, WsHandler).init(allocator),
            .send_fn = send_fn,
            .ctx = undefined,
        };
    }

    pub fn deinit(self: *WsServer) void {
        self.active.deinit();
        var it = self.handlers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.handlers.deinit();
    }

    /// Close all active connections (by sending a Close frame).
    /// The caller should invoke this before destroying WsServer, then close the underlying TCP connections.
    pub fn closeAllActive(self: *WsServer) void {
        var it = self.active.iterator();
        while (it.next()) |entry| {
            self.send_fn(self.ctx, entry.key_ptr.*, .close, "") catch |err| {
                std.debug.print("ws closeAllActive: failed to send close to conn {}: {}\n", .{ entry.key_ptr.*, err });
            };
        }
        self.active.clearRetainingCapacity();
    }

    pub fn register(self: *WsServer, path: []const u8, handler: WsHandler) !void {
        const key = try self.allocator.dupe(u8, path);
        // The WebSocket route table must own the path key; otherwise a caller-passed temporary buffer would leave a dangling key.
        errdefer self.allocator.free(key);
        const gop = try self.handlers.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(key);
        }
        gop.value_ptr.* = handler;
    }

    pub fn hasHandlers(self: *const WsServer) bool {
        return self.handlers.count() > 0;
    }

    pub fn getHandler(self: *const WsServer, path: []const u8) ?WsHandler {
        return self.handlers.get(path);
    }

    pub fn addActive(self: *WsServer, conn_id: u64, handler: WsHandler) !void {
        try self.active.put(conn_id, handler);
    }

    pub fn removeActive(self: *WsServer, conn_id: u64) void {
        _ = self.active.remove(conn_id);
    }

    pub fn getActive(self: *const WsServer, conn_id: u64) ?WsHandler {
        return self.active.get(conn_id);
    }

    pub fn sendWsFrame(self: *WsServer, conn_id: u64, opcode: Opcode, payload: []const u8) !void {
        try self.send_fn(self.ctx, conn_id, opcode, payload);
    }
};

/// Automatically respond to WebSocket control frames.
/// Returns true when the connection should be closed (a Close frame was received).
pub fn handleControlFrame(server: *WsServer, conn_id: u64, opcode: Opcode, payload: []const u8) !bool {
    switch (opcode) {
        .ping => {
            try server.sendWsFrame(conn_id, .pong, payload);
            return false;
        },
        .pong => return false,
        .close => {
            try server.sendWsFrame(conn_id, .close, payload);
            return true;
        },
        else => return false,
    }
}

test "WsServer basic" {
    const allocator = std.testing.allocator;

    var last_sent: struct { conn_id: u64, opcode: Opcode } = undefined;
    _ = &last_sent;
    const send_fn = struct {
        fn send(ctx: *anyopaque, conn_id: u64, opcode: Opcode, payload: []const u8) !void {
            _ = payload;
            const state = @as(*@TypeOf(last_sent), @ptrCast(@alignCast(ctx)));
            state.* = .{ .conn_id = conn_id, .opcode = opcode };
        }
    }.send;

    var state = last_sent;
    var server = WsServer.init(allocator, send_fn);
    server.ctx = &state;
    defer server.deinit();

    try server.register("/test", struct {
        fn h(_: u64, _: *const Frame, _: *anyopaque) void {}
    }.h);

    try std.testing.expect(server.getHandler("/test") != null);
    try std.testing.expect(server.getHandler("/notfound") == null);
    try std.testing.expect(server.hasHandlers());

    try server.addActive(42, server.getHandler("/test").?);
    try std.testing.expect(server.getActive(42) != null);
    server.removeActive(42);
    try std.testing.expect(server.getActive(42) == null);
}

test "WsServer register owns path keys" {
    const allocator = std.testing.allocator;

    const send_fn = struct {
        fn send(_: *anyopaque, _: u64, _: Opcode, _: []const u8) !void {}
    }.send;
    const handler = struct {
        fn h(_: u64, _: *const Frame, _: *anyopaque) void {}
    }.h;

    var server = WsServer.init(allocator, send_fn);
    server.ctx = undefined;
    defer server.deinit();

    const dynamic_path = try allocator.dupe(u8, "/dynamic");
    try server.register(dynamic_path, handler);
    allocator.free(dynamic_path);

    try std.testing.expect(server.getHandler("/dynamic") != null);
    try server.register("/dynamic", handler);
    try std.testing.expect(server.getHandler("/dynamic") != null);
}
