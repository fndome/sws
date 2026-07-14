const std = @import("std");
const Allocator = std.mem.Allocator;
const TcpHandler = @import("types.zig").TcpHandler;

pub const SendFn = *const fn (ctx: *anyopaque, conn_id: u64, data: []const u8) anyerror!void;

pub const TcpServer = struct {
    allocator: Allocator,
    handler: ?TcpHandler = null,
    send_fn: SendFn,
    ctx: *anyopaque,

    pub fn init(allocator: Allocator, send_fn: SendFn) TcpServer {
        return TcpServer{
            .allocator = allocator,
            .send_fn = send_fn,
            .ctx = undefined,
        };
    }

    pub fn deinit(self: *TcpServer) void {
        self.handler = null;
    }

    pub fn hasHandler(self: *const TcpServer) bool {
        return self.handler != null;
    }

    pub fn send(self: *TcpServer, conn_id: u64, data: []const u8) !void {
        try self.send_fn(self.ctx, conn_id, data);
    }
};

test "TcpServer basic" {
    const allocator = std.testing.allocator;

    const send_fn = struct {
        fn send(_: *anyopaque, _: u64, _: []const u8) !void {}
    }.send;

    var server = TcpServer.init(allocator, send_fn);
    server.ctx = @constCast(@ptrCast(&server));
    defer server.deinit();

    try std.testing.expect(!server.hasHandler());

    const handler = struct {
        fn h(_: u64, _: []u8) void {}
    }.h;
    server.handler = handler;
    try std.testing.expect(server.hasHandler());
}
