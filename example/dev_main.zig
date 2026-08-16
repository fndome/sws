const std = @import("std");
const sws = @import("sws");
const AsyncServer = sws.AsyncServer;

fn readPortEnv(default_port: u16) u16 {
    const raw = std.c.getenv("SWS_EXAMPLE_PORT") orelse return default_port;
    return std.fmt.parseInt(u16, std.mem.span(raw), 10) catch default_port;
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const port = readPortEnv(9090);
    const bind_addr = try std.fmt.allocPrint(alloc, "0.0.0.0:{d}", .{port});
    defer alloc.free(bind_addr);

    // DevServer uses std.net internally; io/tls tunables are ignored
    var server = try AsyncServer.init(alloc, undefined, .{ .listen_addr = bind_addr });
    defer server.deinit();

    try server.initPool4NextSubmit(2);

    try server.GET("/hello", struct {
        fn h(a: std.mem.Allocator, ctx: *sws.Context) anyerror!void {
            _ = a;
            var r = ctx.response();
            try r.status(200).json(.{ .message = "Hello from DevServer!" });
        }
    }.h);

    try server.GET("/users/:id", struct {
        fn h(a: std.mem.Allocator, ctx: *sws.Context) anyerror!void {
            _ = a;
            const id = ctx.param("id") orelse "?";
            var r = ctx.response();
            try r.status(200).json(.{ .user_id = id });
        }
    }.h);

    server.installSigterm();

    std.debug.print("DevServer listening on :{d}\n", .{port});
    try server.run();
}
