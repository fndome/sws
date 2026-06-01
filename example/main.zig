const std = @import("std");

const sws = @import("sws");
const AsyncServer = sws.AsyncServer;

const query_go = @import("db_query_go.zig");
const llmr_submit = @import("cpu_llmr_submit.zig");

fn readPortEnv(default_port: u16) u16 {
    const raw = std.c.getenv("SWS_EXAMPLE_PORT") orelse return default_port;
    // 修改原因：示例程序跟随自测脚本端口配置，避免本机已有 9090 服务时无法启动。
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

    var server = try AsyncServer.init(alloc, io, bind_addr, null, 64, null, .{});
    defer server.deinit();

    try server.initPool4NextSubmit(2);
    try server.GET("/users", query_go.findUsers);
    try server.POST("/infer", llmr_submit.inferHandler);

    server.installSigterm();

    std.debug.print("listening on :{d}\n", .{port});
    try server.run();
}
