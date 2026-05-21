const std = @import("std");
const Allocator = std.mem.Allocator;

const logErr = @import("../async_logger.zig").logErr;
const AsyncServer = @import("async_server.zig").AsyncServer;
const Context = @import("context.zig").Context;

pub const DeferredNode = struct {
    server: *AsyncServer,
    conn_id: u64,
    status: u16,
    ct: Context.ContentType,
    body: []u8,
};

pub fn deferredRespond(allocator: Allocator, node: *DeferredNode) void {
    const self = node.server;
    for (self.deferred_hooks.items) |hook| {
        hook(self, node);
    }
    if (self.getConn(node.conn_id)) |conn| {
        self.respondZeroCopy(conn, node.status, node.ct, node.body, "");
    } else {
        allocator.free(node.body);
    }
}

pub fn invokeOnIoThread(
    self: *AsyncServer,
    comptime T: type,
    ctx: T,
    comptime execFn: fn (allocator: Allocator, ctx_ptr: *T) void,
) !void {
    try self.rs.invoke.push(self.allocator, T, ctx, execFn);
}

pub fn sendDeferredResponse(self: *AsyncServer, conn_id: u64, status: u16, ct: Context.ContentType, body: []u8) void {
    const node = DeferredNode{
        .server = self,
        .conn_id = conn_id,
        .status = status,
        .ct = ct,
        .body = body,
    };
    invokeOnIoThread(self, DeferredNode, node, deferredRespond) catch {
        // InvokeQueue full: the deferred response cannot be delivered.
        // Free the body to avoid leaking and log the drop.
        logErr("sendDeferredResponse: invoke queue full, dropping response for conn_id={d}", .{conn_id});
        self.allocator.free(body);
    };
}

pub fn addHookDeferred(self: *AsyncServer, hook: *const fn (self_: *AsyncServer, node: *DeferredNode) void) !void {
    try self.deferred_hooks.append(self.allocator, hook);
}

pub fn addHookTick(self: *AsyncServer, hook: *const fn (self_: *AsyncServer) void) !void {
    try self.tick_hooks.append(self.allocator, hook);
}
