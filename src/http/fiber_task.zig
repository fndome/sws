const std = @import("std");

const AsyncServer = @import("async_server.zig").AsyncServer;
const WsHandler = @import("../ws/server.zig").WsHandler;
const ws_frame = @import("../ws/frame.zig");
const NO_READ_BUFFER_BID = @import("../constants.zig").NO_READ_BUFFER_BID;

const Fiber = @import("../next/fiber.zig").Fiber;

pub const WsTaskCtx = struct {
    tag: u32,
    server: *AsyncServer,
    conn_id: u64,
    read_bid: u16 = NO_READ_BUFFER_BID,
    payload_tier: u8 = 0,
    handler: WsHandler,
    frame: ws_frame.Frame,
    payload_buf: []u8,
};

pub fn wsTaskExec(caller_ctx: ?*anyopaque, complete: *const fn (?*anyopaque, []const u8) void) void {
    const t: *WsTaskCtx = @ptrCast(@alignCast(caller_ctx));
    std.debug.assert(t.tag == 0x57530001);
    t.handler(t.conn_id, &t.frame, t.server.ws_server.ctx);
    complete(t, "");
}

pub fn wsTaskExecWrapperWithOwnership(t: *WsTaskCtx, complete: *const fn (?*anyopaque, []const u8) void) void {
    wsTaskExec(t, complete);
    wsTaskRecycle(t);
}

fn wsTaskRecycle(t: *WsTaskCtx) void {
    std.debug.assert(t.tag == 0x57530001);
    // Always return the read buffer bid to io_uring. If the connection
    // was freed before this task completed, skip connection state updates
    // but still replenish the buffer. markReplenish has internal duplicate-
    // bid detection for safety.
    // read_bid == NO_READ_BUFFER_BID is the "no buffer" sentinel set by the TLS
    // decrypted path (ciphertext already recycled inline). A real read into
    // buffer id 0 must still be replenished, so compare against the sentinel.
    if (t.read_bid != NO_READ_BUFFER_BID) {
        t.server.buffer_pool.markReplenish(t.read_bid);
    }
    if (t.server.connections.getPtr(t.conn_id)) |conn| {
        conn.read_buf_recycled = true;
        conn.read_len = 0;
    }
    // 修改原因：Next.push 会复制任务并自行释放任务内存，这里只释放任务持有的 payload。
    t.server.buffer_pool.freeTieredWriteBuf(t.payload_buf, t.payload_tier);
}

pub fn wsTaskCleanup(t: *WsTaskCtx) void {
    wsTaskRecycle(t);
    t.server.ws_ctx_pool.destroy(t);
}

pub fn wsTaskComplete(caller_ctx: ?*anyopaque, _: []const u8) void {
    const t: *WsTaskCtx = @ptrCast(@alignCast(caller_ctx));
    std.debug.assert(t.tag == 0x57530001);
    // isYielded is true only when the handler yielded and was later
    // resumed. In that case onWsFrame skipped the read re-arm; do it now.
    const deferred_read = Fiber.isYielded();
    t.server.shared_fiber_active = false;
    wsTaskRecycle(t);
    if (deferred_read) {
        if (t.server.connections.getPtr(t.conn_id)) |conn| {
            if (conn.state != .ws_writing) {
                conn.state = .ws_reading;
                t.server.submitRead(t.conn_id, conn) catch {
                    t.server.closeConn(t.conn_id, conn.fd);
                };
            }
        }
    }
    t.server.ws_ctx_pool.destroy(t);
}
