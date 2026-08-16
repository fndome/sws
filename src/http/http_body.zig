const std = @import("std");
const linux = std.os.linux;

const AsyncServer = @import("async_server.zig").AsyncServer;
const Connection = @import("connection.zig").Connection;
const StackSlot = @import("../stack_pool.zig").StackSlot;
const packUserData = @import("../stack_pool.zig").packUserData;
const sticker = @import("../stack_pool_sticker.zig");
const StreamHandle = @import("../next/chunk_stream.zig").StreamHandle;
const logErr = @import("http_helpers.zig").logErr;

const BodyReadWindow = struct {
    offset: usize,
    remaining: usize,
};

fn bodyReadWindow(slot: *const StackSlot, backing_len: usize) ?BodyReadWindow {
    const offset: usize = @intCast(slot.line3.large_buf_offset);
    const target_len: usize = @intCast(slot.line3.large_buf_len);
    if (offset > target_len or offset > backing_len) return null;
    return .{
        .offset = offset,
        .remaining = @min(target_len - offset, backing_len - offset),
    };
}

fn closeInvalidBodyRead(self: *AsyncServer, conn_id: u64, conn: *Connection, slot: *StackSlot, clear_stream: bool) void {
    if (slot.line3.large_buf_ptr != 0) {
        const buf: []u8 = @as([*]u8, @ptrFromInt(slot.line3.large_buf_ptr))[0..slot.line3.large_buf_len];
        self.large_pool.release(buf);
        slot.line3.large_buf_ptr = 0;
    }
    if (clear_stream) sticker.clearStream(slot);
    self.closeConn(conn_id, conn.fd);
}

pub fn submitBodyRead(self: *AsyncServer, conn: *Connection, large_buf: []u8, slot: *StackSlot) !void {
    // A stray CQE or inconsistent state can push offset past the target body length; validating first avoids u32/usize underflow and slice OOB.
    const window = bodyReadWindow(slot, large_buf.len) orelse return error.InvalidBodyOffset;
    if (window.remaining == 0) return;
    const user_data = packUserData(conn.gen_id, conn.pool_idx);
    const fd = conn.ioFd();
    const dest = large_buf[window.offset..][0..window.remaining];
    const sqe = try self.ring.read(user_data, fd, .{ .buffer = dest }, 0);
    if (conn.hasFixedFile()) sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn onBodyChunk(self: *AsyncServer, conn_id: u64, res: i32) void {
    const conn = self.getConn(conn_id) orelse return;
    const slot = self.connSlot(conn) orelse {
        if (res <= 0) self.closeConn(conn_id, conn.fd);
        return;
    };

    if (sticker.getStream(slot)) |stream_ptr| {
        const stream: *StreamHandle = @ptrCast(@alignCast(stream_ptr));
        if (res <= 0) {
            _ = stream.finish();
            sticker.clearStream(slot);
            if (slot.line3.large_buf_ptr != 0) {
                const buf: []u8 = @as([*]u8, @ptrFromInt(slot.line3.large_buf_ptr))[0..slot.line3.large_buf_len];
                self.large_pool.release(buf);
                slot.line3.large_buf_ptr = 0;
            }
            self.closeConn(conn_id, conn.fd);
            return;
        }
        const n = @as(usize, @intCast(res));
        if (slot.line3.large_buf_ptr == 0) {
            self.closeConn(conn_id, conn.fd);
            return;
        }
        const buf: []u8 = @as([*]u8, @ptrFromInt(slot.line3.large_buf_ptr))[0..slot.line3.large_buf_len];
        const window = bodyReadWindow(slot, buf.len) orelse {
            closeInvalidBodyRead(self, conn_id, conn, slot, true);
            return;
        };
        // The streaming body's CQE length must fit within the remaining window, or the slice before feed would go OOB.
        if (n > window.remaining) {
            closeInvalidBodyRead(self, conn_id, conn, slot, true);
            return;
        }
        const data = buf[window.offset..][0..n];
        _ = stream.feed(data);
        slot.line3.large_buf_offset += @intCast(n);
        submitBodyRead(self, conn, buf, slot) catch {
            self.large_pool.release(buf);
            slot.line3.large_buf_ptr = 0;
            sticker.clearStream(slot);
            self.closeConn(conn_id, conn.fd);
        };
        return;
    }

    if (res <= 0) {
        if (slot.line3.large_buf_ptr != 0) {
            const buf: []u8 = @as([*]u8, @ptrFromInt(slot.line3.large_buf_ptr))[0..slot.line3.large_buf_len];
            self.large_pool.release(buf);
            slot.line3.large_buf_ptr = 0;
        }
        self.closeConn(conn_id, conn.fd);
        return;
    }
    if (slot.line3.large_buf_ptr == 0) {
        self.closeConn(conn_id, conn.fd);
        return;
    }
    const buf: []u8 = @as([*]u8, @ptrFromInt(slot.line3.large_buf_ptr))[0..slot.line3.large_buf_len];
    const n = @as(usize, @intCast(res));
    const window = bodyReadWindow(slot, buf.len) orelse {
        closeInvalidBodyRead(self, conn_id, conn, slot, false);
        return;
    };
    // Non-streaming body must also reject CQEs exceeding the remaining Content-Length to avoid an OOB offset slipping into processing.
    if (n > window.remaining) {
        closeInvalidBodyRead(self, conn_id, conn, slot, false);
        return;
    }
    slot.line3.large_buf_offset += @intCast(n);
    if (slot.line3.large_buf_offset >= slot.line3.large_buf_len) {
        conn.state = .processing;
        self.processBodyRequest(conn_id, conn, buf);
    } else {
        submitBodyRead(self, conn, buf, slot) catch {
            self.large_pool.release(buf);
            slot.line3.large_buf_ptr = 0;
            self.closeConn(conn_id, conn.fd);
        };
    }
}

pub fn onStreamRead(self: *AsyncServer, conn_id: u64, res: i32, user_data: u64, cqe_flags: u32) void {
    _ = user_data;
    const conn = self.getConn(conn_id) orelse return;
    const slot = self.connSlot(conn) orelse {
        self.closeConn(conn_id, conn.fd);
        return;
    };
    const stream_ptr = sticker.getStream(slot) orelse {
        self.closeConn(conn_id, conn.fd);
        return;
    };
    const stream: *StreamHandle = @ptrCast(@alignCast(stream_ptr));

    if (res <= 0) {
        _ = stream.finish();
        sticker.clearStream(slot);
        self.closeConn(conn_id, conn.fd);
        return;
    }

    if (cqe_flags & linux.IORING_CQE_F_BUFFER != 0) {
        const bid = @as(u16, @truncate(cqe_flags >> 16));
        const read_buf = self.buffer_pool.getReadBuf(bid);
        const n = @as(usize, @intCast(res));
        _ = stream.feed(read_buf[0..n]);
        self.buffer_pool.markReplenish(bid);
    } else {
        const n = @as(usize, @intCast(res));
        const buf: []u8 = @as([*]u8, @ptrFromInt(slot.line3.large_buf_ptr))[0..slot.line3.large_buf_len];
        const window = bodyReadWindow(slot, buf.len) orelse {
            closeInvalidBodyRead(self, conn_id, conn, slot, true);
            return;
        };
        // Streaming reads without a buffer group also depend on large_buf_offset, so confirm the CQE length stays within the remaining window first.
        if (n > window.remaining) {
            closeInvalidBodyRead(self, conn_id, conn, slot, true);
            return;
        }
        const data = buf[window.offset..][0..n];
        _ = stream.feed(data);
        slot.line3.large_buf_offset += @intCast(n);
    }

    self.submitRead(conn_id, conn) catch {
        self.closeConn(conn_id, conn.fd);
    };
}

test "bodyReadWindow rejects invalid body offsets" {
    var slot = StackSlot{
        .line1 = .{},
        .line2 = .{},
        .line3 = .{},
        .line4 = .{},
        .line5 = .{},
    };

    slot.line3.large_buf_len = 10;
    slot.line3.large_buf_offset = 4;
    const window = bodyReadWindow(&slot, 10).?;
    try std.testing.expectEqual(@as(usize, 4), window.offset);
    try std.testing.expectEqual(@as(usize, 6), window.remaining);

    slot.line3.large_buf_offset = 11;
    try std.testing.expect(bodyReadWindow(&slot, 10) == null);

    slot.line3.large_buf_offset = 9;
    try std.testing.expect(bodyReadWindow(&slot, 8) == null);
}
