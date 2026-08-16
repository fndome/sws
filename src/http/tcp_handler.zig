const std = @import("std");
const linux = std.os.linux;

const AsyncServer = @import("async_server.zig").AsyncServer;
const Connection = @import("connection.zig").Connection;
const packUserData = @import("../stack_pool.zig").packUserData;
const sticker = @import("../stack_pool_sticker.zig");
const helpers = @import("http_helpers.zig");
const logErr = helpers.logErr;
const milliTimestamp = @import("event_loop.zig").milliTimestamp;
const build_options = @import("build_options");
const TlsStream = if (build_options.tls_enabled) @import("../tls/tls.zig").TlsStream else struct {};
const BUFFER_SIZE = @import("../constants.zig").BUFFER_SIZE;
const NO_READ_BUFFER_BID = @import("../constants.zig").NO_READ_BUFFER_BID;
const NO_POOL_SLOT = @import("../constants.zig").NO_POOL_SLOT;
const NO_FIXED_FILE = @import("../constants.zig").NO_FIXED_FILE;
const write_progress = @import("write_progress.zig");
const advanceOffset = write_progress.advanceOffset;
const finishWriteCleanup = @import("tcp_write.zig").finishWriteCleanup;

pub fn onTcpAcceptComplete(self: *AsyncServer, res: i32) void {
    self.tcp_accept_outstanding = false;
    if (res < 0) {
        logErr("tcp accept failed: {}", .{res});
        self.tcp_accept_stalled = true;
        self.submitTcpAccept() catch |err| {
            logErr("failed to resubmit tcp accept: {s}", .{@errorName(err)});
        };
        return;
    }
    const conn_fd: i32 = @intCast(res);

    const alloc = sticker.slotAlloc(&self.pool, conn_fd, &self.conn_gen_id, milliTimestamp(self.io));
    if (alloc.idx == NO_POOL_SLOT) {
        _ = linux.close(conn_fd);
        self.tcp_accept_stalled = true;
        return;
    }
    const pool_idx = alloc.idx;
    self.pool.slots[pool_idx].line2.conn_id = self.next_conn_id;
    self.next_conn_id +%= 1;
    const conn_id = self.pool.slots[pool_idx].line2.conn_id;

    var conn = Connection{
        .id = conn_id,
        .fd = conn_fd,
        .last_active_ms = milliTimestamp(self.io),
        .pool_idx = pool_idx,
        .gen_id = self.pool.slots[pool_idx].line1.gen_id,
        .active_list_pos = self.pool.slots[pool_idx].line2.active_list_pos,
        .state = .tcp_reading,
        .keep_alive = true,
    };

    if (self.use_fixed_files) {
        if (self.allocFixedIndex()) |idx| {
            conn.fixed_index = idx;
        } else |_| {}
        if (conn.hasFixedFile()) {
            if (self.ring.register_files_update(conn.fixed_index, &[_]linux.fd_t{conn_fd})) {} else |_| {
                self.freeFixedIndex(conn.fixed_index);
                conn.fixed_index = NO_FIXED_FILE;
            }
        }
    }

    self.connections.put(conn_id, conn) catch {
        sticker.slotFree(&self.pool, pool_idx);
        if (conn.hasFixedFile()) {
            const idx = conn.fixed_index;
            _ = self.ring.register_files_update(idx, &[_]linux.fd_t{-1}) catch |err| logErr("register_files_update failed for idx={d}: {s}", .{ idx, @errorName(err) });
            self.freeFixedIndex(idx);
        }
        _ = linux.close(conn_fd);
        self.tcp_accept_stalled = true;
        self.submitTcpAccept() catch |err| logErr("failed to resubmit tcp accept: {s}", .{@errorName(err)});
        return;
    };

    self.submitRead(conn_id, self.getConn(conn_id) orelse {
        _ = linux.close(conn_fd);
        self.tcp_accept_stalled = true;
        self.submitTcpAccept() catch |err| logErr("failed to resubmit tcp accept: {s}", .{@errorName(err)});
        return;
    }) catch |err| {
        logErr("submitRead failed for new tcp conn fd={d}: {s}", .{ conn_fd, @errorName(err) });
        self.closeConn(conn_id, conn_fd);
        self.tcp_accept_stalled = true;
        self.submitTcpAccept() catch |err2| logErr("failed to resubmit tcp accept: {s}", .{@errorName(err2)});
        return;
    };

    self.submitTcpAccept() catch |err| {
        self.tcp_accept_stalled = true;
        logErr("failed to resubmit tcp accept: {s}", .{@errorName(err)});
    };
}

pub fn onRawData(self: *AsyncServer, conn_id: u64, res: i32, user_data: u64, cqe_flags: u32) void {
    _ = user_data;
    if (res <= 0) {
        const conn = self.getConn(conn_id) orelse return;
        if (cqe_flags & linux.IORING_CQE_F_BUFFER != 0) {
            self.buffer_pool.markReplenish(@as(u16, @truncate(cqe_flags >> 16)));
        }
        self.closeConn(conn_id, conn.fd);
        return;
    }
    const conn = self.getConn(conn_id) orelse return;

    if (cqe_flags & linux.IORING_CQE_F_BUFFER == 0) {
        self.closeConn(conn_id, conn.fd);
        return;
    }
    var bid = @as(u16, @truncate(cqe_flags >> 16));
    const read_buf = self.buffer_pool.getReadBuf(bid);
    const nread = @as(usize, @intCast(res));

    var plaintext_buf: [BUFFER_SIZE]u8 = [_]u8{0} ** BUFFER_SIZE;
    var effective_buf: []u8 = undefined;
    var effective_nread = nread;
    var tls_decrypted = false;

    if (build_options.tls_enabled) {
        if (conn.tls) |tls_stream| {
            const decrypted = tls_stream.read(read_buf[0..nread], &plaintext_buf) catch {
                self.buffer_pool.markReplenish(bid);
                conn.read_len = 0;
                self.closeConn(conn_id, conn.fd);
                return;
            };
            if (decrypted == 0) {
                self.buffer_pool.markReplenish(bid);
                conn.read_bid = NO_READ_BUFFER_BID;
                conn.read_len = 0;
                self.submitRead(conn_id, conn) catch {
                    self.closeConn(conn_id, conn.fd);
                };
                return;
            }
            self.buffer_pool.markReplenish(bid);
            effective_buf = plaintext_buf[0..decrypted];
            effective_nread = decrypted;
            tls_decrypted = true;
            bid = NO_READ_BUFFER_BID;
        } else {
            effective_buf = @constCast(read_buf[0..nread]);
        }
    } else {
        effective_buf = @constCast(read_buf[0..nread]);
    }

    if (!build_options.tls_enabled or !tls_decrypted) {
        if (conn.read_len > 0) self.buffer_pool.markReplenish(conn.read_bid);
        conn.read_bid = bid;
    } else {
        conn.read_bid = NO_READ_BUFFER_BID;
    }
    conn.read_len = effective_nread;

    if (self.connSlot(conn)) |slot| {
        const now_ms = milliTimestamp(self.io);
        slot.line2.last_active_ms = now_ms;
    }

    const data = if (conn.accum_buf) |prev| blk: {
        const combined = self.allocator.alloc(u8, prev.len + effective_nread) catch {
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            self.closeConn(conn_id, conn.fd);
            return;
        };
        @memcpy(combined[0..prev.len], prev);
        @memcpy(combined[prev.len..], effective_buf[0..effective_nread]);
        self.allocator.free(prev);
        conn.accum_buf = null;
        break :blk combined;
    } else blk: {
        break :blk self.allocator.dupe(u8, effective_buf[0..effective_nread]) catch {
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            self.closeConn(conn_id, conn.fd);
            return;
        };
    };

    if (self.tcp_server.handler) |handler| {
        handler(conn_id, data);
    }
    self.allocator.free(data);

    if (conn.state != .tcp_writing) {
        conn.state = .tcp_reading;
        self.submitRead(conn_id, conn) catch {
            self.closeConn(conn_id, conn.fd);
        };
    }
}

pub fn sendTcp(self: *AsyncServer, conn_id: u64, data: []const u8) !void {
    const conn = self.getConn(conn_id) orelse return;
    if (data.len == 0) return;
    if (!self.ensureWriteBuf(conn, data.len)) return error.OutOfMemory;
    const buf = conn.response_buf.?;
    @memcpy(buf[0..data.len], data);
    conn.write_headers_len = data.len;
    conn.write_offset = 0;
    try self.submitWrite(conn_id, conn);
    conn.state = .tcp_writing;
}

pub fn onTcpWriteComplete(self: *AsyncServer, conn_id: u64, res: i32, user_data: u64) void {
    _ = user_data;
    if (res <= 0) {
        const conn = self.getConn(conn_id) orelse return;
        if (self.connSlot(conn)) |slot| {
            slot.line4.writev_in_flight = 0;
        }
        self.closeConn(conn_id, conn.fd);
        return;
    }
    const conn = self.getConn(conn_id) orelse return;
    conn.write_offset = advanceOffset(conn.write_offset, @as(usize, @intCast(res)), conn.write_headers_len);
    switch (write_progress.classify(conn.write_offset, conn.write_headers_len, conn.write_retries)) {
        .complete => {
            finishWriteCleanup(self, conn);
            if (conn.keep_alive) {
                conn.write_offset = 0;
                conn.write_headers_len = 0;
                conn.state = .tcp_reading;
                conn.last_active_ms = milliTimestamp(self.io);
                if (self.connSlot(conn)) |slot| {
                    slot.line2.last_active_ms = conn.last_active_ms;
                }
                self.submitRead(conn_id, conn) catch |err| {
                    logErr("submitRead failed for tcp fd={d}: {s}", .{ conn.fd, @errorName(err) });
                    self.closeConn(conn_id, conn.fd);
                };
            } else {
                self.closeConn(conn_id, conn.fd);
            }
        },
        .retry => {
            conn.write_retries += 1;
            if (self.connSlot(conn)) |slot| {
                slot.line4.writev_in_flight = 0;
            }
            // Partial progress: refresh the timer so write_timeout_ms tracks time
            // since last progress rather than since the write started.
            conn.write_start_ms = milliTimestamp(self.io);
            if (self.connSlot(conn)) |slot| {
                slot.line2.write_start_ms = conn.write_start_ms;
            }
            self.submitWrite(conn_id, conn) catch |err| {
                logErr("submitWrite failed for tcp fd={d}: {s}", .{ conn.fd, @errorName(err) });
                if (self.connSlot(conn)) |slot| {
                    slot.line4.writev_in_flight = 0;
                }
                self.closeConn(conn_id, conn.fd);
            };
        },
        .give_up => {
            logErr("tcp write retries exceeded for fd={d}", .{conn.fd});
            if (self.connSlot(conn)) |slot| {
                slot.line4.writev_in_flight = 0;
            }
            self.closeConn(conn_id, conn.fd);
        },
    }
}

pub fn tcpSendFn(ctx: *anyopaque, conn_id: u64, data: []const u8) !void {
    const self: *AsyncServer = @ptrCast(@alignCast(ctx));
    try sendTcp(self, conn_id, data);
}
