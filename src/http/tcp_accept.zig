const std = @import("std");
const linux = std.os.linux;

const AsyncServer = @import("async_server.zig").AsyncServer;
const Connection = @import("connection.zig").Connection;
const sticker = @import("../stack_pool_sticker.zig");
const logErr = @import("http_helpers.zig").logErr;
const milliTimestamp = @import("event_loop.zig").milliTimestamp;
const build_options = @import("build_options");

const MAX_FIXED_FILES = @import("../constants.zig").MAX_FIXED_FILES;
const ACCEPT_USER_DATA = @import("../constants.zig").ACCEPT_USER_DATA;
const NO_POOL_SLOT = @import("../constants.zig").NO_POOL_SLOT;
const NO_FIXED_FILE = @import("../constants.zig").NO_FIXED_FILE;

pub fn nextConnId(self: *AsyncServer) u64 {
    const id = self.next_conn_id;
    self.next_conn_id +%= 1;
    return id;
}

pub fn allocFixedIndex(self: *AsyncServer) !u16 {
    if (self.fixed_file_freelist.pop()) |idx| return idx;
    if (self.fixed_file_next < MAX_FIXED_FILES) {
        const idx = self.fixed_file_next;
        self.fixed_file_next += 1;
        return idx;
    }
    return error.OutOfFixedFileSlots;
}

pub fn freeFixedIndex(self: *AsyncServer, idx: u16) void {
    self.fixed_file_freelist.append(self.allocator, idx) catch |err| {
        logErr("freeFixedIndex: append failed for idx {d}: {s}", .{ idx, @errorName(err) });
    };
}

pub fn onAcceptComplete(self: *AsyncServer, res: i32, user_data: u64) void {
    _ = user_data;
    self.accept_outstanding = false;
    if (res < 0) {
        logErr("accept failed: {}", .{res});
        self.accept_stalled = true;
        self.submitAccept() catch |err| {
            logErr("failed to resubmit accept: {s}", .{@errorName(err)});
            return;
        };
        return;
    }
    const conn_fd: i32 = @intCast(res);
    const conn_id = nextConnId(self);

    const alloc = sticker.slotAlloc(&self.pool, conn_fd, &self.conn_gen_id, milliTimestamp(self.io));
    if (alloc.idx == NO_POOL_SLOT) {
        const rc = linux.close(conn_fd);
        if (rc != 0) logErr("close conn_fd={d} failed: {d}", .{ conn_fd, rc });
        // Pool full: stall accept but do NOT resubmit here. Resubmitting
        // immediately creates a tight accept-fail-close loop that wastes
        // CPU. closeConn will resubmit when a slot is freed.
        self.accept_stalled = true;
        return;
    }
    const pool_idx = alloc.idx;
    self.pool.slots[pool_idx].line2.conn_id = conn_id;

    var conn = Connection{
        .id = conn_id,
        .fd = conn_fd,
        .last_active_ms = milliTimestamp(self.io),
        .pool_idx = pool_idx,
        .gen_id = self.pool.slots[pool_idx].line1.gen_id,
        .active_list_pos = self.pool.slots[pool_idx].line2.active_list_pos,
    };

    if (self.use_fixed_files) {
        if (allocFixedIndex(self)) |idx| {
            conn.fixed_index = idx;
        } else |_| {
            // Fixed-file table is full. Fall back to plain-fd I/O for
            // this connection rather than silently dropping it. At 1M
            // connections only the first MAX_FIXED_FILES use the fast path;
            // the rest operate correctly with regular fd-based I/O.
        }
        if (conn.fixed_index != NO_FIXED_FILE) {
            if (self.ring.register_files_update(conn.fixed_index, &[_]linux.fd_t{conn_fd})) {
                // OK — fixed_index was set above
            } else |_| {
                freeFixedIndex(self, conn.fixed_index);
                conn.fixed_index = NO_FIXED_FILE;
            }
        }
    }

    self.connections.put(conn_id, conn) catch {
        sticker.slotFree(&self.pool, pool_idx);
        if (conn.fixed_index != NO_FIXED_FILE) {
            const idx = conn.fixed_index;
            _ = self.ring.register_files_update(idx, &[_]linux.fd_t{-1}) catch {};
            freeFixedIndex(self, idx);
        }
        const rc = linux.close(conn_fd);
        if (rc != 0) logErr("close conn_fd={d} failed: {d}", .{ conn_fd, rc });
        self.accept_stalled = true;
        self.submitAccept() catch |err| logErr("failed to resubmit accept after put error: {s}", .{@errorName(err)});
        return;
    };
    const conn_ptr = self.getConn(conn_id) orelse {
        const rc = linux.close(conn_fd);
        if (rc != 0) logErr("close orphan conn_fd={d} failed: {d}", .{ conn_fd, rc });
        self.accept_stalled = true;
        self.submitAccept() catch |err| logErr("failed to resubmit accept: {s}", .{@errorName(err)});
        return;
    };

    if (build_options.tls_enabled) {
        if (self.tls_config != null) {
            self.initTlsStream(conn_ptr) catch |err| {
                logErr("initTlsStream failed for fd {}: {s}", .{ conn_fd, @errorName(err) });
                self.closeConn(conn_id, conn_fd);
                self.accept_stalled = true;
                self.submitAccept() catch |err2| logErr("failed to resubmit accept after tls error: {s}", .{@errorName(err2)});
                return;
            };
            conn_ptr.state = .tls_handshaking;
            self.submitRead(conn_id, conn_ptr) catch |err| {
                if (err == error.RingFull) {
                    logErr("submitRead RingFull for new TLS conn fd={d}, closing", .{conn_fd});
                    self.closeConn(conn_id, conn_fd);
                } else {
                    logErr("submitRead failed for TLS fd {}: {s}", .{ conn_fd, @errorName(err) });
                    self.closeConn(conn_id, conn_fd);
                }
                self.accept_stalled = true;
                self.submitAccept() catch |err2| logErr("failed to resubmit accept after tls read error: {s}", .{@errorName(err2)});
                return;
            };
        } else {
            self.submitRead(conn_id, conn_ptr) catch |err| {
                if (err == error.RingFull) {
                    logErr("submitRead RingFull for new conn fd={d}, closing", .{conn_fd});
                    self.closeConn(conn_id, conn_fd);
                } else {
                    logErr("submitRead failed for fd {}: {s}", .{ conn_fd, @errorName(err) });
                    self.closeConn(conn_id, conn_fd);
                }
                self.accept_stalled = true;
                self.submitAccept() catch |err2| logErr("failed to resubmit accept after read error: {s}", .{@errorName(err2)});
                return;
            };
        }
    } else {
        self.submitRead(conn_id, conn_ptr) catch |err| {
            if (err == error.RingFull) {
                logErr("submitRead RingFull for new conn fd={d}, closing", .{conn_fd});
                self.closeConn(conn_id, conn_fd);
            } else {
                logErr("submitRead failed for fd {}: {s}", .{ conn_fd, @errorName(err) });
                self.closeConn(conn_id, conn_fd);
            }
            self.accept_stalled = true;
            self.submitAccept() catch |err2| logErr("failed to resubmit accept after read error: {s}", .{@errorName(err2)});
            return;
        };
    }
    self.submitAccept() catch |err| {
        self.accept_stalled = true;
        logErr("failed to resubmit accept: {s}", .{@errorName(err)});
    };
}
