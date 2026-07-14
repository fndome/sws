const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");

const AsyncServer = @import("async_server.zig").AsyncServer;
const Connection = @import("connection.zig").Connection;
const sticker = @import("../stack_pool_sticker.zig");
const packUserData = @import("../stack_pool.zig").packUserData;
const CLOSE_USER_DATA_FLAG = @import("../stack_pool.zig").CLOSE_USER_DATA_FLAG;
const ACCEPT_USER_DATA = @import("../constants.zig").ACCEPT_USER_DATA;
const logErr = @import("http_helpers.zig").logErr;

pub fn getConn(self: *AsyncServer, conn_id: u64) ?*Connection {
    if (sticker.lookupByConnId(&self.pool, &self.connections, conn_id)) |r| {
        return @ptrCast(@alignCast(r.conn));
    }
    return null;
}

pub fn getConnToken(self: *AsyncServer, conn_id: u64) ?[]const u8 {
    if (getConn(self, conn_id)) |conn| {
        return conn.ws_token;
    }
    return null;
}

pub fn nextUserData(self: *AsyncServer) u64 {
    const id = self.next_user_data;
    self.next_user_data +%= 1;
    var ud = id & ~ACCEPT_USER_DATA;
    if (ud == 0) ud = 1;
    return ud;
}

pub fn closeConn(self: *AsyncServer, conn_id: u64, fd: i32) void {
    self.ws_server.removeActive(conn_id);

    if (getConn(self, conn_id)) |conn| {
        if (build_options.tls_enabled) {
            if (conn.tls) |tls_stream| {
                tls_stream.free();
                self.allocator.destroy(tls_stream);
                conn.tls = null;
            }
            if (conn.tls_ciphertext) |buf| {
                self.allocator.free(buf);
                conn.tls_ciphertext = null;
            }
        }
        if (!conn.read_buf_recycled and conn.read_bid != 0) {
            conn.read_buf_recycled = true;
            self.buffer_pool.markReplenish(conn.read_bid);
        }
        if (conn.ws_token) |t| {
            self.allocator.free(t);
            conn.ws_token = null;
        }
        if (conn.accum_buf) |p| {
            self.allocator.free(p);
            conn.accum_buf = null;
        }

        self.drainWsWriteQueue(conn);

        if (conn.pool_idx != 0xFFFFFFFF) {
            const slot = &self.pool.slots[conn.pool_idx];
            if (slot.line3.pending_buffer_ptr != 0) {
                const hw = sticker.httpWork(slot);
                const saved: []u8 = @as([*]u8, @ptrFromInt(slot.line3.pending_buffer_ptr))[0..hw.header_len];
                // 修改原因：跨分片 header 可能在等待 body 时暂存到堆上；异常关闭必须释放，避免半包请求泄漏。
                self.allocator.free(saved);
                slot.line3.pending_buffer_ptr = 0;
                hw.header_len = 0;
            }
            if (slot.line3.large_buf_ptr != 0) {
                const buf: []u8 = @as([*]u8, @ptrFromInt(slot.line3.large_buf_ptr))[0..slot.line3.large_buf_len];
                self.large_pool.release(buf);
                slot.line3.large_buf_ptr = 0;
            }
            // stream_ptr may reference a heap-allocated StreamHandle that was
            // never finished. Clear it so the slot can be safely reused.
            if (slot.line3.stream_ptr != 0) {
                slot.line3.stream_ptr = 0;
            }
        }

        if (!conn.write_bufs_freed) {
            // guard: if a write SQE is still in-flight in the kernel,
            // defer freeing write_body/response_buf to the CQE handler.
            // freeing now would risk kernel use-after-free on the buffer.
            // onWriteComplete / onWsWriteComplete + the .closing CQE path
            // handle the deferred cleanup.
            const write_inflight = if (conn.pool_idx != 0xFFFFFFFF)
                self.pool.slots[conn.pool_idx].line4.writev_in_flight != 0
            else
                false;

            if (!write_inflight) {
                conn.write_bufs_freed = true;
                if (conn.write_body) |b| {
                    self.allocator.free(b);
                    conn.write_body = null;
                }
                if (conn.response_buf) |buf| {
                    self.buffer_pool.freeTieredWriteBuf(buf, conn.response_buf_tier);
                    conn.response_buf = null;
                }
            }
        }

        if (conn.state == .closing or fd == 0) {
            // If a writev is still in-flight in the kernel, defer connFree.
            // The write CQE handler (.closing dispatch) clears the flag and
            // re-invokes closeConn. Freeing the slot now would orphan
            // write_body/response_buf — the next CQE sees gen_id=0 and drops
            // them silently, leaking heap + tiered-pool buffers.
            if (conn.pool_idx != 0xFFFFFFFF and
                self.pool.slots[conn.pool_idx].line4.writev_in_flight != 0)
            {
                return;
            }
            sticker.connFree(&self.pool, &self.connections, conn_id);
            // A slot was just freed. If accept was stalled due to pool full,
            // resume the accept chain now. This avoids the tight accept-fail-
            // close loop that would otherwise spin CPU when at capacity.
            if (self.accept_stalled) {
                self.submitAccept() catch |err| {
                    logErr("accept recovery failed: {s}", .{@errorName(err)});
                };
            }
            return;
        }

        conn.state = .closing;
    }

    if (self.use_fixed_files) {
        if (getConn(self, conn_id)) |conn| {
            if (conn.fixed_index == 0xFFFF) {
                // no fixed file registered; skip deregister
            } else {
                const idx = conn.fixed_index;
                _ = self.ring.register_files_update(idx, &[_]linux.fd_t{-1}) catch {};
                self.freeFixedIndex(idx);
            }
        }
    }

    if (fd > 0) {
        const close_conn = getConn(self, conn_id) orelse return;
        const close_ud = packUserData(close_conn.gen_id, close_conn.pool_idx) | CLOSE_USER_DATA_FLAG;
        const sqe = self.ring.nop(close_ud) catch {
            _ = linux.close(fd);
            if (getConn(self, conn_id)) |c| {
                c.state = .closing;
            }
            closeConn(self, conn_id, 0);
            return;
        };
        sqe.opcode = @enumFromInt(19);
        sqe.fd = fd;
    }
}
