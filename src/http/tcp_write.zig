const std = @import("std");
const linux = std.os.linux;

const AsyncServer = @import("async_server.zig").AsyncServer;
const Connection = @import("connection.zig").Connection;
const packUserData = @import("../stack_pool.zig").packUserData;
const logErr = @import("http_helpers.zig").logErr;
const milliTimestamp = @import("event_loop.zig").milliTimestamp;
const TlsStream = @import("../tls/tls.zig").TlsStream;

const maxWriteRetries = @import("http_response.zig").maxWriteRetries;

fn queuePendingWrite(self: *AsyncServer, conn_id: u64, conn: *Connection) !void {
    self.pending_writes.append(self.allocator, conn_id) catch {
        // 修改原因：写 SQE 没提交成功时如果连重试队列也入不了，继续返回成功会让连接永久停在 writing。
        logErr("submitWrite: pend queue full, close fd={d}", .{conn.fd});
        return error.PendingWriteQueueFull;
    };
}

pub fn submitWrite(self: *AsyncServer, conn_id: u64, conn: *Connection) !void {
    if (conn.write_offset == 0) {
        conn.write_start_ms = milliTimestamp(self.io);
        conn.write_retries = 0;
    }

    if (conn.tls) |tls_stream| {
        return submitTlsWrite(self, conn_id, conn, tls_stream);
    }

    const user_data = packUserData(conn.gen_id, conn.pool_idx);
    const fd = if (conn.fixed_index != 0xFFFF) @as(i32, @intCast(conn.fixed_index)) else conn.fd;

    const resp_buf = conn.response_buf orelse return;

    const slot = &self.pool.slots[conn.pool_idx];

    if (slot.line4.writev_in_flight != 0) {
        logErr("submitWrite: writev already in-flight for fd={d}, skipping", .{conn.fd});
        return error.WriteInFlight;
    }

    const iovs = &slot.line4.write_iovs;

    const header_len = @min(conn.write_headers_len, resp_buf.len);

    if (conn.write_body) |body| {
        const total = header_len + body.len;
        if (conn.write_offset >= total) return;

        var count: usize = 0;

        if (conn.write_offset < header_len) {
            iovs[count] = .{
                .base = resp_buf.ptr + conn.write_offset,
                .len = header_len - conn.write_offset,
            };
            count += 1;
        }

        const body_start = if (conn.write_offset > header_len)
            conn.write_offset - header_len
        else
            0;
        if (body_start < body.len) {
            iovs[count] = .{
                .base = body.ptr + body_start,
                .len = body.len - body_start,
            };
            count += 1;
        }

        slot.line4.writev_in_flight = 1;
        // SQ full — push to pending queue so the event loop retries
        // next iteration rather than dropping the write
        const sqe = self.ring.writev(user_data, fd, iovs[0..count], 0) catch {
            slot.line4.writev_in_flight = 0;
            try queuePendingWrite(self, conn_id, conn);
            return;
        };
        if (conn.fixed_index != 0xFFFF) sqe.flags |= linux.IOSQE_FIXED_FILE;
    } else {
        if (conn.write_offset >= header_len) return;
        const to_send = resp_buf[conn.write_offset..header_len];
        slot.line4.writev_in_flight = 1;
        // SQ full — push to pending queue for retry next iteration
        const sqe = self.ring.write(user_data, fd, to_send, 0) catch {
            slot.line4.writev_in_flight = 0;
            try queuePendingWrite(self, conn_id, conn);
            return;
        };
        if (conn.fixed_index != 0xFFFF) sqe.flags |= linux.IOSQE_FIXED_FILE;
    }
}

pub fn onWriteComplete(self: *AsyncServer, conn_id: u64, res: i32, user_data: u64) void {
    _ = user_data;
    if (res <= 0) {
        const conn = self.getConn(conn_id) orelse return;
        if (conn.pool_idx != 0xFFFFFFFF) {
            self.pool.slots[conn.pool_idx].line4.writev_in_flight = 0;
        }
        self.closeConn(conn_id, conn.fd);
        return;
    }
    const conn = self.getConn(conn_id) orelse return;
    if (conn.tls != null) {
        return onTlsWriteComplete(self, conn_id, conn, res);
    }
    conn.write_offset += @as(usize, @intCast(res));
    const total = conn.write_headers_len + if (conn.write_body) |b| b.len else 0;
    if (conn.write_offset >= total) {
        conn.write_retries = 0;
        if (conn.pool_idx != 0xFFFFFFFF) {
            self.pool.slots[conn.pool_idx].line4.writev_in_flight = 0;
        }
        if (conn.write_body) |b| {
            self.allocator.free(b);
            conn.write_body = null;
        }
        conn.write_start_ms = 0;
        if (conn.response_buf) |buf| {
            self.buffer_pool.freeTieredWriteBuf(buf, conn.response_buf_tier);
            conn.response_buf = null;
        }
        if (self.ws_server.getActive(conn_id) != null) {
            // 修改原因：WebSocket 101 升级完成后 keep_alive 在 tryWsUpgrade 被设为 false，
            // 若不重置为 true，onWsWriteComplete 的 keep_alive 检查会把后续 pong/应用帧写入后断连。
            conn.keep_alive = true;
            conn.write_offset = 0;
            conn.write_headers_len = 0;
            conn.state = .ws_reading;
            self.submitRead(conn_id, conn) catch |err| {
                logErr("submitRead failed for WS upgrade fd {}: {s}", .{ conn.fd, @errorName(err) });
                self.closeConn(conn_id, conn.fd);
            };
        } else if (conn.keep_alive) {
            conn.write_start_ms = 0;
            conn.state = .reading;
            conn.read_len = 0;
            conn.write_offset = 0;
            conn.write_headers_len = 0;
            conn.last_active_ms = milliTimestamp(self.io);
            self.submitRead(conn_id, conn) catch |err| {
                logErr("submitRead failed for keep-alive fd {}: {s}", .{ conn.fd, @errorName(err) });
                self.closeConn(conn_id, conn.fd);
            };
        } else {
            self.closeConn(conn_id, conn.fd);
        }
    } else {
        conn.write_retries += 1;
        if (conn.write_retries > maxWriteRetries(total)) {
            logErr("write retries exceeded for fd {} ({} attempts, {} bytes total)", .{ conn.fd, conn.write_retries, total });
            if (conn.pool_idx != 0xFFFFFFFF) {
                self.pool.slots[conn.pool_idx].line4.writev_in_flight = 0;
            }
            self.closeConn(conn_id, conn.fd);
            return;
        }
        if (conn.pool_idx != 0xFFFFFFFF) {
            self.pool.slots[conn.pool_idx].line4.writev_in_flight = 0;
        }
        self.submitWrite(conn_id, conn) catch |err| {
            logErr("submitWrite failed for fd {}: {s}", .{ conn.fd, @errorName(err) });
            if (conn.pool_idx != 0xFFFFFFFF) {
                self.pool.slots[conn.pool_idx].line4.writev_in_flight = 0;
            }
            self.closeConn(conn_id, conn.fd);
        };
    }
}

fn submitTlsWrite(self: *AsyncServer, conn_id: u64, conn: *Connection, tls_stream: *TlsStream) !void {
    _ = conn_id;
    const user_data = packUserData(conn.gen_id, conn.pool_idx);
    const fd = if (conn.fixed_index != 0xFFFF) @as(i32, @intCast(conn.fixed_index)) else conn.fd;

    const resp_buf = conn.response_buf orelse return;
    const slot = &self.pool.slots[conn.pool_idx];

    if (slot.line4.writev_in_flight != 0) {
        return error.WriteInFlight;
    }

    const header_len = @min(conn.write_headers_len, resp_buf.len);

    var ciphertext_buf: [16384]u8 = [_]u8{0} ** 16384;

    if (conn.write_body) |body| {
        const total = header_len + body.len;
        if (conn.write_offset >= total) return;

        var plaintext_buf: [16384]u8 = [_]u8{0} ** 16384;
        var plaintext_offset: usize = 0;

        if (conn.write_offset < header_len) {
            const hdr_part = resp_buf[conn.write_offset..header_len];
            @memcpy(plaintext_buf[plaintext_offset..][0..hdr_part.len], hdr_part);
            plaintext_offset += hdr_part.len;
        }

        const body_start = if (conn.write_offset > header_len)
            conn.write_offset - header_len
        else
            0;
        if (body_start < body.len) {
            const body_part = body[body_start..];
            const to_copy = @min(body_part.len, plaintext_buf.len - plaintext_offset);
            @memcpy(plaintext_buf[plaintext_offset..][0..to_copy], body_part[0..to_copy]);
            plaintext_offset += to_copy;
        }

        const plaintext = plaintext_buf[0..plaintext_offset];
        const ciphertext_len = tls_stream.write(plaintext, &ciphertext_buf) catch {
            return error.TlsWriteFailed;
        };
        if (ciphertext_len == 0) return;

        slot.line4.writev_in_flight = 1;
        _ = self.ring.write(user_data, fd, ciphertext_buf[0..ciphertext_len], 0) catch {
            slot.line4.writev_in_flight = 0;
            try queuePendingWrite(self, conn_id, conn);
            return;
        };
    } else {
        if (conn.write_offset >= header_len) return;
        const plaintext = resp_buf[conn.write_offset..header_len];
        const to_encrypt = if (plaintext.len > 16384) plaintext[0..16384] else plaintext;
        const ciphertext_len = tls_stream.write(to_encrypt, &ciphertext_buf) catch {
            return error.TlsWriteFailed;
        };
        if (ciphertext_len == 0) return;

        slot.line4.writev_in_flight = 1;
        _ = self.ring.write(user_data, fd, ciphertext_buf[0..ciphertext_len], 0) catch {
            slot.line4.writev_in_flight = 0;
            try queuePendingWrite(self, conn_id, conn);
            return;
        };
    }
}

fn onTlsWriteComplete(self: *AsyncServer, conn_id: u64, conn: *Connection, _: i32) void {
    const header_len = if (conn.response_buf) |rb|
        @min(conn.write_headers_len, rb.len)
    else
        0;
    const body_len = if (conn.write_body) |b| b.len else 0;
    const total = header_len + body_len;

    conn.write_offset = total;

    conn.write_retries = 0;
    if (conn.pool_idx != 0xFFFFFFFF) {
        self.pool.slots[conn.pool_idx].line4.writev_in_flight = 0;
    }
    if (conn.write_body) |b| {
        self.allocator.free(b);
        conn.write_body = null;
    }
    conn.write_start_ms = 0;
    if (conn.response_buf) |buf| {
        self.buffer_pool.freeTieredWriteBuf(buf, conn.response_buf_tier);
        conn.response_buf = null;
    }
    if (self.ws_server.getActive(conn_id) != null) {
        conn.keep_alive = true;
        conn.write_offset = 0;
        conn.write_headers_len = 0;
        conn.state = .ws_reading;
        self.submitRead(conn_id, conn) catch |err| {
            logErr("submitRead failed for WS upgrade fd {}: {s}", .{ conn.fd, @errorName(err) });
            self.closeConn(conn_id, conn.fd);
        };
    } else if (conn.keep_alive) {
        conn.write_start_ms = 0;
        conn.state = .reading;
        conn.read_len = 0;
        conn.write_offset = 0;
        conn.write_headers_len = 0;
        conn.last_active_ms = milliTimestamp(self.io);
        self.submitRead(conn_id, conn) catch |err| {
            logErr("submitRead failed for keep-alive fd {}: {s}", .{ conn.fd, @errorName(err) });
            self.closeConn(conn_id, conn.fd);
        };
    } else {
        self.closeConn(conn_id, conn.fd);
    }
}
