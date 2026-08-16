const std = @import("std");
const linux = std.os.linux;

const AsyncServer = @import("async_server.zig").AsyncServer;
const Connection = @import("connection.zig").Connection;
const packUserData = @import("../stack_pool.zig").packUserData;
const logErr = @import("http_helpers.zig").logErr;
const milliTimestamp = @import("event_loop.zig").milliTimestamp;
const TlsStream = @import("../tls/tls.zig").TlsStream;
const build_options = @import("build_options");

const write_progress = @import("write_progress.zig");

/// Free per-connection write buffers and reset write bookkeeping after a
/// response write completes. Leaves write_offset/write_headers_len and the
/// protocol state transition to the caller (http/ws/tcp complete differently).
/// write_body/tls_ciphertext are null for ws/raw-tcp, so the guarded frees are
/// no-ops there.
///
/// Call this before the caller re-arms I/O (flushWsWriteQueue/submitRead):
/// clearing writev_in_flight first is required, because submitWrite checks it
/// and would otherwise refuse the next write.
pub fn finishWriteCleanup(self: *AsyncServer, conn: *Connection) void {
    conn.write_retries = 0;
    if (self.connSlot(conn)) |slot| {
        slot.line4.writev_in_flight = 0;
    }
    if (conn.write_body) |b| {
        self.allocator.free(b);
        conn.write_body = null;
    }
    conn.write_start_ms = 0;
    if (self.connSlot(conn)) |slot| {
        slot.line2.write_start_ms = 0;
    }
    if (conn.response_buf) |buf| {
        self.buffer_pool.freeTieredWriteBuf(buf, conn.response_buf_tier);
        conn.response_buf = null;
    }
    if (build_options.tls_enabled) {
        if (conn.tls_ciphertext) |buf| {
            self.allocator.free(buf);
            conn.tls_ciphertext = null;
        }
    }
}

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
        // Mirror the write start time into the slot so ttlScan can enforce
        // write_timeout_ms without a per-connection hashmap lookup.
        if (self.connSlot(conn)) |slot| {
            slot.line2.write_start_ms = conn.write_start_ms;
        }
    }

    if (build_options.tls_enabled) {
        if (conn.tls) |tls_stream| {
            return submitTlsWrite(self, conn_id, conn, tls_stream);
        }
    }

    const user_data = packUserData(conn.gen_id, conn.pool_idx);
    const fd = conn.ioFd();

    const resp_buf = conn.response_buf orelse return;

    // Defensive: onWriteComplete and closeConn both guard pool_idx, but
    // submitWrite did not. Without a valid slot, writev_in_flight and
    // write_iovs are inaccessible — close the connection rather than OOB.
    const slot = self.connSlot(conn) orelse {
        logErr("submitWrite: no pool slot for fd={d}, closing", .{conn.fd});
        self.closeConn(conn_id, conn.fd);
        return;
    };

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
        if (conn.hasFixedFile()) sqe.flags |= linux.IOSQE_FIXED_FILE;
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
        if (conn.hasFixedFile()) sqe.flags |= linux.IOSQE_FIXED_FILE;
    }
}

pub fn onWriteComplete(self: *AsyncServer, conn_id: u64, res: i32, user_data: u64) void {
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
    if (build_options.tls_enabled) {
        if (conn.tls != null) {
            return onTlsWriteComplete(self, conn_id, conn, res);
        }
    }
    const total = write_progress.writeTotal(conn.write_headers_len, if (conn.write_body) |b| b.len else 0);
    conn.write_offset = write_progress.advanceOffset(conn.write_offset, @as(usize, @intCast(res)), total);
    switch (write_progress.classify(conn.write_offset, total, conn.write_retries)) {
        .complete => {
            finishWriteCleanup(self, conn);
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
                if (self.connSlot(conn)) |slot| {
                    slot.line2.last_active_ms = conn.last_active_ms;
                }
                self.submitRead(conn_id, conn) catch |err| {
                    logErr("submitRead failed for keep-alive fd {}: {s}", .{ conn.fd, @errorName(err) });
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
            // A partial write CQE means the client is still reading; refresh the
            // timer so write_timeout_ms measures time since last progress, not
            // since the write began (otherwise slow large responses are killed).
            conn.write_start_ms = milliTimestamp(self.io);
            if (self.connSlot(conn)) |slot| {
                slot.line2.write_start_ms = conn.write_start_ms;
            }
            self.submitWrite(conn_id, conn) catch |err| {
                logErr("submitWrite failed for fd {}: {s}", .{ conn.fd, @errorName(err) });
                if (self.connSlot(conn)) |slot| {
                    slot.line4.writev_in_flight = 0;
                }
                self.closeConn(conn_id, conn.fd);
            };
        },
        .give_up => {
            logErr("write retries exceeded for fd {} ({} attempts, {} bytes total)", .{ conn.fd, conn.write_retries + 1, total });
            if (self.connSlot(conn)) |slot| {
                slot.line4.writev_in_flight = 0;
            }
            self.closeConn(conn_id, conn.fd);
        },
    }
}

fn submitTlsWrite(self: *AsyncServer, conn_id: u64, conn: *Connection, tls_stream: *TlsStream) !void {
    if (build_options.tls_enabled) {
    const user_data = packUserData(conn.gen_id, conn.pool_idx);
    const fd = conn.ioFd();

    const resp_buf = conn.response_buf orelse return;

    // Defensive: closeConn and general write paths guard pool_idx; TLS
    // path was missed when TLS support was added in #58.
    const slot = self.connSlot(conn) orelse {
        logErr("submitTlsWrite: no pool slot for fd={d}, closing", .{conn.fd});
        self.closeConn(conn_id, conn.fd);
        return;
    };

    if (slot.line4.writev_in_flight != 0) {
        return error.WriteInFlight;
    }

    const header_len = @min(conn.write_headers_len, resp_buf.len);

    const max_ciphertext = @as(usize, 16384) + 2048;
    if (conn.tls_ciphertext == null) {
        conn.tls_ciphertext = self.allocator.alloc(u8, max_ciphertext) catch return error.OutOfMemory;
    }
    var ciphertext_buf = conn.tls_ciphertext.?;
    var plaintext_buf: [16384]u8 = [_]u8{0} ** 16384;
    var plaintext_len: usize = 0;

    if (conn.write_offset < header_len) {
        const hdr_part = resp_buf[conn.write_offset..header_len];
        const n = @min(hdr_part.len, plaintext_buf.len - plaintext_len);
        @memcpy(plaintext_buf[plaintext_len..][0..n], hdr_part[0..n]);
        plaintext_len += n;
    }

    if (conn.write_body) |body| {
        if (plaintext_len < plaintext_buf.len) {
            const body_start = if (conn.write_offset > header_len)
            conn.write_offset - header_len
        else
            0;
        const body_part = body[body_start..];
        const n = @min(body_part.len, plaintext_buf.len - plaintext_len);
        @memcpy(plaintext_buf[plaintext_len..][0..n], body_part[0..n]);
        plaintext_len += n;
        }
    }

    if (plaintext_len == 0) return;

    const ciphertext_len = tls_stream.write(plaintext_buf[0..plaintext_len], ciphertext_buf) catch {
        return error.TlsWriteFailed;
    };
    if (ciphertext_len == 0) return;

    slot.line4.writev_in_flight = 1;
    _ = self.ring.write(user_data, fd, ciphertext_buf[0..ciphertext_len], 0) catch {
        slot.line4.writev_in_flight = 0;
        try queuePendingWrite(self, conn_id, conn);
        return;
    };
    conn.tls_write_len = @intCast(ciphertext_len);
    }
}

fn onTlsWriteComplete(self: *AsyncServer, conn_id: u64, conn: *Connection, res: i32) void {
    if (build_options.tls_enabled) {
    if (res <= 0) {
        if (self.connSlot(conn)) |slot| {
            slot.line4.writev_in_flight = 0;
        }
        self.closeConn(conn_id, conn.fd);
        return;
    }

    if (conn.tls_write_len > 0 and @as(u32, @intCast(res)) != conn.tls_write_len) {
        if (self.connSlot(conn)) |slot| {
            slot.line4.writev_in_flight = 0;
        }
        conn.tls_write_len = 0;
        self.closeConn(conn_id, conn.fd);
        return;
    }
    conn.tls_write_len = 0;

    const header_len = if (conn.response_buf) |rb|
        @min(conn.write_headers_len, rb.len)
    else
        0;
    const body_len = if (conn.write_body) |b| b.len else 0;
    const total = write_progress.writeTotal(header_len, body_len);

    // Advance write_offset by the plaintext that was encrypted in submitTlsWrite.
    // submitTlsWrite packs up to 16384 bytes of plaintext per chunk.
    conn.write_offset += write_progress.tlsChunkAdvance(total, conn.write_offset);

    if (conn.write_offset >= total) {
        finishWriteCleanup(self, conn);
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
            if (self.connSlot(conn)) |slot| {
                slot.line2.last_active_ms = conn.last_active_ms;
            }
            self.submitRead(conn_id, conn) catch |err| {
                logErr("submitRead failed for keep-alive fd {}: {s}", .{ conn.fd, @errorName(err) });
                self.closeConn(conn_id, conn.fd);
            };
        } else {
            self.closeConn(conn_id, conn.fd);
        }
    } else {
        // More plaintext to encrypt, submit next chunk
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
            logErr("submitWrite failed for TLS chunk fd {}: {s}", .{ conn.fd, @errorName(err) });
            if (self.connSlot(conn)) |slot| {
                slot.line4.writev_in_flight = 0;
            }
            self.closeConn(conn_id, conn.fd);
        };
    }
    }
}
