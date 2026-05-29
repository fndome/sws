const std = @import("std");
const linux = std.os.linux;

const AsyncServer = @import("async_server.zig").AsyncServer;
const Connection = @import("connection.zig").Connection;
const sticker = @import("../stack_pool_sticker.zig");
const Fiber = @import("../next/fiber.zig").Fiber;
const logErr = @import("http_helpers.zig").logErr;

const ACCEPT_USER_DATA = @import("../constants.zig").ACCEPT_USER_DATA;
const MAX_CQES_BATCH = @import("../constants.zig").MAX_CQES_BATCH;
const USER_TASK_BATCH = @import("../constants.zig").USER_TASK_BATCH;
const CLOSE_USER_DATA_FLAG = @import("../stack_pool.zig").CLOSE_USER_DATA_FLAG;
const packUserData = @import("../stack_pool.zig").packUserData;
const CLIENT_USER_DATA_FLAG = @import("../shared/io_registry.zig").CLIENT_USER_DATA_FLAG;
const Item = @import("../next/queue.zig").Item;
const IO_QUANTUM: usize = 64;
const TlsStream = @import("../tls/tls.zig").TlsStream;
const HandshakeStep = @import("../tls/tls.zig").HandshakeStep;

pub fn milliTimestamp(io: std.Io) i64 {
    const ts = std.Io.Timestamp.now(io, .real);
    return @as(i64, @intCast(@divTrunc(ts.nanoseconds, @as(i96, std.time.ns_per_ms))));
}

pub fn stop(self: *AsyncServer) void {
    // 修改原因：stop 可能由管理/压测线程触发，事件循环跨线程读取时需要原子同步。
    @atomicStore(bool, &self.should_stop, true, .release);
}

var sigterm_server: ?*AsyncServer = null;

pub fn installSigterm(self: *AsyncServer) void {
    sigterm_server = self;
    var act = std.mem.zeroes(linux.Sigaction);
    act.handler = .{ .handler = sigtermHandler };
    _ = linux.sigaction(linux.SIG.TERM, &act, null);
    _ = linux.sigaction(linux.SIG.INT, &act, null);
}

fn sigtermHandler(_: linux.SIG) callconv(.c) void {
    // 修改原因：信号回调和事件循环不在同一执行点，普通 bool 写入会和主循环读取形成数据竞争。
    if (sigterm_server) |s| @atomicStore(bool, &s.should_stop, true, .release);
}

pub fn drainPendingResumes(self: *AsyncServer) void {
    while (Fiber.popResume()) |entry| {
        if (entry.slot_idx != 0 and entry.gen_id != 0) {
            const slot = &self.pool.slots[entry.slot_idx];
            if (slot.line1.gen_id != entry.gen_id) continue;
        }
        Fiber.resumeYielded(entry.data);
    }
}

pub fn run(self: *AsyncServer) !void {
    // AsyncServer.init returns the server by value, so any pointer captured
    // inside init would point at the temporary local. Bind the WebSocket
    // callback context here, after the caller's final server address exists.
    self.ws_server.ctx = self;

    if (self.cfg.io_cpu) |cpu| {
        var mask: linux.cpu_set_t = [_]usize{0} ** (linux.CPU_SETSIZE / @sizeOf(usize));
        mask[0] = @as(usize, 1) << @as(u6, cpu);
        var orig_mask: linux.cpu_set_t = undefined;
        _ = linux.sched_getaffinity(0, @sizeOf(linux.cpu_set_t), &orig_mask);
        self.worker_orig_cpu_mask = orig_mask[0];
        self.io_pinned = if (linux.sched_setaffinity(0, &mask)) true else |_| false;
    }

    try self.submitAccept();

    var cqes: [MAX_CQES_BATCH]linux.io_uring_cqe = undefined;
    var user_tasks_buf: [USER_TASK_BATCH]Item = undefined;
    while (!@atomicLoad(bool, &self.should_stop, .acquire)) {
        // flushReplenish may fail when the SQ ring is full (scale > buffer
        // churn rate). This is non-fatal: remaining bids stay in the queue
        // and are retried next iteration. Do NOT propagate the error.
        self.buffer_pool.flushReplenish(&self.ring) catch |err| {
            logErr("flushReplenish deferred: {s}", .{@errorName(err)});
        };

        if (self.accept_stalled or !self.accept_outstanding) {
            // 修改原因：短连接关闭 CQE 和 accept CQE 交错时 accept 链可能断掉，主循环要能主动补提。
            self.submitAccept() catch |err| {
                logErr("accept chain recovery failed: {s}", .{@errorName(err)});
            };
        }

        // retry writes deferred by SQ backpressure (1M broadcast scenario)
        retryPendingWrites(self);

        _ = self.ring.submit() catch |err| {
            logErr("submit failed: {s}", .{@errorName(err)});
        };

        const n = self.ring.copy_cqes(&cqes, 0) catch |err| {
            if (err == error.SignalInterrupt) {
                // SIGTERM arrived during copy_cqes — loop back to check should_stop.
                continue;
            }
            return err;
        };
        if (n > 0) {
            dispatchCqes(self, &cqes, n);
            drainPendingResumes(self);
            drainNextTasks(self);

            // submit SQEs queued by dispatch/drain so they hit the ring
            // now, not next iteration. avoids +1 RTT on fiber writes.
            _ = self.ring.submit() catch |err| {
                logErr("submit-after-drain failed: {s}", .{@errorName(err)});
            };

            drainTick(self);
            ttlScanTick(self);
            continue;
        }

        if (self.timeout_user_data == 0) {
            submitIdleTimeout(self) catch |err| {
                logErr("submitIdleTimeout failed: {s}", .{@errorName(err)});
            };
        }

        {
            const n_user = self.submit_registry.drain(&user_tasks_buf);
            for (user_tasks_buf[0..n_user]) |*req| {
                executeNext(req);
            }
        }

        drainNextTasks(self);
        drainTick(self);
        ttlScanTick(self);

        _ = self.ring.submit_and_wait(1) catch |err| {
            if (err == error.SignalInterrupt) {
                continue;
            }
            return err;
        };
        const n2 = self.ring.copy_cqes(&cqes, 0) catch |err| {
            if (err == error.SignalInterrupt) {
                continue;
            }
            return err;
        };
        dispatchCqes(self, &cqes, n2);
        drainPendingResumes(self);
        ttlScanTick(self);
    }
}

pub fn dispatchCqes(self: *AsyncServer, cqes: []linux.io_uring_cqe, n: usize) void {
    // 修改原因：Zig 0.16 的 copy_cqes 已经推进 CQ head，额外 cqe_seen 会跳过后续完成事件。
    for (cqes[0..n]) |cqe| {
        const user_data = cqe.user_data;
        const res = cqe.res;

        if (self.timeout_user_data != 0 and user_data == self.timeout_user_data) {
            self.timeout_user_data = 0;
            continue;
        }

        if (user_data == ACCEPT_USER_DATA) {
            self.onAcceptComplete(res, user_data);
        } else if ((user_data & CLOSE_USER_DATA_FLAG) != 0) {
            const raw_ud = user_data & ~CLOSE_USER_DATA_FLAG;
            const close_conn_id: u64 = if (sticker.getSlotChecked(&self.pool, raw_ud)) |slot|
                slot.line2.conn_id
            else
                raw_ud;
            self.closeConn(close_conn_id, 0);
        } else if ((user_data & CLIENT_USER_DATA_FLAG) != 0) {
            self.io_registry.dispatch(user_data, res);
        } else {
            const disp = sticker.dispatchToken(&self.pool, &self.connections, user_data);
            const conn_ptr = if (disp) |d| @as(*Connection, @ptrCast(@alignCast(d.conn))) else {
                if (cqe.flags & linux.IORING_CQE_F_BUFFER != 0) {
                    self.buffer_pool.markReplenish(sticker.extractBid(cqe.flags));
                }
                continue;
            };
            const conn_id = conn_ptr.id;

            if (conn_ptr.state == .reading or conn_ptr.state == .processing) {
                self.onReadComplete(conn_id, res, user_data, cqe.flags);
            } else if (conn_ptr.state == .tls_handshaking) {
                self.onTlsHandshake(conn_id, conn_ptr, res, user_data, cqe.flags);
            } else if (conn_ptr.state == .receiving_body) {
                self.onBodyChunk(conn_id, res);
            } else if (conn_ptr.state == .streaming) {
                self.onStreamRead(conn_id, res, user_data, cqe.flags);
            } else if (conn_ptr.state == .writing) {
                self.onWriteComplete(conn_id, res, user_data);
            } else if (conn_ptr.state == .ws_reading) {
                self.onWsFrame(conn_id, res, user_data, cqe.flags);
            } else if (conn_ptr.state == .ws_writing) {
                self.onWsWriteComplete(conn_id, res, user_data);
            } else if (conn_ptr.state == .closing) {
                if (!conn_ptr.read_buf_recycled and cqe.flags & linux.IORING_CQE_F_BUFFER != 0) {
                    conn_ptr.read_buf_recycled = true;
                    const bid = @as(u16, @truncate(cqe.flags >> 16));
                    self.buffer_pool.markReplenish(bid);
                }
                if (conn_ptr.pool_idx != 0xFFFFFFFF) {
                    self.pool.slots[conn_ptr.pool_idx].line4.writev_in_flight = 0;
                }
                self.closeConn(conn_id, conn_ptr.fd);
            } else if (conn_ptr.state == .waiting_computation) {
                // Worker pool still computing; no new I/O is submitted in this state.
                // A residual CQE (e.g. a late read completion) must only replenish
                // its buffer — do NOT close the connection.
                if (cqe.flags & linux.IORING_CQE_F_BUFFER != 0) {
                    self.buffer_pool.markReplenish(sticker.extractBid(cqe.flags));
                }
            } else {
                self.closeConn(conn_id, conn_ptr.fd);
            }
        }
    }
}

pub fn drainNextTasks(self: *AsyncServer) void {
    if (self.next) |*n| {
        var count: usize = 0;
        while (count < IO_QUANTUM) : (count += 1) {
            const item = n.ringbuffer.pop() orelse break;
            executeNext(&item);
        }
    }
}

pub fn executeNext(req: *const Item) void {
    req.execute(req.ctx, req.on_complete);
}

/// SQ backpressure: retry writes that were deferred when ring.write()
/// failed (SQ full). called before each ring.submit() to drain the
/// pending queue into the fresh SQ ring.
///
/// WriteInFlight is not a retryable error — the write is already queued,
/// so just skip it. other errors mean the SQ is still full; break and
/// retry next iteration.
fn retryPendingWrites(self: *AsyncServer) void {
    const count = self.pending_writes.items.len;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const conn_id = self.pending_writes.items[i];
        if (getConn(self, conn_id)) |conn| {
            if (conn.state == .writing or conn.state == .ws_writing) {
                self.submitWrite(conn_id, conn) catch |err| {
                    if (err != error.WriteInFlight) break;
                };
            }
        }
    }
    if (i > 0) {
        std.mem.copyForwards(u64, self.pending_writes.items, self.pending_writes.items[i..]);
    }
    self.pending_writes.shrinkRetainingCapacity(self.pending_writes.items.len - i);
}

const getConn = @import("connection_mgr.zig").getConn;

pub fn submitIdleTimeout(self: *AsyncServer) !void {
    const user_data = self.nextUserData();
    _ = self.ring.timeout(user_data, &self.timeout_ts, 0, 0) catch {
        self.timeout_user_data = 0;
        return;
    };
    self.timeout_user_data = user_data;
}

pub fn ttlScanTick(self: *AsyncServer) void {
    const now = milliTimestamp(self.io);
    self.ttl_scan_out.clearRetainingCapacity();
    sticker.ttlScan(
        &self.pool,
        self.allocator,
        now,
        @intCast(self.cfg.idle_timeout_ms),
        &self.ttl_scan_cursor,
        512,
        &self.ttl_scan_out,
    );
    for (self.ttl_scan_out.items) |idx| {
        const slot = &self.pool.slots[idx];
        self.closeConn(slot.line2.conn_id, slot.line1.fd);
    }
}

pub fn drainTick(self: *AsyncServer) void {
    self.dns_resolver.tick();
    self.rs.invoke.drain(self.allocator);
    for (self.tick_hooks.items) |hook| {
        hook(self);
    }
}

fn onTlsHandshake(self: *AsyncServer, conn_id: u64, conn: *Connection, res: i32, user_data: u64, cqe_flags: u32) void {
    _ = user_data;
    const tls_stream = conn.tls orelse {
        self.closeConn(conn_id, conn.fd);
        return;
    };

    if (tls_stream.pending_handshake_write) {
        tls_stream.pending_handshake_write = false;
        if (res <= 0) {
            self.closeConn(conn_id, conn.fd);
            return;
        }
        conn.last_active_ms = milliTimestamp(self.io);
        self.submitRead(conn_id, conn) catch |err| {
            logErr("submitRead failed during TLS handshake: {s}", .{@errorName(err)});
            self.closeConn(conn_id, conn.fd);
        };
        return;
    }

    if (res <= 0) {
        if (cqe_flags & linux.IORING_CQE_F_BUFFER != 0) {
            const bid = @as(u16, @truncate(cqe_flags >> 16));
            self.buffer_pool.markReplenish(bid);
        }
        self.closeConn(conn_id, conn.fd);
        return;
    }

    var ciphertext: []const u8 = &.{};
    var bid: u16 = 0;
    if (cqe_flags & linux.IORING_CQE_F_BUFFER != 0) {
        bid = @as(u16, @truncate(cqe_flags >> 16));
        ciphertext = self.buffer_pool.getReadBuf(bid)[0..@as(usize, @intCast(res))];
    }

    if (conn.read_len > 0 and conn.read_bid != 0 and conn.read_bid != bid) {
        self.buffer_pool.markReplenish(conn.read_bid);
    }
    conn.read_bid = bid;
    conn.read_len = ciphertext.len;

    const step = tls_stream.handshakeAdvance(if (ciphertext.len > 0) ciphertext else null) catch {
        if (bid != 0) {
            self.buffer_pool.markReplenish(bid);
            conn.read_bid = 0;
            conn.read_len = 0;
        }
        logErr("TLS handshake failed for fd {}", .{conn.fd});
        self.closeConn(conn_id, conn.fd);
        return;
    };

    switch (step) {
        .done => {
            if (bid != 0) {
                self.buffer_pool.markReplenish(bid);
                conn.read_bid = 0;
                conn.read_len = 0;
            }
            conn.state = .reading;
            conn.last_active_ms = milliTimestamp(self.io);
            self.submitRead(conn_id, conn) catch |err| {
                logErr("submitRead after TLS handshake failed: {s}", .{@errorName(err)});
                self.closeConn(conn_id, conn.fd);
            };
        },
        .want_read => {
            if (bid != 0) {
                self.buffer_pool.markReplenish(bid);
                conn.read_bid = 0;
                conn.read_len = 0;
            }
            conn.last_active_ms = milliTimestamp(self.io);
            self.submitRead(conn_id, conn) catch |err| {
                logErr("submitRead during TLS handshake: {s}", .{@errorName(err)});
                self.closeConn(conn_id, conn.fd);
            };
        },
        .want_write => {
            const handshake_out = tls_stream.handshakeOutput();
            if (bid != 0) {
                self.buffer_pool.markReplenish(bid);
                conn.read_bid = 0;
                conn.read_len = 0;
            }
            submitTlsHandshakeWrite(self, conn_id, conn, handshake_out) catch |err| {
                logErr("submitTlsHandshakeWrite failed: {s}", .{@errorName(err)});
                self.closeConn(conn_id, conn.fd);
            };
        },
        .error => {
            if (bid != 0) {
                self.buffer_pool.markReplenish(bid);
                conn.read_bid = 0;
                conn.read_len = 0;
            }
            logErr("TLS handshake error for fd {}", .{conn.fd});
            self.closeConn(conn_id, conn.fd);
        },
    }
}

fn submitTlsHandshakeWrite(self: *AsyncServer, conn_id: u64, conn: *Connection, data: []const u8) !void {
    _ = conn_id;
    const tls_stream = conn.tls orelse return error.NoTlsStream;
    const user_data = packUserData(conn.gen_id, conn.pool_idx);
    const fd = if (conn.fixed_index != 0xFFFF) @as(i32, @intCast(conn.fixed_index)) else conn.fd;
    const sqe = self.ring.write(user_data, fd, data, 0) catch {
        return error.RingFull;
    };
    if (conn.fixed_index != 0xFFFF) sqe.flags |= linux.IOSQE_FIXED_FILE;
    tls_stream.pending_handshake_write = true;
}
