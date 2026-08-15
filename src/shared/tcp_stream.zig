const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");

const RingShared = @import("ring_shared.zig").RingShared;
const DnsResolver = @import("../dns/resolver.zig").DnsResolver;
const NO_FIXED_FILE = @import("../constants.zig").NO_FIXED_FILE;
const logErr = @import("../async_logger.zig").logErr;
const TlsStream = if (build_options.tls_enabled) @import("../tls/tls.zig").TlsStream else struct {};
const HandshakeStep = if (build_options.tls_enabled) @import("../tls/tls.zig").HandshakeStep else struct {};
const tls_lib = @import("tls");

pub const CLIENT_READ_BUF = 16384;
pub const CLIENT_TLS_RECV_BUF = if (build_options.tls_enabled) tls_lib.input_buffer_len else CLIENT_READ_BUF;
pub const CLIENT_TLS_SEND_BUF = if (build_options.tls_enabled) tls_lib.output_buffer_len else CLIENT_READ_BUF;
const CLIENT_WRITE_USER_DATA_FLAG: u64 = 1 << 61;

fn clientDispatch(ptr: *anyopaque, user_data: u64, res: i32) void {
    const self: *RingSharedClient = @ptrCast(@alignCast(ptr));
    self.dispatchCqeRes(user_data, res);
}

fn streamSocketFd(raw_fd: usize) !i32 {
    // 修改原因：linux.socket 失败时返回 errno 编码的 usize，先 @intCast 会在安全构建下触发整数转换失败。
    if (linux.errno(raw_fd) != .SUCCESS) return error.SocketFailed;
    return @intCast(raw_fd);
}

pub const RingSharedClient = struct {
    allocator: Allocator,
    rs: RingShared,
    id: u64,
    fd: i32,
    state: State,

    on_data: *const fn (stream: *RingSharedClient, ctx: ?*anyopaque, data: []u8) void,
    on_close: *const fn (stream: *RingSharedClient, ctx: ?*anyopaque) void,
    callback_ctx: ?*anyopaque,

    read_buf: []u8,
    conn_errno: i32 = 0, // connect CQE 错误码 (0=成功, -ETIMEDOUT=超时)
    connect_addr: linux.sockaddr = undefined,
    connect_timeout_ts: linux.timespec = .{ .sec = 0, .nsec = 0 },
    _connect_addrlen: u32 = 0,

    write_buf: std.ArrayList(u8),
    write_offset: usize,
    writing: bool,

    dns: ?*DnsResolver,
    fixed_index: u16 = NO_FIXED_FILE,
    tls: ?*TlsStream = null,
    tls_handshaking: bool = false,
    tls_write_plaintext: u32 = 0,
    tls_ciphertext_buf: ?[]u8 = null,

    pub const State = enum(u8) {
        idle,
        connecting,
        connected,
        closing,
        closed,
    };

    pub fn init(
        allocator: Allocator,
        rs: RingShared,
        on_data: *const fn (stream: *RingSharedClient, ctx: ?*anyopaque, data: []u8) void,
        on_close: *const fn (stream: *RingSharedClient, ctx: ?*anyopaque) void,
        callback_ctx: ?*anyopaque,
        dns: ?*DnsResolver,
    ) !*RingSharedClient {
        const self = try allocator.create(RingSharedClient);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .rs = rs,
            .id = 0,
            .fd = -1,
            .state = .idle,
            .on_data = on_data,
            .on_close = on_close,
            .callback_ctx = callback_ctx,
            .read_buf = try allocator.alloc(u8, CLIENT_READ_BUF),
            .write_buf = std.ArrayList(u8).empty,
            .write_offset = 0,
            .writing = false,
            .dns = dns,
        };
        return self;
    }

    pub fn resetForReuse(self: *RingSharedClient) void {
        self.write_offset = 0;
        self.write_buf.clearRetainingCapacity();
        self.writing = false;
        if (build_options.tls_enabled) {
            if (self.tls) |tls_stream| {
                tls_stream.reset();
            }
        }
    }

    pub fn deinit(self: *RingSharedClient) void {
        if (build_options.tls_enabled) {
            if (self.tls) |tls_stream| {
                tls_stream.free();
                self.allocator.destroy(tls_stream);
                self.tls = null;
            }
            if (self.tls_ciphertext_buf) |buf| {
                self.allocator.free(buf);
                self.tls_ciphertext_buf = null;
            }
        }
        if (self.id != 0) {
            self.rs.remove(self.id);
        }
        if (self.fd >= 0) {
            _ = linux.close(self.fd);
            self.fd = -1;
        }
        self.allocator.free(self.read_buf);
        self.write_buf.deinit(self.allocator);
        self.state = .closed;
        self.allocator.destroy(self);
    }

    pub fn connect(self: *RingSharedClient, host: []const u8, port: u16) !void {
        const ip = parseIpv4(host) catch blk: {
            if (self.dns) |dns| {
                break :blk dns.resolve(host) catch return error.InvalidHost;
            }
            return error.InvalidHost;
        };
        self.connectRaw(ip, port) catch |err| return err;
    }

    pub fn connectRaw(self: *RingSharedClient, ip: u32, port: u16) !void {
        try self.connectRawTimeout(ip, port, 5000); // default 5s
    }

    pub fn connectRawTimeout(self: *RingSharedClient, ip: u32, port: u16, timeout_ms: u32) !void {
        const raw_fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
        const fd = try streamSocketFd(raw_fd);
        errdefer {
            // 修改原因：connect 提交失败时 self.fd/self.id 已经写入，必须同步清理，避免调用方 deinit 时重复关闭 fd 或留下 registry 项。
            if (self.id != 0) {
                self.rs.remove(self.id);
                self.id = 0;
            }
            if (self.fd == fd) {
                _ = linux.close(fd);
                self.fd = -1;
            }
            self.state = .idle;
        }

        var addr_in = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = @byteSwap(port),
            .addr = ip,
            .zero = [_]u8{0} ** 8,
        };
        const addr: *linux.sockaddr = @ptrCast(&addr_in);

        self.fd = fd;
        self.id = self.rs.allocUserData();
        self.connect_addr = addr.*;
        self._connect_addrlen = @sizeOf(linux.sockaddr.in);
        var registered = false;
        errdefer {
            // 修改原因：connect SQE 入队或 submit 失败时，fd/id 仍挂在 client 上会导致后续重复 close 或注册表残留。
            if (registered) self.rs.remove(self.id);
            // 修改原因：内层 errdefer 会先把 self.fd 复位，必须在复位前关闭本次创建的 socket，避免外层守卫看不到 fd。
            if (self.fd == fd) _ = linux.close(fd);
            self.id = 0;
            self.fd = -1;
            self.state = .idle;
        }

        self.rs.register(self.id, @ptrCast(self), &clientDispatch) catch return error.RegisterFailed;
        registered = true;
        self.state = .connecting;

        _ = linux.connect(fd, @ptrCast(&addr_in), @sizeOf(linux.sockaddr.in));
        try self.submitPollOut(timeout_ms);
    }

    fn submitPollOut(self: *RingSharedClient, timeout_ms: u32) !void {
        const ring = self.rs.ringPtr();
        // 修改原因：带超时的 connect 必须同时拿到 CONNECT 和 LINK_TIMEOUT 两个 SQE；否则会提交一个没有超时保护的连接。
        if (!hasConnectSqeCapacity(@intCast(ring.sq_ready()), ring.sq.sqes.len, timeout_ms)) return error.ConnectSubmitQueueFull;
        // 修改原因：CONNECT SQE 都拿不到时不能静默成功，否则连接会永久停在 connecting 且 fd/registry 无法回收。
        const sqe = ring.nop(self.id) catch return error.ConnectSubmitQueueFull;
        sqe.opcode = .CONNECT;
        sqe.fd = self.fd;
        sqe.addr = @intFromPtr(&self.connect_addr);
        sqe.off = self._connect_addrlen;
        if (timeout_ms > 0) {
            const tsqe = ring.nop(0) catch {
                _ = ring.submit() catch |err| logErr("client connect submit failed: {s}", .{@errorName(err)});
                return error.ConnectSubmitQueueFull;
            };
            sqe.flags |= linux.IOSQE_IO_LINK; // link LINK_TIMEOUT next
            tsqe.opcode = .LINK_TIMEOUT;
            // 修改原因：LINK_TIMEOUT 的 timespec 会被内核异步读取，不能指向本函数的栈变量。
            self.connect_timeout_ts = .{
                .sec = @intCast(timeout_ms / 1000),
                .nsec = @intCast((timeout_ms % 1000) * 1_000_000),
            };
            tsqe.addr = @intFromPtr(&self.connect_timeout_ts);
            tsqe.len = 1;
            // CONNECT + LINK_TIMEOUT submitted together — no orphan window
        }
        _ = ring.submit() catch |err| logErr("client connect submit failed: {s}", .{@errorName(err)});
    }

    pub fn write(self: *RingSharedClient, data: []const u8) !void {
        if (self.state == .connecting) {
            try self.write_buf.appendSlice(self.allocator, data);
            return;
        }
        if (self.state != .connected) return error.NotConnected;
        if (build_options.tls_enabled) {
            if (self.tls != null) {
                if (self.tls_handshaking) {
                    try self.write_buf.appendSlice(self.allocator, data);
                    return;
                }
                return self.writeTls(data);
            }
        }
        try self.write_buf.appendSlice(self.allocator, data);
        if (!self.writing) {
            try self.flushWrite();
        }
    }

    fn writeTls(self: *RingSharedClient, data: []const u8) !void {
        if (build_options.tls_enabled) {
        const tls_stream = self.tls orelse return error.NotConnected;
        if (self.tls_ciphertext_buf == null) {
            self.tls_ciphertext_buf = self.allocator.alloc(u8, CLIENT_TLS_SEND_BUF) catch return error.OutOfMemory;
        }
        var ciphertext_buf = self.tls_ciphertext_buf.?;
        const ciphertext_len = tls_stream.write(data, ciphertext_buf) catch return error.TlsWriteFailed;
        if (ciphertext_len == 0) return;
        try self.write_buf.appendSlice(self.allocator, ciphertext_buf[0..ciphertext_len]);
        if (!self.writing) {
            try self.flushWrite();
        }
    }
    }

    fn flushTlsWrites(self: *RingSharedClient) !void {
        const tls_stream = self.tls orelse return error.NotConnected;
        if (self.write_offset >= self.write_buf.items.len) {
            // All plaintext flushed: reset write_buf and submit read for response
            self.write_offset = 0;
            self.write_buf.clearRetainingCapacity();
            self.writing = false;
            try self.submitRead();
            return;
        }
        const remaining = self.write_buf.items[self.write_offset..];
        const to_encrypt = if (remaining.len > 16384) remaining[0..16384] else remaining;
        if (self.tls_ciphertext_buf == null) {
            self.tls_ciphertext_buf = self.allocator.alloc(u8, CLIENT_TLS_SEND_BUF) catch return error.OutOfMemory;
        }
        var ciphertext_buf = self.tls_ciphertext_buf.?;
        const ciphertext_len = tls_stream.write(to_encrypt, ciphertext_buf) catch return error.TlsWriteFailed;
        if (ciphertext_len == 0) return;
        // Track how much plaintext this chunk consumed for offset advancement on CQE
        self.tls_write_plaintext = @intCast(to_encrypt.len);
        // Write ciphertext to socket
        const use_fixed = self.fixed_index != NO_FIXED_FILE;
        const fd_or_idx = if (use_fixed) @as(i32, @intCast(self.fixed_index)) else self.fd;
        const sqe = try self.rs.ringPtr().write(self.id | CLIENT_WRITE_USER_DATA_FLAG, fd_or_idx, ciphertext_buf[0..ciphertext_len], 0);
        if (use_fixed) sqe.flags |= linux.IOSQE_FIXED_FILE;
        self.writing = true;
    }

    fn writeRawTls(self: *RingSharedClient, data: []const u8) !void {
        if (build_options.tls_enabled) {
        try self.write_buf.appendSlice(self.allocator, data);
        if (!self.writing) {
            try self.flushWrite();
        }
        }
    }

    fn flushWrite(self: *RingSharedClient) !void {
        if (self.write_offset >= self.write_buf.items.len) {
            self.write_offset = 0;
            self.write_buf.clearRetainingCapacity();
            self.writing = false;
            try self.submitRead();
            return;
        }
        const to_send = self.write_buf.items[self.write_offset..];
        const use_fixed = self.fixed_index != NO_FIXED_FILE;
        const fd_or_idx = if (use_fixed) @as(i32, @intCast(self.fixed_index)) else self.fd;
        // 修改原因：同一连接上可能同时存在 keep-alive 读 CQE 和新请求写 CQE；
        // 给写操作打标记，完成时才能按真实操作类型分发，而不是靠 self.writing 猜。
        const sqe = try self.rs.ringPtr().write(self.id | CLIENT_WRITE_USER_DATA_FLAG, fd_or_idx, to_send, 0);
        if (use_fixed) sqe.flags |= linux.IOSQE_FIXED_FILE;
        self.writing = true;
    }

    fn submitRead(self: *RingSharedClient) !void {
        const use_fixed = self.fixed_index != NO_FIXED_FILE;
        const fd_or_idx = if (use_fixed) @as(i32, @intCast(self.fixed_index)) else self.fd;
        const sqe = try self.rs.ringPtr().read(self.id, fd_or_idx, .{ .buffer = self.read_buf }, 0);
        if (use_fixed) sqe.flags |= linux.IOSQE_FIXED_FILE;
    }

    pub fn close(self: *RingSharedClient) void {
        if (self.state == .closing or self.state == .closed) return;
        self.state = .closing;
    }

    pub fn startTls(self: *RingSharedClient, tls_config: *@import("../tls/tls.zig").TlsConfig) !void {
        if (build_options.tls_enabled) {
        const tls_stream = try self.allocator.create(TlsStream);
        errdefer self.allocator.destroy(tls_stream);
        tls_stream.* = try TlsStream.new(tls_config);
        // Upgrade read buffer for max TLS ciphertext record (16645 > 16384)
        if (self.read_buf.len < CLIENT_TLS_RECV_BUF) {
            const new_buf = try self.allocator.alloc(u8, CLIENT_TLS_RECV_BUF);
            self.allocator.free(self.read_buf);
            self.read_buf = new_buf;
        }
        self.tls = tls_stream;
        self.tls_handshaking = true;

        const step = tls_stream.handshakeAdvance(null) catch {
            tls_stream.free();
            self.allocator.destroy(tls_stream);
            self.tls = null;
            self.tls_handshaking = false;
            return error.TlsHandshakeFailed;
        };

        switch (step) {
            .want_write => {
                const handshake_out = tls_stream.handshakeOutput();
                self.writeRawTls(handshake_out) catch {
                    tls_stream.free();
                    self.allocator.destroy(tls_stream);
                    self.tls = null;
                    self.tls_handshaking = false;
                    return error.TlsHandshakeFailed;
                };
            },
            .want_read => {
                self.submitRead() catch {
                    tls_stream.free();
                    self.allocator.destroy(tls_stream);
                    self.tls = null;
                    self.tls_handshaking = false;
                    return error.TlsHandshakeFailed;
                };
            },
            .done => {
                self.tls_handshaking = false;
            },
            .@"error" => {
                tls_stream.free();
                self.allocator.destroy(tls_stream);
                self.tls = null;
                self.tls_handshaking = false;
                return error.TlsHandshakeFailed;
            },
        }
    }
    } // build_options.tls_enabled

    pub fn dispatchCqe(self: *RingSharedClient, cqe: *const linux.io_uring_cqe) void {
        self.dispatchCqeRes(cqe.user_data, cqe.res);
    }

    fn dispatchCqeRes(self: *RingSharedClient, user_data: u64, res: i32) void {
        switch (self.state) {
            .connecting => {
                if (res < 0) {
                    self.conn_errno = res;
                    self.onClose();
                    return;
                }
                self.conn_errno = 0;
                var so_err: i32 = 0;
                var so_len: linux.socklen_t = @sizeOf(i32);
                const rc = linux.getsockopt(self.fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&so_err), &so_len);
                if (rc != 0 or so_err != 0) {
                    self.onClose();
                    return;
                }
                self.state = .connected;
                // Disable Nagle — low-latency microservice calls
                const one: i32 = 1;
                _ = linux.setsockopt(self.fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, @ptrCast(&one), @sizeOf(i32));
                // 修改原因：RingSharedClient 没有 fixed-file 槽位分配器；多个连接共用 slot 0 会互相覆盖 fd。
                self.fixed_index = NO_FIXED_FILE;
                if (self.write_buf.items.len > self.write_offset) {
                    // 修改原因：连接建立前排队的首个请求必须先写出，再等响应；否则新建连接会先挂读或直接丢掉首包。
                    self.flushWrite() catch {
                        self.onClose();
                    };
                } else {
                    self.submitRead() catch {
                        self.onClose();
                    };
                }
            },
            .connected, .closing => {
                if (res < 0) {
                    self.onClose();
                    return;
                }
                if (isWriteCqe(user_data)) {
                    if (res == 0) {
                        self.onClose();
                        return;
                    }
                    if (build_options.tls_enabled and self.tls_handshaking) {
                        // TLS handshake write CQE: advance ciphertext offset, continue handshake
                        self.write_offset += @intCast(res);
                        if (self.tls) |tls_stream| {
                            const step = tls_stream.handshakeAdvance(null) catch {
                                self.onClose();
                                return;
                            };
                            switch (step) {
                                .done => {
                                    self.tls_handshaking = false;
                                    if (self.write_buf.items.len > self.write_offset) {
                                        self.flushTlsWrites() catch {
                                            self.onClose();
                                            return;
                                        };
                                    }
                                },
                                .want_write => {
                                    const handshake_out = tls_stream.handshakeOutput();
                                    self.writeRawTls(handshake_out) catch {
                                        self.onClose();
                                    };
                                    return;
                                },
                                .want_read => {
                                    self.submitRead() catch {
                                        self.onClose();
                                    };
                                    return;
                                },
                                .@"error" => {
                                    self.onClose();
                                    return;
                                },
                            }
                        }
                        self.flushWrite() catch {
                            self.onClose();
                        };
                    } else if (build_options.tls_enabled and self.tls != null and !self.tls_handshaking) {
                        if (self.tls_write_plaintext > 0) {
                            // flushTlsWrites path: advance by PLAINTEXT consumed
                            self.write_offset += self.tls_write_plaintext;
                            self.tls_write_plaintext = 0;
                            self.flushTlsWrites() catch {
                                self.onClose();
                            };
                        } else {
                            // writeTls path: ciphertext was appended to write_buf, advance by CIPHERTEXT bytes
                            self.write_offset += @intCast(res);
                            self.flushWrite() catch {
                                self.onClose();
                            };
                        }
                    } else {
                        // Plaintext write CQE
                        self.write_offset += @intCast(res);
                        self.flushWrite() catch {
                            self.onClose();
                        };
                    }
                } else {
                    if (res == 0) {
                        self.onClose();
                        return;
                    }
                    const raw_read = self.read_buf[0..@intCast(res)];
                    if (build_options.tls_enabled) {
                        if (self.tls_handshaking) {
                            if (self.tls) |tls_stream| {
                                const step = tls_stream.handshakeAdvance(raw_read) catch {
                                    self.onClose();
                                    return;
                                };
                                switch (step) {
                                    .done => {
                                        self.tls_handshaking = false;
                                        if (self.write_buf.items.len > self.write_offset) {
                                            self.flushTlsWrites() catch {
                                                self.onClose();
                                                return;
                                            };
                                        }
                                    },
                                    .want_write => {
                                        const handshake_out = tls_stream.handshakeOutput();
                                        self.writeRawTls(handshake_out) catch {
                                            self.onClose();
                                        };
                                        return;
                                    },
                                    .want_read => {
                                        self.submitRead() catch {
                                            self.onClose();
                                        };
                                        return;
                                    },
                                    .@"error" => {
                                        self.onClose();
                                        return;
                                    },
                                }
                            }
                        }
                        if (self.tls) |tls_stream| {
                            var plaintext_buf: [CLIENT_READ_BUF]u8 = [_]u8{0} ** CLIENT_READ_BUF;
                            const decrypted = tls_stream.read(raw_read, &plaintext_buf) catch {
                                self.onClose();
                                return;
                            };
                            if (decrypted > 0) {
                                self.on_data(self, self.callback_ctx, plaintext_buf[0..decrypted]);
                            }
                        } else {
                            self.on_data(self, self.callback_ctx, raw_read);
                        }
                    } else {
                        self.on_data(self, self.callback_ctx, raw_read);
                    }
                    if (self.state != .connected) return;
                    if (!self.writing) {
                        self.submitRead() catch {
                            self.onClose();
                        };
                    }
                }
            },
            .idle, .closed => {},
        }
    }

    fn onClose(self: *RingSharedClient) void {
        if (self.state == .closed) return;
        self.state = .closed;
        if (self.fixed_index != NO_FIXED_FILE) {
            _ = self.rs.ringPtr().register_files_update(self.fixed_index, &[_]linux.fd_t{-1}) catch |err| logErr("client register_files_update failed for idx={d}: {s}", .{ self.fixed_index, @errorName(err) });
        }
        if (self.fd >= 0) {
            _ = linux.close(self.fd);
            self.fd = -1;
        }
        if (self.id != 0) {
            self.rs.remove(self.id);
        }
        self.on_close(self, self.callback_ctx);
    }
};

fn parseIpv4(ip_str: []const u8) !u32 {
    var parts = std.mem.splitScalar(u8, ip_str, '.');
    var octets: [4]u8 = undefined;
    var i: usize = 0;
    while (parts.next()) |part| : (i += 1) {
        if (i >= 4) return error.InvalidHost;
        octets[i] = try std.fmt.parseInt(u8, part, 10);
    }
    if (i != 4) return error.InvalidHost;
    const ip = (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        (@as(u32, octets[3]));
    // 修改原因：connectRaw 会直接把 ip 写进 sockaddr.in.addr，返回值必须是网络字节序布局。
    return std.mem.nativeToBig(u32, ip);
}

fn isWriteCqe(user_data: u64) bool {
    return (user_data & CLIENT_WRITE_USER_DATA_FLAG) != 0;
}

fn hasConnectSqeCapacity(ready: usize, capacity: usize, timeout_ms: u32) bool {
    if (ready > capacity) return false;
    const needed: usize = if (timeout_ms > 0) 2 else 1;
    return capacity - ready >= needed;
}

fn noopClientData(stream: *RingSharedClient, ctx: ?*anyopaque, data: []u8) void {
    _ = stream;
    _ = ctx;
    _ = data;
}

fn noopClientClose(stream: *RingSharedClient, ctx: ?*anyopaque) void {
    _ = stream;
    _ = ctx;
}

test "RingSharedClient distinguishes write CQE user data" {
    const base = @as(u64, 1) << 62;
    try std.testing.expect(!isWriteCqe(base));
    try std.testing.expect(isWriteCqe(base | CLIENT_WRITE_USER_DATA_FLAG));
}

test "RingSharedClient connect submit checks timeout SQE capacity" {
    try std.testing.expect(hasConnectSqeCapacity(254, 256, 5000));
    try std.testing.expect(!hasConnectSqeCapacity(255, 256, 5000));
    try std.testing.expect(hasConnectSqeCapacity(255, 256, 0));
}

test "RingSharedClient socket fd conversion checks errno before casting" {
    const failed: usize = @bitCast(@as(isize, -1));
    try std.testing.expectError(error.SocketFailed, streamSocketFd(failed));
    try std.testing.expectEqual(@as(i32, 3), try streamSocketFd(3));
}

test "RingSharedClient queues writes while connect is in flight" {
    var read_buf: [1]u8 = undefined;
    var client = RingSharedClient{
        .allocator = std.testing.allocator,
        .rs = undefined,
        .id = 0,
        .fd = -1,
        .state = .connecting,
        .on_data = &noopClientData,
        .on_close = &noopClientClose,
        .callback_ctx = null,
        .read_buf = read_buf[0..],
        .write_buf = std.ArrayList(u8).empty,
        .write_offset = 0,
        .writing = false,
        .dns = null,
    };
    defer client.write_buf.deinit(std.testing.allocator);

    try client.write("GET / HTTP/1.1\r\n\r\n");

    try std.testing.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", client.write_buf.items);
    try std.testing.expect(!client.writing);
}
