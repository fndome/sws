const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const StreamHandle = @import("../next/chunk_stream.zig").StreamHandle;

const TCP_READ_BUF = 262144; // 256KB

/// ── TcpOutboundRing: 通用 TCP 出站 io_uring 通道 ──────────
///
/// 不与 RingA(主服务)/RingB(HTTP)/RingC(NATS) 共享 ring。
/// 每条 TCP 连接有独立 token → CQE 路由。
/// tick() 非阻塞: submit pending SQEs → 收已有 CQEs → 处理 → 重投读取。
///
/// 同一 ring 可承载 MySQL、Redis、PostgreSQL 等多种协议。
/// 上层只需要 connect → (可选 auth/query helpers) → attachStream。
///
/// 用法:
///   var ring = try TcpOutboundRing.init(alloc, 256);
///   defer ring.deinit();
///   const conn = try ring.connect("127.0.0.1", 3306);
///   ring.attachStream(conn, stream);
///   // 主循环: while (running) { ring.tick(); }
pub const TcpOutboundRing = struct {
    const Self = @This();

    ring: linux.IoUring,
    allocator: Allocator,
    conns: std.AutoHashMap(u64, *TcpConn),
    next_token: u64 = 1,
    cqes: [256]linux.io_uring_cqe = [_]linux.io_uring_cqe{std.mem.zeroes(linux.io_uring_cqe)} ** 256,

    pub fn init(allocator: Allocator, entries: u12) !TcpOutboundRing {
        const ring = try linux.IoUring.init(entries, 0);
        return TcpOutboundRing{
            .ring = ring,
            .allocator = allocator,
            .conns = std.AutoHashMap(u64, *TcpConn).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.conns.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.conns.deinit();
        self.ring.deinit();
    }

    /// 非阻塞 tick: 投递 SQEs → 收已有 CQEs → 处理。
    /// 在主 event loop 中每轮调用一次。
    pub fn tick(self: *Self) void {
        _ = self.ring.submit() catch {};

        const n = self.ring.copy_cqes(self.cqes, 0) catch 0;
        // 修改原因：Zig 0.16 的 copy_cqes 已经消费 CQE，重复 cqe_seen 会漏处理出站事件。
        for (self.cqes[0..n]) |*cqe| {
            self.processCqe(cqe);
        }
    }

    fn processCqe(self: *Self, cqe: *const linux.io_uring_cqe) void {
        const token = cqe.user_data;
        const conn = self.conns.getPtr(token) orelse return;
        const res = cqe.res;

        switch (conn.state) {
            .connecting => {
                if (res < 0) {
                    self.closeConnFd(conn);
                    return;
                }
                conn.state = .idle;
                self.submitReadyIo(conn);
            },
            .reading => {
                if (res <= 0) {
                    if (conn.stream) |s| _ = s.finish();
                    self.closeConnFd(conn);
                    return;
                }
                const n = @as(usize, @intCast(res));
                if (conn.stream) |s| {
                    _ = s.feed(conn.read_buf[0..n]);
                } else if (conn.on_read) |cb| {
                    cb(conn.on_read_ctx, conn.read_buf[0..n]);
                }
                self.submitReadyIo(conn);
            },
            .writing => {
                if (res <= 0) {
                    self.closeConnFd(conn);
                    return;
                }
                conn.written += @as(usize, @intCast(res));
                if (conn.written >= conn.wbuf_len) {
                    conn.wbuf_len = 0;
                    conn.written = 0;
                    conn.state = .idle;
                    self.submitReadyIo(conn);
                } else {
                    conn.submitWrite(&self.ring) catch {
                        self.closeConnFd(conn);
                    };
                }
            },
            .idle, .closing => {},
        }
    }

    fn submitReadyIo(self: *Self, conn: *TcpConn) void {
        switch (conn.nextReadyIo()) {
            .write => {
                conn.submitWrite(&self.ring) catch self.closeConnFd(conn);
            },
            .read => conn.submitRead(&self.ring) catch self.closeConnFd(conn),
            .idle => {},
        }
    }

    pub fn connect(self: *Self, host: []const u8, port: u16) !*TcpConn {
        const fd = try linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        errdefer _ = linux.close(fd);

        const addr = try std.net.Address.parseIp(host, port) catch
            try std.net.Address.resolveIp(host, port, .ip4);

        const token = self.next_token;
        self.next_token += 1;

        const conn = init: {
            const c = try self.allocator.create(TcpConn);
            errdefer self.allocator.destroy(c);
            c.* = .{
                .fd = fd,
                .token = token,
                .state = .connecting,
                .stream = null,
                .on_read = null,
                .on_read_ctx = null,
                .read_buf = try self.allocator.alloc(u8, TCP_READ_BUF),
                .wbuf = .{},
                .wbuf_len = 0,
                .written = 0,
            };
            break :init c;
        };
        // After the labeled block, the plain destroy errdefer is out of scope.
        // Only this errdefer (full deinit) will fire on subsequent failures.
        errdefer conn.deinit(self.allocator);

        try self.conns.put(token, conn);
        errdefer _ = self.conns.remove(token);

        try self.ring.connect(token, fd, &addr.any, addr.getOsSockLen());
        _ = self.ring.submit() catch {};
        return conn;
    }

    pub fn attachStream(self: *Self, conn: *TcpConn, stream: *StreamHandle) void {
        conn.stream = stream;
        if (conn.state != .idle) return;
        conn.submitRead(&self.ring) catch self.closeConnFd(conn);
    }

    pub fn write(self: *Self, conn: *TcpConn, data: []const u8) !void {
        if (conn.state == .closing) return error.ConnClosed;
        if (conn.wbuf_len + data.len > conn.wbuf.len) {
            return error.WriteBufferFull;
        }
        @memcpy(conn.wbuf[conn.wbuf_len..][0..data.len], data);
        conn.wbuf_len += data.len;
        if (conn.state == .idle) {
            conn.submitWrite(&self.ring) catch self.closeConnFd(conn);
        }
    }

    /// Close a connection explicitly. Safe to call multiple times.
    /// Returns false if the connection was already removed from the map.
    pub fn close(self: *Self, conn: *TcpConn) bool {
        if (self.conns.getPtr(conn.token)) |_| {
            self.removeConn(conn);
            return true;
        }
        return false;
    }

    fn removeConn(self: *Self, conn: *TcpConn) void {
        _ = self.conns.remove(conn.token);
        conn.deinit(self.allocator);
    }

    fn closeConnFd(self: *Self, conn: *TcpConn) void {
        _ = self;
        if (conn.fd >= 0) {
            _ = linux.close(conn.fd);
            conn.fd = -1;
        }
        conn.state = .closing;
    }
};

pub const TcpConn = struct {
    fd: i32,
    token: u64,
    state: State,
    stream: ?*StreamHandle,
    on_read: ?*const fn (ctx: ?*anyopaque, data: []const u8) void,
    on_read_ctx: ?*anyopaque,
    read_buf: []u8,
    wbuf: [65536]u8, // 64KB, 对齐 read_buf
    wbuf_len: usize,
    written: usize,

    pub const State = enum(u8) { connecting, idle, reading, writing, closing };
    const ReadyIo = enum { write, read, idle };

    fn nextReadyIo(self: *const TcpConn) ReadyIo {
        if (self.written < self.wbuf_len) return .write;
        if (self.stream != null or self.on_read != null) return .read;
        return .idle;
    }

    // Queue an SQE via the ring; actual submission is batched in tick().
    // Calling ring.submit() per I/O would trigger io_uring_enter on every
    // read/write, wasting syscalls when multiple connections share the ring.
    fn submitRead(self: *TcpConn, ring: *linux.IoUring) !void {
        // 修复：移除每次 I/O 后的独立 ring.submit()，由 tick() 统一提交以减少 io_uring_enter 调用。
        self.state = .reading;
        _ = try ring.read(self.token, self.fd, .{ .buffer = self.read_buf }, 0);
    }

    fn submitWrite(self: *TcpConn, ring: *linux.IoUring) !void {
        // 修复：同上，提交由 tick() 统一处理。
        self.state = .writing;
        const pending = self.wbuf[self.written..self.wbuf_len];
        _ = try ring.write(self.token, self.fd, pending, 0);
    }

    fn deinit(self: *TcpConn, allocator: Allocator) void {
        if (self.fd >= 0) {
            _ = linux.close(self.fd);
            self.fd = -1;
        }
        allocator.free(self.read_buf);
        allocator.destroy(self);
    }
};

fn dummyRead(_: ?*anyopaque, _: []const u8) void {}

test "TcpConn prefers pending writes before re-arming reads" {
    var read_buf: [0]u8 = .{};
    var conn = TcpConn{
        .fd = -1,
        .token = 1,
        .state = .idle,
        .stream = null,
        .on_read = dummyRead,
        .on_read_ctx = null,
        .read_buf = read_buf[0..],
        .wbuf = .{},
        .wbuf_len = 4,
        .written = 0,
    };

    try std.testing.expectEqual(TcpConn.ReadyIo.write, conn.nextReadyIo());
    conn.written = conn.wbuf_len;
    try std.testing.expectEqual(TcpConn.ReadyIo.read, conn.nextReadyIo());
    conn.on_read = null;
    try std.testing.expectEqual(TcpConn.ReadyIo.idle, conn.nextReadyIo());
}
