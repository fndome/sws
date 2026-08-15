const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const logWarn = @import("../async_logger.zig").logWarn;

const packet = @import("packet.zig");
const cache_mod = @import("cache.zig");
const DnsCache = cache_mod.DnsCache;
const Fiber = @import("../next/fiber.zig").Fiber;
const RingShared = @import("../shared/ring_shared.zig").RingShared;

const DNS_TIMEOUT_MS: i64 = 2000;
const MAX_RETRIES: u8 = 2;

const PendingQuery = struct {
    txid: u16,
    hostname: []const u8,
    deadline_ms: i64,
    retries: u8,
    slot: Fiber.DnsYieldSlot,
};

const QueryResult = struct {
    addrs: [packet.AddrList.MAX_ADDRS]u32,
    len: u8,
    ttl: u32,
};

fn dnsDispatch(ptr: *anyopaque, user_data: u64, res: i32) void {
    _ = user_data;
    const self: *DnsResolver = @ptrCast(@alignCast(ptr));
    self.handleCqe(res);
}

fn udpSocketFd(raw_fd: usize) !i32 {
    // 修改原因：UDP socket 创建失败时 raw_fd 是 errno 编码值，不能先转成 i32 再判断负数。
    if (linux.errno(raw_fd) != .SUCCESS) return error.UdpSocketFailed;
    return @intCast(raw_fd);
}

pub const DnsResolver = struct {
    allocator: std.mem.Allocator,
    rs: RingShared,
    io: std.Io,
    udp_fd: i32,
    dns_ud: u64,
    nameserver_ip: u32,
    nameserver_port: u16,
    cache: DnsCache,
    pending: std.AutoHashMap(u16, PendingQuery),
    results: std.AutoHashMap(u16, QueryResult),
    next_txid: u16,
    recv_buf: [packet.MAX_PACKET_SIZE]u8,
    recv_outstanding: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        nameserver_ip: u32,
    ) !DnsResolver {
        const raw_fd = linux.socket(
            linux.AF.INET,
            linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
            0,
        );
        const fd = try udpSocketFd(raw_fd);

        var addr_any = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = 0,
            .addr = 0,
            .zero = [_]u8{0} ** 8,
        };
        if (linux.bind(fd, @ptrCast(&addr_any), @sizeOf(linux.sockaddr.in)) != 0) {
            _ = linux.close(fd);
            return error.BindFailed;
        }
        // 修改原因：bind 成功后如果后续初始化失败，必须关闭 UDP fd，避免初始化失败路径泄漏 socket。
        errdefer _ = linux.close(fd);

        return DnsResolver{
            .allocator = allocator,
            .rs = undefined,
            .io = io,
            .udp_fd = fd,
            .dns_ud = 0,
            .nameserver_ip = nameserver_ip,
            .nameserver_port = packet.DNS_PORT,
            .cache = DnsCache.init(allocator),
            .pending = std.AutoHashMap(u16, PendingQuery).init(allocator),
            .results = std.AutoHashMap(u16, QueryResult).init(allocator),
            .next_txid = 1,
            .recv_buf = [_]u8{0} ** packet.MAX_PACKET_SIZE,
            .recv_outstanding = false,
        };
    }

    /// Register this resolver with the shared IORegistry so its CQEs are
    /// dispatched back here. Must be called once, on the resolver's final
    /// address, with the owner's stable RingShared. Split from init() because
    /// init() returns the resolver by value (its address changes on the move),
    /// so registering inside init() would store a dangling pointer — the same
    /// bug fixed for UdpServer.
    pub fn register(self: *DnsResolver, rs: RingShared) !void {
        self.rs = rs;
        self.dns_ud = try self.rs.alloc(@ptrCast(self), &dnsDispatch);
    }

    /// Re-point ring/registry after the owner moved to its final address.
    /// Unlike register(), this does not re-allocate dns_ud nor assert the IO
    /// thread; it only refreshes the stored pointers. Call it from the owner's
    /// run()/init-on-final-address path after RingShared.rebind().
    pub fn rebind(self: *DnsResolver, rs: RingShared) void {
        self.rs = rs;
    }

    pub fn deinit(self: *DnsResolver) void {
        self.cache.deinit();
        self.pending.deinit();
        self.results.deinit();
        // dns_ud == 0 means register() was never called (init error path);
        // self.rs is undefined in that case, so skip the registry remove.
        if (self.dns_ud != 0) {
            self.rs.remove(self.dns_ud);
        }
        if (self.udp_fd >= 0) {
            _ = linux.close(self.udp_fd);
            self.udp_fd = -1;
        }
    }

    fn nowMs(self: *DnsResolver) i64 {
        const ts = std.Io.Timestamp.now(self.io, .real);
        return @as(i64, @intCast(@divTrunc(ts.nanoseconds, @as(i96, std.time.ns_per_ms))));
    }

    fn nextTxid(self: *DnsResolver) !u16 {
        var attempts: usize = 0;
        while (attempts < std.math.maxInt(u16)) : (attempts += 1) {
            const txid = self.next_txid;
            self.next_txid +%= 1;
            if (self.next_txid == 0) self.next_txid = 1;
            if (txid == 0) continue;
            // 修改原因：txid 仍在 pending 时不能复用，否则响应会覆盖旧查询并唤醒错误 fiber。
            if (!self.pending.contains(txid)) return txid;
        }
        return error.DnsTxidExhausted;
    }

    const NEGATIVE_TTL_SECS: u32 = 5;

    pub fn resolve(self: *DnsResolver, hostname: []const u8) !u32 {
        const now = self.nowMs();

        if (self.cache.get(hostname, now)) |cached| {
            if (cached.negative) return error.DomainNotFound;
            return cached.addrs[0];
        }

        const txid = try self.nextTxid();

        try self.sendQuery(hostname, txid);

        const pq = PendingQuery{
            .txid = txid,
            .hostname = hostname,
            .deadline_ms = now + DNS_TIMEOUT_MS,
            .retries = 0,
            .slot = undefined,
        };

        try self.pending.put(txid, pq);

        Fiber.dnsYield(&self.pending.getPtr(txid).?.slot);

        const result = self.results.fetchRemove(txid) orelse {
            self.cache.put(hostname, &.{}, NEGATIVE_TTL_SECS, self.nowMs(), true) catch {};
            return error.DnsTimeout;
        };

        if (result.value.len > 0) {
            try self.cache.put(hostname, result.value.addrs[0..result.value.len], result.value.ttl, self.nowMs(), false);
            return result.value.addrs[0];
        }
        self.cache.put(hostname, &.{}, NEGATIVE_TTL_SECS, self.nowMs(), true) catch {};
        return error.DomainNotFound;
    }

    fn sendQuery(self: *DnsResolver, hostname: []const u8, txid: u16) !void {
        const query = try packet.buildQuery(hostname, txid);
        const query_bytes = query.bytes();
        var addr = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = @byteSwap(self.nameserver_port),
            .addr = self.nameserver_ip,
            .zero = [_]u8{0} ** 8,
        };
        const send_rc = linux.sendto(self.udp_fd, query_bytes.ptr, query_bytes.len, 0, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
        // 修改原因：sendto 失败时不能挂起 fiber 等 DNS timeout；需要立即把 UDP 发送错误返回给调用方。
        if (linux.errno(send_rc) != .SUCCESS or send_rc != query_bytes.len) return error.DnsSendFailed;
        self.submitRecv();
    }

    fn submitRecv(self: *DnsResolver) void {
        if (self.recv_outstanding) return;
        const sqe = self.rs.ring.nop(self.dns_ud) catch return;
        sqe.opcode = @enumFromInt(28); // IORING_OP_RECV
        sqe.fd = self.udp_fd;
        sqe.addr = @intFromPtr(&self.recv_buf);
        sqe.len = self.recv_buf.len;
        sqe.off = 0;
        self.recv_outstanding = true;
        _ = self.rs.ring.submit() catch {};
    }

    pub fn handleCqe(self: *DnsResolver, res: i32) void {
        self.recv_outstanding = false;
        if (res <= 0) return;

        const n: usize = @intCast(res);
        if (n < 12) return;

        const txid = packet.parseTxid(self.recv_buf[0..n]);
        const parsed = packet.parseResponse(self.recv_buf[0..n]);

        const pending = self.pending.fetchRemove(txid) orelse {
            if (self.pending.count() > 0) self.submitRecv();
            return;
        };

        var result = QueryResult{
            .addrs = [_]u32{0} ** packet.AddrList.MAX_ADDRS,
            .len = parsed.addrs.len,
            .ttl = parsed.ttl,
        };
        if (parsed.rcode == .NOERROR and parsed.addrs.len > 0) {
            @memcpy(result.addrs[0..parsed.addrs.len], parsed.addrs.addrs[0..parsed.addrs.len]);
        }
        self.results.put(txid, result) catch {
            // Failed to store the result (OOM). The fiber will see
            // error.DnsTimeout and retry. Log so the operator knows
            // DNS is working but memory is tight.
            logWarn("DnsResolver: failed to store result for txid={d}, will retry", .{txid});
        };

        Fiber.dnsResume(&pending.value.slot);

        if (self.pending.count() > 0) self.submitRecv();
    }

    pub fn tick(self: *DnsResolver) void {
        const now = self.nowMs();
        self.cache.evictExpired(now);

        var timed_out = std.ArrayList(u16).empty;
        defer timed_out.deinit(self.allocator);

        var it = self.pending.iterator();
        while (it.next()) |entry| {
            if (now >= entry.value_ptr.deadline_ms) {
                timed_out.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (timed_out.items) |txid| {
            const pq = self.pending.getPtr(txid) orelse continue;
            if (pq.retries < MAX_RETRIES) {
                pq.retries += 1;
                pq.deadline_ms = now + DNS_TIMEOUT_MS;
                self.sendQuery(pq.hostname, pq.txid) catch {
                    const removed = self.pending.fetchRemove(txid) orelse continue;
                    Fiber.dnsResume(&removed.value.slot);
                };
            } else {
                const removed = self.pending.fetchRemove(txid) orelse continue;
                const empty_result = QueryResult{
                    .addrs = [_]u32{0} ** packet.AddrList.MAX_ADDRS,
                    .len = 0,
                    .ttl = 0,
                };
                self.results.put(txid, empty_result) catch {};
                Fiber.dnsResume(&removed.value.slot);
            }
        }
    }
};

fn testPendingQuery(txid: u16) PendingQuery {
    return .{
        .txid = txid,
        .hostname = "example.test",
        .deadline_ms = 0,
        .retries = 0,
        .slot = undefined,
    };
}

test "DnsResolver nextTxid skips zero and pending ids" {
    var resolver = DnsResolver{
        .allocator = std.testing.allocator,
        .rs = undefined,
        .io = undefined,
        .udp_fd = -1,
        .dns_ud = 0,
        .nameserver_ip = 0,
        .nameserver_port = packet.DNS_PORT,
        .cache = DnsCache.init(std.testing.allocator),
        .pending = std.AutoHashMap(u16, PendingQuery).init(std.testing.allocator),
        .results = std.AutoHashMap(u16, QueryResult).init(std.testing.allocator),
        .next_txid = 1,
        .recv_buf = [_]u8{0} ** packet.MAX_PACKET_SIZE,
        .recv_outstanding = false,
    };
    defer resolver.cache.deinit();
    defer resolver.pending.deinit();
    defer resolver.results.deinit();

    try resolver.pending.put(1, testPendingQuery(1));
    try std.testing.expectEqual(@as(u16, 2), try resolver.nextTxid());

    resolver.next_txid = 0;
    try std.testing.expectEqual(@as(u16, 2), try resolver.nextTxid());

    resolver.next_txid = std.math.maxInt(u16);
    try resolver.pending.put(std.math.maxInt(u16), testPendingQuery(std.math.maxInt(u16)));
    try std.testing.expectEqual(@as(u16, 2), try resolver.nextTxid());
}

test "DnsResolver sendQuery reports sendto failure" {
    var resolver = DnsResolver{
        .allocator = std.testing.allocator,
        .rs = undefined,
        .io = undefined,
        .udp_fd = -1,
        .dns_ud = 0,
        .nameserver_ip = 0,
        .nameserver_port = packet.DNS_PORT,
        .cache = DnsCache.init(std.testing.allocator),
        .pending = std.AutoHashMap(u16, PendingQuery).init(std.testing.allocator),
        .results = std.AutoHashMap(u16, QueryResult).init(std.testing.allocator),
        .next_txid = 1,
        .recv_buf = [_]u8{0} ** packet.MAX_PACKET_SIZE,
        .recv_outstanding = false,
    };
    defer resolver.cache.deinit();
    defer resolver.pending.deinit();
    defer resolver.results.deinit();

    try std.testing.expectError(error.DnsSendFailed, resolver.sendQuery("example.com", 0x1234));
    try std.testing.expect(!resolver.recv_outstanding);
}

test "DnsResolver socket fd conversion checks errno before casting" {
    const failed: usize = @bitCast(@as(isize, -1));
    try std.testing.expectError(error.UdpSocketFailed, udpSocketFd(failed));
    try std.testing.expectEqual(@as(i32, 4), try udpSocketFd(4));
}
