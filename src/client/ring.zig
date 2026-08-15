const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const IORegistry = @import("../shared/io_registry.zig").IORegistry;
const RingShared = @import("../shared/ring_shared.zig").RingShared;
const InvokeQueue = @import("../shared/io_invoke.zig").InvokeQueue;
const DnsResolver = @import("../dns/resolver.zig").DnsResolver;
const CLIENT_USER_DATA_FLAG = @import("../shared/io_registry.zig").CLIENT_USER_DATA_FLAG;
const TinyCache = @import("tiny_cache.zig").TinyCache;
const helpers = @import("../http/http_helpers.zig");

const MAX_CQES_TICK = 64;

/// ── Ring B ────────────────────────────────────────────────
///
/// 出站 HTTP 客户端 IO 归口。
/// 持有 ring + RingShared + IORegistry + DnsResolver + InvokeQueue + TinyCache。
///
/// 调用方应自行驱动 RingB.tick()（可在独立线程中轮询）。
///
/// TinyCache 内建在 RingB 中，由 RingB.tick() 每轮自动淘汰过期连接，
/// 用户无需手动管理缓存生命周期。
///
/// 用法：
///   const ring_b = try RingB.init(alloc, io, server.ring.fd, 1000);
///   defer ring_b.deinit();
///   try ring_b.registerWith(&fiber_shared);
///   const client = try HttpClient.init(alloc, &ring_b);
pub const RingB = struct {
    allocator: Allocator,
    ring: linux.IoUring,
    registry: IORegistry,
    rs: RingShared,
    dns: *DnsResolver,
    invoke: InvokeQueue,
    /// 内建出站连接缓存：同 host:port 在 TTL 内复用 TCP 连接。
    /// RingB.tick() 自动淘汰过期条目，用户无需干预。
    http_cache: TinyCache,
    /// 同 (host, port) 并发建连计数，防止死目标扇出耗尽 SQE ring。
    /// 键格式: "host:port"，值为当前正在建连的 fiber 数量。
    connecting: std.StringHashMap(u32),
    /// 单目标最大并发建连数
    pub const MAX_CONCURRENT_CONNECTS: u32 = 4;

    pub fn init(allocator: Allocator, io: std.Io, attach_ring_fd: i32, cache_ttl_ms: i64) !RingB {
        const ns_ip = helpers.readResolvConfNameserver() catch @as(u32, 0x08080808);

        var ring = brk: {
            var params = std.mem.zeroes(linux.io_uring_params);
            // 修改原因：RingB 可能由主流程创建后交给 IO tick 驱动，SINGLE_ISSUER 会要求创建/提交同线程。
            params.flags = linux.IORING_SETUP_DEFER_TASKRUN |
                linux.IORING_SETUP_ATTACH_WQ;
            params.wq_fd = @intCast(attach_ring_fd);
            break :brk try linux.IoUring.init_params(256, &params);
        };
        errdefer ring.deinit();

        var registry = IORegistry.init(allocator);
        errdefer registry.deinit();

        const dns = try allocator.create(DnsResolver);
        errdefer allocator.destroy(dns);
        dns.* = try DnsResolver.init(allocator, io, ns_ip);
        errdefer dns.deinit();

        const http_cache = try TinyCache.init(allocator, cache_ttl_ms);

        var ring_b = RingB{
            .allocator = allocator,
            .ring = ring,
            .registry = registry,
            .rs = undefined,
            .dns = dns,
            .invoke = .{},
            .http_cache = http_cache,
            .connecting = std.StringHashMap(u32).init(allocator),
        };
        // Bind rs to RingB's own fields (not the moved-in locals) and register
        // the DNS resolver on its final heap address with that stable rs.
        ring_b.rs = RingShared.bind(&ring_b.ring, &ring_b.registry);
        try ring_b.dns.register(ring_b.rs);
        return ring_b;
    }

    pub fn deinit(self: *RingB) void {
        self.http_cache.deinit();
        {
            var it = self.connecting.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
            }
        }
        self.connecting.deinit();
        self.invoke.drain(self.allocator);
        self.dns.deinit();
        self.allocator.destroy(self.dns);
        self.registry.deinit();
        self.ring.deinit();
    }

    /// 非阻塞收割 Ring B 的 CQE + 淘汰过期缓存连接。
    pub fn tick(self: *RingB) void {
        if (self.http_cache.enabled()) {
            self.http_cache.tick(nowMs());
        }
        self.dns.tick();
        self.invoke.drain(self.allocator);
        _ = self.ring.submit() catch |err| helpers.logErr("RingB: submit failed: {s}", .{@errorName(err)});

        var cqes: [MAX_CQES_TICK]linux.io_uring_cqe = undefined;
        const n = self.ring.copy_cqes(&cqes, 0) catch return;
        // 修改原因：copy_cqes 会自动推进 CQ head，不能再对复制出来的 CQE 调 cqe_seen。
        for (cqes[0..n]) |*cqe| {
            const ud = cqe.user_data;
            if ((ud & CLIENT_USER_DATA_FLAG) != 0) {
                self.registry.dispatch(ud, cqe.res);
            }
        }
    }

    pub fn tryIncConnecting(self: *RingB, host: []const u8, port: u16) !void {
        const key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ host, port });
        const entry = try self.connecting.getOrPut(key);
        if (!entry.found_existing) {
            // First entry for this target — key string is now owned by the map.
            entry.value_ptr.* = 1;
        } else {
            // Key already exists in the map; free our temporary lookup copy.
            self.allocator.free(key);
            if (entry.value_ptr.* >= MAX_CONCURRENT_CONNECTS) {
                return error.TargetConnectLimitReached;
            }
            entry.value_ptr.* += 1;
        }
    }

    pub fn decConnecting(self: *RingB, host: []const u8, port: u16) void {
        const key = std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ host, port }) catch return;
        defer self.allocator.free(key);
        if (self.connecting.getPtr(key)) |v| {
            if (v.* > 1) {
                v.* -= 1;
            } else {
                // Remove and free the key owned by the map.
                if (self.connecting.fetchRemove(key)) |kv| {
                    self.allocator.free(kv.key);
                }
            }
        }
    }
};

/// 保留向下兼容别名
pub const HttpRing = RingB;

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(ts.nsec, std.time.ns_per_ms);
}
