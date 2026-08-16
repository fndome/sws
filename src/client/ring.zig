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
/// Central IO entry point for the outbound HTTP client.
/// Owns ring + RingShared + IORegistry + DnsResolver + InvokeQueue + TinyCache.
///
/// The caller should drive RingB.tick() itself (it may be polled on a separate thread).
///
/// TinyCache is built into RingB and its expired connections are evicted automatically by RingB.tick() each round,
/// so the user never needs to manage the cache lifetime manually.
///
/// Usage:
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
    /// Built-in outbound connection cache: reuses TCP connections for the same host:port within the TTL.
    /// RingB.tick() evicts expired entries automatically; the user needs no intervention.
    http_cache: TinyCache,
    /// Concurrent connect count per (host, port), to prevent dead-target fan-out from exhausting the SQE ring.
    /// Key format: "host:port", value is the number of fibers currently connecting.
    connecting: std.StringHashMap(u32),
    /// Maximum concurrent connects per target
    pub const MAX_CONCURRENT_CONNECTS: u32 = 4;

    pub fn init(allocator: Allocator, io: std.Io, attach_ring_fd: i32, cache_ttl_ms: i64) !RingB {
        const ns_ip = helpers.readResolvConfNameserver() catch @as(u32, 0x08080808);

        var ring = brk: {
            var params = std.mem.zeroes(linux.io_uring_params);
            // RingB may be created by the main flow and then driven by the IO tick, but SINGLE_ISSUER requires create/submit on the same thread.
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

    /// Non-blockingly harvests Ring B CQEs and evicts expired cache connections.
    pub fn tick(self: *RingB) void {
        if (self.http_cache.enabled()) {
            self.http_cache.tick(nowMs());
        }
        self.dns.tick();
        self.invoke.drain(self.allocator);
        _ = self.ring.submit() catch |err| helpers.logErr("RingB: submit failed: {s}", .{@errorName(err)});

        var cqes: [MAX_CQES_TICK]linux.io_uring_cqe = undefined;
        const n = self.ring.copy_cqes(&cqes, 0) catch return;
        // copy_cqes advances the CQ head automatically, so the copied CQEs must not be passed to cqe_seen.
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

/// Kept as a backward-compatible alias
pub const HttpRing = RingB;

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(ts.nsec, std.time.ns_per_ms);
}
