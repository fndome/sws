const std = @import("std");
const Allocator = std.mem.Allocator;

const RingSharedClient = @import("../shared/tcp_stream.zig").RingSharedClient;
const Pipe = @import("../next/pipe.zig").Pipe;

/// ── Outbound connection pool ──────────────────────────────────────────
///
/// Multiple concurrent connections per host:port are allowed (needed for K8s pod-to-pod communication).
/// getPipe() prefers lending an idle connection; when all are lent out it returns null so the caller opens a new one.
/// releasePipe() returns a connection to the pool. Idle connections are evicted automatically when their TTL expires.
///
/// Limit: MAX_CONNS_PER_HOST = 8
const MAX_CONNS_PER_HOST: usize = 12;

const PoolEntry = struct {
    host: []u8,
    port: u16,
    tls: bool,
    stream: *RingSharedClient,
    pipe: Pipe,
    last_used_ms: i64,
    borrowed: bool,
};

pub const TinyCache = struct {
    allocator: Allocator,
    ttl_ms: i64,
    entries: std.ArrayList(PoolEntry),

    pub fn init(allocator: Allocator, ttl_ms: i64) !TinyCache {
        return TinyCache{
            .allocator = allocator,
            .ttl_ms = ttl_ms,
            .entries = try std.ArrayList(PoolEntry).initCapacity(allocator, MAX_CONNS_PER_HOST),
        };
    }

    pub fn enabled(self: *const TinyCache) bool {
        return self.ttl_ms > 0;
    }

    pub fn deinit(self: *TinyCache) void {
        for (self.entries.items) |*e| {
            self.allocator.free(e.host);
            e.stream.deinit();
            e.pipe.deinit();
        }
        self.entries.deinit(self.allocator);
    }

    /// Lend an idle connection to host:port. Returns (stream, pipe) or null.
    pub fn acquire(self: *TinyCache, host: []const u8, port: u16, tls: bool, now_ms: i64) ?struct { stream: *RingSharedClient, pipe: *Pipe } {
        if (!self.enabled()) return null;
        for (self.entries.items) |*e| {
            if (e.borrowed) continue;
            if (e.port != port) continue;
            if (e.tls != tls) continue;
            // HTTP/DNS hostnames are case-insensitive, so pool reuse must also fold case to avoid reconnecting to the same upstream.
            if (!sameHost(e.host, host)) continue;
            if (now_ms - e.last_used_ms >= self.ttl_ms) continue;
            e.pipe.reset();
            e.last_used_ms = now_ms;
            e.borrowed = true;
            return .{ .stream = e.stream, .pipe = &e.pipe };
        }
        return null;
    }

    /// Return a lent-out connection.
    pub fn release(self: *TinyCache, p: *const Pipe, now_ms: i64) void {
        for (self.entries.items) |*e| {
            if (&e.pipe == p) {
                e.borrowed = false;
                e.last_used_ms = now_ms;
                return;
            }
        }
    }

    /// Store a new connection into the pool. Returns error.PoolFull when the pool is full.
    pub fn store(self: *TinyCache, stream: *RingSharedClient, p: Pipe, host: []const u8, port: u16, tls: bool, now_ms: i64) !void {
        if (!self.enabled()) {
            // On store failure the caller still owns stream/pipe; deinit'ing here would double-free with the caller's catch path.
            return error.CacheDisabled;
        }
        self.evictExpired(now_ms);
        if (self.countForHostPort(host, port, tls) >= MAX_CONNS_PER_HOST) {
            // The limit applies to the number of concurrent connections for the same host:port; other upstreams must not fill the global pool and cause a false PoolFull.
            return error.PoolFull;
        }
        const host_dup = self.allocator.dupe(u8, host) catch {
            return error.OutOfMemory;
        };
        errdefer self.allocator.free(host_dup);
        try self.entries.append(self.allocator, .{
            .host = host_dup,
            .port = port,
            .tls = tls,
            .stream = stream,
            .pipe = p,
            .last_used_ms = now_ms,
            .borrowed = false,
        });
    }

    /// Evict a single connection (used on write/read failure)
    pub fn evictPipe(self: *TinyCache, p: *const Pipe) void {
        for (self.entries.items, 0..) |*e, i| {
            if (&e.pipe == p) {
                self.allocator.free(e.host);
                e.stream.deinit();
                e.pipe.deinit();
                _ = self.entries.swapRemove(i);
                return;
            }
        }
    }

    pub fn pipeForStream(self: *TinyCache, stream: *RingSharedClient) ?*Pipe {
        // HTTP client replies must be looked up by connection, not via a threadlocal active_pipe.
        for (self.entries.items) |*e| {
            if (e.stream == stream) return &e.pipe;
        }
        return null;
    }

    pub fn evictStream(self: *TinyCache, stream: *RingSharedClient) void {
        // The connection-close callback only knows the stream, so it must reliably evict the matching cache entry and free the Pipe.
        for (self.entries.items, 0..) |*e, i| {
            if (e.stream == stream) {
                self.allocator.free(e.host);
                e.stream.deinit();
                e.pipe.deinit();
                _ = self.entries.swapRemove(i);
                return;
            }
        }
    }

    /// Called periodically by tick(): evicts expired connections that are not lent out
    pub fn tick(self: *TinyCache, now_ms: i64) void {
        if (!self.enabled()) return;
        self.evictExpired(now_ms);
    }

    fn evictExpired(self: *TinyCache, now_ms: i64) void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const e = &self.entries.items[i];
            if (!e.borrowed and now_ms - e.last_used_ms >= self.ttl_ms) {
                self.allocator.free(e.host);
                e.stream.deinit();
                e.pipe.deinit();
                _ = self.entries.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    fn countForHostPort(self: *const TinyCache, host: []const u8, port: u16, tls: bool) usize {
        var n: usize = 0;
        for (self.entries.items) |e| {
            if (e.port == port and e.tls == tls and sameHost(e.host, host)) n += 1;
        }
        return n;
    }

    pub fn count(self: *const TinyCache) usize {
        var n: usize = 0;
        for (self.entries.items) |e| {
            if (!e.borrowed) n += 1;
        }
        return n;
    }
};

fn sameHost(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn testPipe(stream: *RingSharedClient) Pipe {
    return .{
        .allocator = std.testing.allocator,
        .stream = stream,
        .read_buf = std.ArrayList(u8).empty,
        .write_buf = std.ArrayList(u8).empty,
        .max_read = 1,
    };
}

test "TinyCache.store keeps stream ownership with caller on PoolFull" {
    var cache = try TinyCache.init(std.testing.allocator, 1000);
    defer {
        for (cache.entries.items) |*e| {
            std.testing.allocator.free(e.host);
        }
        cache.entries.deinit(std.testing.allocator);
    }

    const fake_stream: *RingSharedClient = @ptrFromInt(0x1000);
    for (0..MAX_CONNS_PER_HOST) |_| {
        const host = try std.testing.allocator.dupe(u8, "same.test");
        try cache.entries.append(std.testing.allocator, .{
            .host = host,
            .port = 80,
            .tls = false,
            .stream = fake_stream,
            .pipe = testPipe(fake_stream),
            .last_used_ms = 0,
            .borrowed = false,
        });
    }

    try std.testing.expectError(error.PoolFull, cache.store(fake_stream, testPipe(fake_stream), "same.test", 80, false, 0));
}

test "TinyCache.store applies pool limit per host and port" {
    var cache = try TinyCache.init(std.testing.allocator, 1000);
    defer {
        for (cache.entries.items) |*e| {
            std.testing.allocator.free(e.host);
        }
        cache.entries.deinit(std.testing.allocator);
    }

    const fake_stream: *RingSharedClient = @ptrFromInt(0x1000);
    for (0..MAX_CONNS_PER_HOST) |i| {
        const host = try std.fmt.allocPrint(std.testing.allocator, "h{d}.test", .{i});
        try cache.entries.append(std.testing.allocator, .{
            .host = host,
            .port = 80,
            .tls = false,
            .stream = fake_stream,
            .pipe = testPipe(fake_stream),
            .last_used_ms = 0,
            .borrowed = false,
        });
    }

    try cache.store(fake_stream, testPipe(fake_stream), "extra.test", 80, false, 0);
    try std.testing.expectEqual(MAX_CONNS_PER_HOST + 1, cache.entries.items.len);
}

test "sameHost matches case-insensitively" {
    try std.testing.expect(sameHost("example.com", "Example.COM"));
    try std.testing.expect(sameHost("EXAMPLE.com", "example.com"));
    try std.testing.expect(!sameHost("example.com", "other.com"));
}
