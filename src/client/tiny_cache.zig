const std = @import("std");
const Allocator = std.mem.Allocator;

const RingSharedClient = @import("../shared/tcp_stream.zig").RingSharedClient;
const Pipe = @import("../next/pipe.zig").Pipe;

/// ── 出站连接池 ──────────────────────────────────────────
///
/// 同 host:port 允许多条并发连接 (K8s pod 间通信需要)。
/// getPipe() 优先借出空闲连接，全部借出时返回 null 让调用方新建。
/// releasePipe() 归还到池。TTL 过期自动淘汰空闲连接。
///
/// 上限: MAX_CONNS_PER_HOST = 8
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

    /// 借出一条空闲连接到 host:port。返回 (stream, pipe) 或 null。
    pub fn acquire(self: *TinyCache, host: []const u8, port: u16, tls: bool, now_ms: i64) ?struct { stream: *RingSharedClient, pipe: *Pipe } {
        if (!self.enabled()) return null;
        for (self.entries.items) |*e| {
            if (e.borrowed) continue;
            if (e.port != port) continue;
            if (e.tls != tls) continue;
            // 修改原因：HTTP/DNS 主机名大小写不敏感，连接池复用也必须折叠大小写，避免同一上游重复建连。
            if (!sameHost(e.host, host)) continue;
            if (now_ms - e.last_used_ms >= self.ttl_ms) continue;
            e.pipe.reset();
            e.last_used_ms = now_ms;
            e.borrowed = true;
            return .{ .stream = e.stream, .pipe = &e.pipe };
        }
        return null;
    }

    /// 归还借出的连接。
    pub fn release(self: *TinyCache, p: *const Pipe, now_ms: i64) void {
        for (self.entries.items) |*e| {
            if (&e.pipe == p) {
                e.borrowed = false;
                e.last_used_ms = now_ms;
                return;
            }
        }
    }

    /// 存入新连接到池。池满时返回 error.PoolFull。
    pub fn store(self: *TinyCache, stream: *RingSharedClient, p: Pipe, host: []const u8, port: u16, tls: bool, now_ms: i64) !void {
        if (!self.enabled()) {
            // 修改原因：store 失败时调用方仍负责释放 stream/pipe；这里提前 deinit 会和调用方 catch 路径 double-free。
            return error.CacheDisabled;
        }
        self.evictExpired(now_ms);
        if (self.countForHostPort(host, port, tls) >= MAX_CONNS_PER_HOST) {
            // 修改原因：上限语义是同一 host:port 的并发连接数，不能让其他上游占满全局池导致误报 PoolFull。
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

    /// 淘汰单条连接 (write/read 失败时用)
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
        // 修改原因：HTTP client 的回包必须按连接查找 Pipe，不能依赖 threadlocal active_pipe。
        for (self.entries.items) |*e| {
            if (e.stream == stream) return &e.pipe;
        }
        return null;
    }

    pub fn evictStream(self: *TinyCache, stream: *RingSharedClient) void {
        // 修改原因：连接关闭回调只知道 stream，需能稳定淘汰对应缓存项并释放 Pipe。
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

    /// tick() 周期调用：淘汰过期且未借出的连接
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

test "TinyCache.acquire matches host case-insensitively" {
    var cache = try TinyCache.init(std.testing.allocator, 1000);
    defer {
        for (cache.entries.items) |*e| {
            std.testing.allocator.free(e.host);
        }
        cache.entries.deinit(std.testing.allocator);
    }

    const fake_stream: *RingSharedClient = @ptrFromInt(0x1000);
    const host = try std.testing.allocator.dupe(u8, "Example.COM");
    try cache.entries.append(std.testing.allocator, .{
        .host = host,
        .port = 80,
        .tls = false,
        .stream = fake_stream,
        .pipe = testPipe(fake_stream),
        .last_used_ms = 0,
        .borrowed = false,
    });

    const borrowed = cache.acquire("example.com", 80, false, 1) orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expectEqual(fake_stream, borrowed.stream);
    try std.testing.expect(cache.entries.items[0].borrowed);
}
