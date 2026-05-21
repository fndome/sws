const std = @import("std");
const Allocator = std.mem.Allocator;

pub const DEFAULT_TTL_SECS: u32 = 60;
pub const MIN_TTL_SECS: u32 = 5;
pub const MAX_TTL_SECS: u32 = 300;
pub const MAX_ENTRIES: usize = 256;

const CacheEntry = struct {
    key_hash: u64,
    name: []const u8,
    addrs: [MAX_IP]u32,
    addr_count: u8,
    expires_at_ms: i64,
    negative: bool,
};

const MAX_IP: usize = 8;

pub const DnsCache = struct {
    allocator: Allocator,
    entries: std.ArrayList(CacheEntry),
    last_evict_ms: i64,
    pub const EVICT_INTERVAL_MS: i64 = 30_000;

    pub fn init(allocator: Allocator) DnsCache {
        return .{
            .allocator = allocator,
            .entries = std.ArrayList(CacheEntry).empty,
            .last_evict_ms = 0,
        };
    }

    pub fn deinit(self: *DnsCache) void {
        for (self.entries.items) |*entry| {
            self.allocator.free(entry.name);
        }
        self.entries.deinit(self.allocator);
    }

    pub fn get(self: *DnsCache, name: []const u8, now_ms: i64) ?struct { addrs: []const u32, ttl: u32, negative: bool } {
        const hash = hashName(name);
        for (self.entries.items) |*entry| {
            if (entry.key_hash == hash and namesEqual(entry.name, name)) {
                if (entry.expires_at_ms <= now_ms) return null;
                return .{
                    .addrs = entry.addrs[0..entry.addr_count],
                    .ttl = @intCast(@max(entry.expires_at_ms - now_ms, 1000) / 1000),
                    .negative = entry.negative,
                };
            }
        }
        return null;
    }

    pub fn put(self: *DnsCache, name: []const u8, addrs: []const u32, ttl_secs: u32, now_ms: i64, negative: bool) !void {
        const hash = hashName(name);
        const ttl = @max(ttl_secs, MIN_TTL_SECS);
        const capped_ttl = @min(ttl, MAX_TTL_SECS);
        const expires = now_ms + @as(i64, @intCast(capped_ttl)) * 1000;

        for (self.entries.items) |*entry| {
            if (entry.key_hash == hash and namesEqual(entry.name, name)) {
                const name_dup = try self.allocator.dupe(u8, name);
                // 修改原因：更新已有缓存项时必须先分配新 name，成功后再释放旧 name；
                // 旧逻辑先 free 再 dupe，OOM 会把 entry.name 留成悬空指针。
                self.allocator.free(entry.name);
                entry.name = name_dup;
                entry.expires_at_ms = expires;
                entry.negative = negative;
                entry.addr_count = @intCast(@min(addrs.len, MAX_IP));
                @memcpy(entry.addrs[0..entry.addr_count], addrs[0..entry.addr_count]);
                return;
            }
        }

        if (self.entries.items.len >= MAX_ENTRIES) {
            self.evictOne(now_ms);
        }

        const name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_dup);

        var entry = CacheEntry{
            .key_hash = hash,
            .name = name_dup,
            .addrs = [_]u32{0} ** MAX_IP,
            .addr_count = @intCast(@min(addrs.len, MAX_IP)),
            .expires_at_ms = expires,
            .negative = negative,
        };
        @memcpy(entry.addrs[0..entry.addr_count], addrs[0..entry.addr_count]);
        try self.entries.append(self.allocator, entry);
    }

    fn evictOne(self: *DnsCache, now_ms: i64) void {
        var best_idx: ?usize = null;
        var best_ts: i64 = std.math.maxInt(i64);

        for (self.entries.items, 0..) |*entry, i| {
            if (entry.expires_at_ms <= now_ms) {
                self.allocator.free(entry.name);
                _ = self.entries.swapRemove(i);
                return;
            }
            if (entry.expires_at_ms < best_ts) {
                best_ts = entry.expires_at_ms;
                best_idx = i;
            }
        }

        if (best_idx) |idx| {
            self.allocator.free(self.entries.items[idx].name);
            _ = self.entries.swapRemove(idx);
        }
    }

    pub fn evictExpired(self: *DnsCache, now_ms: i64) void {
        if (now_ms - self.last_evict_ms < EVICT_INTERVAL_MS) return;
        self.last_evict_ms = now_ms;

        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].expires_at_ms <= now_ms) {
                self.allocator.free(self.entries.items[i].name);
                _ = self.entries.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }
};

fn namesEqual(a: []const u8, b: []const u8) bool {
    // 修改原因：DNS 名称大小写不敏感，且末尾点只表示 root 终止；比较逻辑必须和查询编码保持一致。
    return std.ascii.eqlIgnoreCase(canonicalName(a), canonicalName(b));
}

fn canonicalName(name: []const u8) []const u8 {
    return if (name.len > 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
}

fn hashName(name: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    // 修改原因：example.com. 和 example.com 会编码成同一个 DNS qname，缓存 key 也要折叠末尾 root 点。
    for (canonicalName(name)) |c| {
        h ^= @as(u64, @intCast(std.ascii.toLower(c)));
        h *%= 0x100000001b3;
    }
    return h;
}

test "DnsCache replaces existing entry after allocating replacement name" {
    var cache = DnsCache.init(std.testing.allocator);
    defer cache.deinit();

    const first = [_]u32{0x01020304};
    const second = [_]u32{0x05060708};

    try cache.put("example.com", first[0..], 30, 0, false);
    try cache.put("example.com", second[0..], 30, 1000, false);

    const cached = cache.get("example.com", 1000).?;
    try std.testing.expectEqual(@as(usize, 1), cached.addrs.len);
    try std.testing.expectEqual(second[0], cached.addrs[0]);
}

test "DnsCache matches names case-insensitively" {
    var cache = DnsCache.init(std.testing.allocator);
    defer cache.deinit();

    const first = [_]u32{0x01020304};
    const second = [_]u32{0x05060708};

    try cache.put("Example.COM", first[0..], 30, 0, false);
    const cached = cache.get("example.com", 1000).?;
    try std.testing.expectEqual(first[0], cached.addrs[0]);

    try cache.put("example.com", second[0..], 30, 2000, false);
    try std.testing.expectEqual(@as(usize, 1), cache.entries.items.len);
    const updated = cache.get("EXAMPLE.COM", 2000).?;
    try std.testing.expectEqual(second[0], updated.addrs[0]);
}

test "DnsCache folds trailing root dot" {
    var cache = DnsCache.init(std.testing.allocator);
    defer cache.deinit();

    const first = [_]u32{0x01020304};
    const second = [_]u32{0x05060708};

    try cache.put("example.com.", first[0..], 30, 0, false);
    const cached = cache.get("example.com", 1000).?;
    try std.testing.expectEqual(first[0], cached.addrs[0]);

    try cache.put("EXAMPLE.COM", second[0..], 30, 2000, false);
    try std.testing.expectEqual(@as(usize, 1), cache.entries.items.len);
    const updated = cache.get("example.com.", 2000).?;
    try std.testing.expectEqual(second[0], updated.addrs[0]);
}
