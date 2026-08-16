// router_hash.zig — Router-side consistent hash routing
//
// Identical to the pod_hash.zig algorithm: FNV-1a + 150 vnodes + binary search
//
// Router use case: determine the target NodePort when a client connects
//   hash(uid) → target ordinal → external "wss://DOMAIN:{NODEPORT_BASE+N}/ws"
//   → client receives redirect → connects directly to the NodePort
//
// Usage:
//   var ring = HashRing.init(alloc, 0);
//   try ring.addNode(0); try ring.addNode(1); try ring.addNode(2);
//   // when a client connects
//   const addr = ring.routeToAddr(uid, domain, nodeport_base, &url_buf);
//   // → ordinal=0, url="wss://ws.example.com:30001/ws"

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const HashRing = struct {
    const Self = @This();
    const VNODES_PER_NODE: u16 = 150;

    allocator: Allocator,
    vnodes: std.ArrayList(VNode),
    nodes: std.ArrayList(u8),

    const VNode = struct {
        hash: u32,
        node_id: u8,

        fn lessThan(_: void, a: VNode, b: VNode) bool {
            return a.hash < b.hash;
        }
    };

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .vnodes = std.ArrayList(VNode).empty.toManaged(allocator),
            .nodes = std.ArrayList(u8).empty.toManaged(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.vnodes.deinit();
        self.nodes.deinit();
    }

    pub fn addNode(self: *Self, node_id: u8) !void {
        var vi: u16 = 0;
        while (vi < VNODES_PER_NODE) : (vi += 1) {
            const seed = vnodeSeed(node_id, vi);
            const h = hash32(seed[0..seed.len]);
            try self.vnodes.append(.{ .hash = h, .node_id = node_id });
        }
        try self.nodes.append(node_id);
        sortRing(self.vnodes.items);
    }

    pub fn removeNode(self: *Self, node_id: u8) void {
        var i: usize = 0;
        while (i < self.vnodes.items.len) {
            if (self.vnodes.items[i].node_id == node_id) {
                _ = self.vnodes.swapRemove(i);
            } else {
                i += 1;
            }
        }
        for (self.nodes.items, 0..) |n, j| {
            if (n == node_id) {
                _ = self.nodes.swapRemove(j);
                break;
            }
        }
        sortRing(self.vnodes.items);
    }

    /// Route: hash(user_id) → target node ordinal
    pub fn route(self: *const Self, user_id: u64) ?u8 {
        if (self.vnodes.items.len == 0) return null;
        const h = hash64(user_id);
        const h32: u32 = @truncate(h);
        const pos = binarySearch(self.vnodes.items, h32);
        return self.vnodes.items[pos].node_id;
    }

    /// ── Router-specific: hash → ordinal + external IP:PORT ─────
    ///
    /// domain example: "ws.example.com"
    /// nodeport_base example: 30001
    /// Returns the target ordinal and the assembled redirect URL
    /// Caller: w.Write(redirect_json) → client connects directly once received
    pub fn routeToAddr(
        self: *const Self,
        user_id: u64,
        domain: []const u8,
        nodeport_base: u16,
        url_buf: []u8,
    ) ?AddrTarget {
        const target = self.route(user_id) orelse return null;
        const port = nodeport_base + @as(u16, target);
        const url = std.fmt.bufPrint(url_buf, "wss://{s}:{d}/ws", .{ domain, port }) catch return null;
        return AddrTarget{ .ordinal = target, .url = url };
    }

    pub const AddrTarget = struct {
        ordinal: u8,
        url: []const u8,
    };
};

fn vnodeSeed(node_id: u8, vi: u16) []u8 {
    const s = std.fmt.bufPrint(&seed_buf, "{d}-{d}", .{ node_id, vi }) catch unreachable;
    return seed_buf[0..s.len];
}

var seed_buf: [64]u8 = undefined;

fn binarySearch(vnodes: []const HashRing.VNode, key_hash: u32) usize {
    if (vnodes.len == 0) return 0;
    if (key_hash > vnodes[vnodes.len - 1].hash) return 0;
    var lo: usize = 0;
    var hi: usize = vnodes.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (vnodes[mid].hash < key_hash) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

fn sortRing(vnodes: []HashRing.VNode) void {
    std.sort.insertion(HashRing.VNode, vnodes, {}, HashRing.VNode.lessThan);
}

fn hash32(data: []const u8) u32 {
    var h: u32 = 0x811c9dc5;
    for (data) |c| {
        h ^= @as(u32, c);
        h *%= 0x01000193;
    }
    return h;
}

fn hash64(v: u64) u64 {
    var h: u64 = 0xcbf29ce484222325;
    var x = v;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        h ^= @as(u8, @truncate(x));
        h *%= 0x100000001b3;
        x >>= 8;
    }
    return h;
}

// ── Tests ──────────────────────────────────────────────────────

test "router: route to addr" {
    const alloc = std.testing.allocator;
    var ring = HashRing.init(alloc);
    defer ring.deinit();

    try ring.addNode(0);
    try ring.addNode(1);
    try ring.addNode(2);

    var url_buf: [128]u8 = undefined;
    const result = ring.routeToAddr(12345, "ws.example.com", 30001, &url_buf).?;
    try std.testing.expect(result.ordinal < 3);
    try std.testing.expect(std.mem.startsWith(u8, result.url, "wss://ws.example.com:3000"));
}

test "router: same uid → same ordinal" {
    const alloc = std.testing.allocator;
    var ring = HashRing.init(alloc);
    defer ring.deinit();

    try ring.addNode(0);
    try ring.addNode(1);
    try ring.addNode(2);

    try std.testing.expectEqual(ring.route(42), ring.route(42));
}

test "router: 3→4 migration ~25%" {
    const alloc = std.testing.allocator;

    var ring3 = HashRing.init(alloc);
    defer ring3.deinit();
    try ring3.addNode(0);
    try ring3.addNode(1);
    try ring3.addNode(2);

    var ring4 = HashRing.init(alloc);
    defer ring4.deinit();
    try ring4.addNode(0);
    try ring4.addNode(1);
    try ring4.addNode(2);
    try ring4.addNode(3);

    var changed: usize = 0;
    const samples: usize = 10000;
    for (0..samples) |uid| {
        if (ring3.route(@intCast(uid)) != ring4.route(@intCast(uid))) {
            changed += 1;
        }
    }
    const pct = @as(f64, @floatFromInt(changed)) / @as(f64, @floatFromInt(samples)) * 100.0;
    try std.testing.expect(pct >= 15.0);
    try std.testing.expect(pct <= 35.0);
}
