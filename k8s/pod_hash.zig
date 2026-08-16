// pod_hash.zig — Pod-side consistent hash routing
//
// Identical to the im-router (Go) algorithm: FNV-1a + 150 vnodes + binary search
//
// Pod use case: determine the target Pod when forwarding messages
//   hash(uid) → target ordinal → K8s DNS "im-ws-{N}.im-ws-headless"
//   → getaddrinfo(DNS) → Pod IP → TCP connect
//
// Usage:
//   var ring = HashRing.init(alloc, pod_ordinal);
//   try ring.addNode(0); try ring.addNode(1); try ring.addNode(2);
//   // message forwarding
//   const target = ring.routeToPod(to_uid, dns_fmt, &dns_buf);
//   // → ordinal=1, dns="im-ws-1.im-ws-headless"

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const HashRing = struct {
    const Self = @This();
    const VNODES_PER_NODE: u16 = 150;

    allocator: Allocator,
    local_ordinal: u8,
    vnodes: std.ArrayList(VNode),
    nodes: std.ArrayList(u8),

    const VNode = struct {
        hash: u32,
        node_id: u8,

        fn lessThan(_: void, a: VNode, b: VNode) bool {
            return a.hash < b.hash;
        }
    };

    pub fn init(allocator: Allocator, local_ordinal: u8) Self {
        return .{
            .allocator = allocator,
            .local_ordinal = local_ordinal,
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

    /// Whether the route lands on this Pod
    pub fn isLocal(self: *const Self, user_id: u64) bool {
        if (self.route(user_id)) |n| return n == self.local_ordinal;
        return false;
    }

    /// ── Pod-specific: hash → ordinal + K8s DNS ────────────────
    ///
    /// dns_fmt example: "im-ws-{d}.im-ws-headless"
    /// Returns the target ordinal and the assembled DNS name
    /// Caller: resolve DNS → getaddrinfo → Pod IP → connect
    pub fn routeToPod(
        self: *const Self,
        user_id: u64,
        dns_fmt: []const u8,
        dns_buf: []u8,
    ) ?PodTarget {
        const target = self.route(user_id) orelse return null;
        const dns = std.fmt.bufPrint(dns_buf, dns_fmt, .{target}) catch return null;
        return PodTarget{ .ordinal = target, .dns = dns };
    }

    pub const PodTarget = struct {
        ordinal: u8,
        dns: []const u8,
    };
};

/// K8s DNS name such as "im-ws-1.im-ws-headless"
/// Once the Pod gets it: std.c.getaddrinfo(dns, null, ...) → sockaddr.in → linux.connect()

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

test "pod: route to DNS" {
    const alloc = std.testing.allocator;
    var ring = HashRing.init(alloc, 0);
    defer ring.deinit();

    try ring.addNode(0);
    try ring.addNode(1);
    try ring.addNode(2);

    var dns_buf: [64]u8 = undefined;
    const result = ring.routeToPod(12345, "im-ws-{d}.im-ws-headless", &dns_buf).?;
    try std.testing.expect(result.ordinal < 3);
    try std.testing.expect(std.mem.startsWith(u8, result.dns, "im-ws-"));
}

test "pod: same uid → same pod across rings" {
    const alloc = std.testing.allocator;
    var ring_a = HashRing.init(alloc, 0);
    defer ring_a.deinit();
    try ring_a.addNode(0);
    try ring_a.addNode(1);
    try ring_a.addNode(2);

    var ring_b = HashRing.init(alloc, 1);
    defer ring_b.deinit();
    try ring_b.addNode(0);
    try ring_b.addNode(1);
    try ring_b.addNode(2);

    try std.testing.expectEqual(ring_a.route(42), ring_b.route(42));
}
