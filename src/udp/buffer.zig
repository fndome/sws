const std = @import("std");
const Allocator = std.mem.Allocator;
const MAX_UDP_PAYLOAD = @import("../constants.zig").UDP_RECV_BUF_SIZE;

pub const UdpBufferPool = struct {
    slab: []u8,
    freelist: []u16,
    freelist_top: u16,
    block_count: u16,

    pub fn init(allocator: Allocator, count: u16) !UdpBufferPool {
        const slab = try allocator.alloc(u8, @as(usize, count) * MAX_UDP_PAYLOAD);
        errdefer allocator.free(slab);
        const freelist = try allocator.alloc(u16, count);
        errdefer allocator.free(freelist);

        for (freelist, 0..) |*f, i| {
            f.* = @intCast(i);
        }

        return UdpBufferPool{
            .slab = slab,
            .freelist = freelist,
            .freelist_top = count,
            .block_count = count,
        };
    }

    pub fn deinit(self: *UdpBufferPool, allocator: Allocator) void {
        allocator.free(self.slab);
        allocator.free(self.freelist);
    }

    pub fn acquire(self: *UdpBufferPool) ?struct { idx: u16, buf: []u8 } {
        if (self.freelist_top == 0) return null;
        self.freelist_top -= 1;
        const idx = self.freelist[self.freelist_top];
        const off = @as(usize, idx) * MAX_UDP_PAYLOAD;
        return .{ .idx = idx, .buf = self.slab[off .. off + MAX_UDP_PAYLOAD] };
    }

    pub fn release(self: *UdpBufferPool, idx: u16) void {
        if (idx >= self.block_count) return;
        self.freelist[self.freelist_top] = idx;
        self.freelist_top += 1;
    }

    pub fn bufSlice(self: *UdpBufferPool, idx: u16) []u8 {
        const off = @as(usize, idx) * MAX_UDP_PAYLOAD;
        return self.slab[off .. off + MAX_UDP_PAYLOAD];
    }
};

test "UdpBufferPool acquire/release" {
    const allocator = std.testing.allocator;
    var pool = try UdpBufferPool.init(allocator, 4);
    defer pool.deinit(allocator);

    const a = pool.acquire().?;
    const b = pool.acquire().?;
    try std.testing.expect(a.idx != b.idx);

    pool.release(a.idx);
    const c = pool.acquire().?;
    try std.testing.expectEqual(a.idx, c.idx);
}

test "UdpBufferPool exhaust" {
    const allocator = std.testing.allocator;
    var pool = try UdpBufferPool.init(allocator, 1);
    defer pool.deinit(allocator);

    _ = pool.acquire().?;
    try std.testing.expect(pool.acquire() == null);
}
