const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const logErr = @import("async_logger.zig").logErr;
const logWarn = @import("async_logger.zig").logWarn;
const BUFFER_SIZE = @import("constants.zig").BUFFER_SIZE;
const READ_BUF_GROUP_ID = @import("constants.zig").READ_BUF_GROUP_ID;
const TIER_SIZES = @import("constants.zig").TIER_SIZES;
const TIER_COUNT = @import("constants.zig").TIER_COUNT;

pub const BufferPool = struct {
    allocator: Allocator,
    /// Single contiguous slab for io_uring provided read buffers
    slab: []u8,
    /// Number of BUFFER_SIZE blocks in the slab (all for io_uring)
    block_count: usize,

    /// Pending replenish queue for io_uring provided buffers
    replenish_queue: std.ArrayList(u16),

    /// Tiered write buffer freelists (recycled per size-class)
    tier_freelists: [TIER_COUNT]std.ArrayList([]u8),

    pub fn init(allocator: Allocator, block_count: usize) !BufferPool {
        const slab = try allocator.alloc(u8, block_count * BUFFER_SIZE);
        errdefer allocator.free(slab);

        // Defensive: markReplenish runs on the read-completion hot path, so a read buffer must not be lost to a queue-growth OOM the first time a bid is returned.
        // Double capacity to absorb duplicate-bid edge cases before each flush cycle.
        var replenish_queue = try std.ArrayList(u16).initCapacity(allocator, block_count * 2);
        errdefer replenish_queue.deinit(allocator);

        var self = BufferPool{
            .allocator = allocator,
            .slab = slab,
            .block_count = block_count,
            .replenish_queue = replenish_queue,
            .tier_freelists = undefined,
        };
        for (0..TIER_COUNT) |i| {
            self.tier_freelists[i] = std.ArrayList([]u8).empty;
        }
        return self;
    }

    pub fn deinit(self: *BufferPool) void {
        self.replenish_queue.deinit(self.allocator);
        for (0..TIER_COUNT) |i| {
            var fl = &self.tier_freelists[i];
            for (fl.items) |buf| self.allocator.free(buf);
            fl.deinit(self.allocator);
        }
        self.allocator.free(self.slab);
    }

    /// Register all slab blocks as io_uring provided buffers for zero-copy reads.
    pub fn provideAllReads(self: *BufferPool, ring: *linux.IoUring) !void {
        _ = try ring.provide_buffers(
            0,
            self.slab.ptr,
            BUFFER_SIZE,
            self.block_count,
            READ_BUF_GROUP_ID,
            0,
        );
    }

    /// Get a read buffer slice by bid (buffer ID from io_uring CQE).
    pub fn getReadBuf(self: *BufferPool, bid: u16) []u8 {
        std.debug.assert(bid < self.block_count);
        const i = @as(usize, bid);
        return self.slab[i * BUFFER_SIZE .. (i + 1) * BUFFER_SIZE];
    }

    /// Queue a bid for replenish back to io_uring.
    /// Skips duplicate bids already in the queue to prevent silent pool shrink
    /// when the append-OOM path is hit.
    pub fn markReplenish(self: *BufferPool, bid: u16) void {
        if (bid >= self.block_count) return;
        for (self.replenish_queue.items) |queued| {
            if (queued == bid) return;
        }
        self.replenish_queue.append(self.allocator, bid) catch |err| {
            logErr("markReplenish: failed to append bid={d}: {s}", .{ bid, @errorName(err) });
        };
    }

    /// Flush replenish queue to io_uring (re-register buffers with kernel).
    /// On partial failure, keeps remaining bids in queue for next attempt.
    pub fn flushReplenish(self: *BufferPool, ring: *linux.IoUring) !void {
        var i: usize = 0;
        while (i < self.replenish_queue.items.len) {
            const bid = self.replenish_queue.items[i];
            const ptr = self.slab.ptr + @as(usize, bid) * BUFFER_SIZE;
            _ = ring.provide_buffers(0, ptr, BUFFER_SIZE, 1, READ_BUF_GROUP_ID, bid) catch |err| {
                // Ring full — trim processed items, keep remaining for next flush
                logWarn("flushReplenish: provide_buffers failed at bid={d}: {s}, {d} remaining", .{ bid, @errorName(err), self.replenish_queue.items.len - i });
                // Shift remaining items to front
                const remaining = self.replenish_queue.items[i..];
                std.mem.copyForwards(u16, self.replenish_queue.items[0..remaining.len], remaining);
                self.replenish_queue.items.len = remaining.len;
                return err;
            };
            i += 1;
        }
        self.replenish_queue.clearRetainingCapacity();
    }

    // ── Tiered Write Buffer Pool (like greatws bytespool) ──────────

    /// Find which tier fits `needed` bytes (smallest >= needed).
    fn tierFor(needed: usize) usize {
        for (TIER_SIZES, 0..) |sz, i| {
            if (sz >= needed) return i;
        }
        return TIER_COUNT - 1;
    }

    /// Allocate a write buffer from the tiered pool, sized to fit at least `needed` bytes.
    /// Returns (buffer slice, tier_index). Returns null if needed exceeds max tier.
    pub fn allocTieredWriteBuf(self: *BufferPool, needed: usize) ?struct { buf: []u8, tier: usize } {
        if (needed > TIER_SIZES[TIER_COUNT - 1]) return null;
        const tier = tierFor(needed);
        var fl = &self.tier_freelists[tier];
        if (fl.items.len > 0) {
            return .{ .buf = fl.pop().?, .tier = tier };
        }
        const buf = self.allocator.alloc(u8, TIER_SIZES[tier]) catch {
            // Fallback: try larger tiers
            var t = tier + 1;
            while (t < TIER_COUNT) : (t += 1) {
                var fallback_fl = &self.tier_freelists[t];
                if (fallback_fl.items.len > 0) {
                    return .{ .buf = fallback_fl.pop().?, .tier = t };
                }
            }
            return null;
        };
        return .{ .buf = buf, .tier = tier };
    }

    /// Return a write buffer to the tiered pool.
    pub fn freeTieredWriteBuf(self: *BufferPool, buf: []u8, tier: usize) void {
        if (tier == 0xFF) {
            // Slab write buffer (legacy, should not occur in new path)
            self.allocator.free(buf);
            return;
        }
        if (tier >= TIER_COUNT) {
            self.allocator.free(buf);
            return;
        }
        const max_per_tier: usize = 4096;
        var fl = &self.tier_freelists[tier];
        if (fl.items.len < max_per_tier) {
            fl.append(self.allocator, buf) catch {
                self.allocator.free(buf);
            };
        } else {
            self.allocator.free(buf);
        }
    }

    pub fn readPoolStats(self: *const BufferPool) ReadPoolStats {
        return .{
            .total = self.block_count,
            .pending_replenish = self.replenish_queue.items.len,
        };
    }

    pub const ReadPoolStats = struct {
        total: usize,
        pending_replenish: usize,
    };
};

test "BufferPool preallocates replenish queue for read buffers" {
    var pool = try BufferPool.init(std.testing.allocator, 2);
    defer pool.deinit();

    try std.testing.expect(pool.replenish_queue.capacity >= 2);
}
