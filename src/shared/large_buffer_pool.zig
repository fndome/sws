const std = @import("std");
const Allocator = std.mem.Allocator;
const logErr = @import("../async_logger.zig").logErr;

/// ── Generic block buffer pool ────────────────────────────────────────
///
/// Pre-allocates N blocks, each block_size bytes. O(1) acquire/release, driven by a freelist.
/// For large IM JSON, file I/O, database result sets, etc. — any scenario needing deterministic memory.
///
/// Owned exclusively by the IO thread with no concurrent access — no atomics needed.
///
/// Usage:
///   var pool = try BufferBlockPool(65536, 32).init(alloc); // 32 × 64KB
///   const buf = pool.acquire() orelse return error.OutOfBlocks;
///   defer pool.release(buf);
///   // io_uring read/write CQEs write directly to buf.ptr
///
/// release() is an O(n) pointer scan, suitable for pools with <= 64 blocks.
/// For larger pools use std.heap.MemoryPool or an arena allocator.
///
/// Per-block state machine defends against releasing the same buffer twice:
///   0 = IDLE (free)
///   1 = BUSY (acquired, in-flight)
/// release() checks the current state: BUSY → IDLE + return; IDLE → double free, log + skip.
pub fn BufferBlockPool(comptime block_size: usize, comptime capacity: usize) type {
    return struct {
        const Self = @This();
        const STATE_IDLE: u8 = 0;
        const STATE_BUSY: u8 = 1;

        blocks: [capacity][]u8,
        freelist: [capacity]usize,
        freelist_top: usize,
        states: [capacity]u8,
        count: usize,

        pub fn init(allocator: Allocator, runtime_capacity: usize) !Self {
            if (runtime_capacity > capacity) return error.OutOfMemory;
            var blocks: [capacity][]u8 = undefined;
            var allocated: usize = 0;
            errdefer {
                for (blocks[0..allocated]) |block| {
                    allocator.free(block);
                }
            }
            var freelist: [capacity]usize = undefined;
            for (0..runtime_capacity) |i| {
                blocks[i] = try allocator.alloc(u8, block_size);
                allocated += 1;
                freelist[i] = runtime_capacity - 1 - i;
            }
            return Self{
                .blocks = blocks,
                .freelist = freelist,
                .freelist_top = runtime_capacity,
                .states = [_]u8{STATE_IDLE} ** capacity,
                .count = runtime_capacity,
            };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            for (self.blocks[0..self.count]) |block| {
                allocator.free(block);
            }
        }

        pub fn acquire(self: *Self) ?[]u8 {
            if (self.freelist_top == 0) return null;
            self.freelist_top -= 1;
            const idx = self.freelist[self.freelist_top];
            self.states[idx] = STATE_BUSY;
            return self.blocks[idx];
        }

        /// Idempotent release: checks the current state. BUSY → IDLE + return to the freelist.
        /// If already IDLE → double free, log an error and skip.
        /// Owned exclusively by the IO thread with no concurrency — no CAS needed.
        pub fn release(self: *Self, buf: []u8) void {
            for (self.blocks[0..self.count], 0..) |block, i| {
                if (block.ptr == buf.ptr) {
                    if (self.states[i] == STATE_IDLE) {
                        logErr("LargeBufferPool: double-free detected for block idx={d} ptr=0x{x}", .{ i, @intFromPtr(buf.ptr) });
                        return;
                    }
                    self.states[i] = STATE_IDLE;
                    self.freelist[self.freelist_top] = i;
                    self.freelist_top += 1;
                    return;
                }
            }
            logErr("LargeBufferPool.release: buffer 0x{x} not found in pool", .{@intFromPtr(buf.ptr)});
        }
    };
}

/// Backward-compatible: 1MB × N blocks, for large messages (Content-Length > 32KB)
pub fn LargeBufferPool(comptime capacity: usize) type {
    return BufferBlockPool(1024 * 1024, capacity);
}

test "BufferBlockPool.init frees partial blocks on allocation failure" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 2 });
    const allocator = failing_allocator.allocator();

    try std.testing.expectError(error.OutOfMemory, BufferBlockPool(16, 4).init(allocator, 4));
    try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
    try std.testing.expectEqual(failing_allocator.allocations, failing_allocator.deallocations);
}
