const std = @import("std");
const Allocator = std.mem.Allocator;
const logErr = @import("../async_logger.zig").logErr;

/// ── 通用块缓冲池 ────────────────────────────────────────
///
/// 预分配 N 块, 每块 block_size 字节。O(1) acquire/release, freelist 驱动。
/// 用于 IM 的大 JSON、文件 I/O、数据库结果集等 — 任何需要确定性内存的场景。
///
/// IO 线程独占，无并发访问 — 不需要原子操作。
///
/// 用法:
///   var pool = try BufferBlockPool(65536, 32).init(alloc); // 32 × 64KB
///   const buf = pool.acquire() orelse return error.OutOfBlocks;
///   defer pool.release(buf);
///   // io_uring read/write CQE 直接写 buf.ptr
///
/// release() 是 O(n) 指针扫描, 适合 块数 <= 64 的场景。
/// 需要更大池子用 std.heap.MemoryPool 或 arena allocator。
///
/// 状态机 (per-block) 防御同一 buffer 被 release 两次:
///   0 = IDLE (free)
///   1 = BUSY (acquired, in-flight)
/// release() 检查当前状态: BUSY → IDLE + 归还; IDLE → 双重释放, log + skip。
pub fn BufferBlockPool(comptime block_size: usize, comptime capacity: usize) type {
    return struct {
        const Self = @This();
        const STATE_IDLE: u8 = 0;
        const STATE_BUSY: u8 = 1;

        blocks: [capacity][]u8,
        freelist: [capacity]usize,
        freelist_top: usize,
        states: [capacity]u8,

        pub fn init(allocator: Allocator) !Self {
            var blocks: [capacity][]u8 = undefined;
            var allocated: usize = 0;
            errdefer {
                for (blocks[0..allocated]) |block| {
                    allocator.free(block);
                }
            }
            var freelist: [capacity]usize = undefined;
            for (0..capacity) |i| {
                blocks[i] = try allocator.alloc(u8, block_size);
                allocated += 1;
                freelist[i] = capacity - 1 - i;
            }
            return Self{
                .blocks = blocks,
                .freelist = freelist,
                .freelist_top = capacity,
                .states = [_]u8{STATE_IDLE} ** capacity,
            };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            for (self.blocks) |block| {
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

        /// 幂等释放：检查当前状态。BUSY → IDLE + 归还 freelist。
        /// 若已是 IDLE → 双重释放，记录错误并跳过。
        /// IO 线程独占，无并发 — 不需要 CAS。
        pub fn release(self: *Self, buf: []u8) void {
            for (self.blocks, 0..) |block, i| {
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

/// 向后兼容: 1MB × N 块, 用于大报文 (Content-Length > 32KB)
pub fn LargeBufferPool(comptime capacity: usize) type {
    return BufferBlockPool(1024 * 1024, capacity);
}

test "BufferBlockPool.init frees partial blocks on allocation failure" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 2 });
    const allocator = failing_allocator.allocator();

    try std.testing.expectError(error.OutOfMemory, BufferBlockPool(16, 4).init(allocator));
    try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
    try std.testing.expectEqual(failing_allocator.allocations, failing_allocator.deallocations);
}
