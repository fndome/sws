const std = @import("std");
const RingBuffer = @import("../spsc_ringbuffer.zig").RingBuffer;

/// Ring buffer entry (internal)
pub const Item = struct {
    ctx: ?*anyopaque,
    execute: *const fn (ctx: ?*anyopaque, complete: *const fn (?*anyopaque, []const u8) void) void,
    on_complete: *const fn (ctx: ?*anyopaque, result: []const u8) void,
};

/// User-created SPSC submission queue.
pub const SubmitQueue = struct {
    ring: RingBuffer(Item, 4096),
    registered: bool = false,

    pub fn init() SubmitQueue {
        return .{ .ring = RingBuffer(Item, 4096).init() };
    }

    pub fn push(self: *SubmitQueue, req: Item) bool {
        return self.ring.tryPush(req);
    }

    pub fn pop(self: *SubmitQueue) ?Item {
        return self.ring.tryPop();
    }
};

/// Submission queue registry, attached to AsyncServer.
pub const SubmitQueueRegistry = struct {
    queues: std.ArrayList(*SubmitQueue),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !SubmitQueueRegistry {
        return .{
            .queues = try std.ArrayList(*SubmitQueue).initCapacity(allocator, 0),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SubmitQueueRegistry) void {
        self.queues.deinit(self.allocator);
    }

    pub fn register(self: *SubmitQueueRegistry, queue: *SubmitQueue) !void {
        try self.queues.append(self.allocator, queue);
        queue.registered = true;
    }

    pub fn drain(self: *SubmitQueueRegistry, tasks: []Item) usize {
        var count: usize = 0;
        const num_queues = self.queues.items.len;
        if (num_queues == 0) return 0;
        var active = true;
        while (active) {
            active = false;
            for (self.queues.items) |q| {
                if (count >= tasks.len) return count;
                if (q.pop()) |t| {
                    tasks[count] = t;
                    count += 1;
                    active = true;
                }
            }
        }
        return count;
    }
};
