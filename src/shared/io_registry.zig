const std = @import("std");
const Allocator = std.mem.Allocator;
pub const CLIENT_USER_DATA_FLAG: u64 = 1 << 62;
const GEN_MASK: u32 = 0x0FFF_FFFF;

pub const CqeDispatchFn = *const fn (*anyopaque, u64, i32) void;

const RegisteredEntry = struct {
    ptr: *anyopaque,
    dispatch: CqeDispatchFn,
    gen_id: u32,
};

/// Unified registry for io_uring handles. Supports Ring A (built into the server) and outbound Ring B/C/D.
///
/// user_data encoding (aligned with StackPool, together preventing ghost CQEs):
///   CLIENT_USER_DATA_FLAG | ((gen_id & 0x0FFF_FFFF) << 32) | (counter & 0xFFFF_FFFF)
///
/// gen_id increases monotonically and is invalidated on remove, preventing u32 counter wraparound from colliding old and new connections.
pub const IORegistry = struct {
    streams: std.AutoHashMap(u32, RegisteredEntry),
    counter: u32 = 0,
    gen_counter: u32 = 1,

    pub fn init(allocator: Allocator) IORegistry {
        return .{ .streams = std.AutoHashMap(u32, RegisteredEntry).init(allocator) };
    }

    pub fn deinit(self: *IORegistry) void {
        self.streams.deinit();
    }

    /// Allocate a user_data token encoding gen_id + counter.
    pub fn allocUserData(self: *IORegistry) u64 {
        var gen = self.gen_counter & GEN_MASK;
        // user_data encodes only a 28-bit generation; an encoded 0 would weaken the ghost-CQE defense, so wraparound must skip it.
        if (gen == 0) gen = 1;
        self.gen_counter = gen + 1;
        if (self.gen_counter > GEN_MASK) self.gen_counter = 1;
        const idx = self.counter;
        self.counter +%= 1;

        return CLIENT_USER_DATA_FLAG | (@as(u64, gen) << 32) | idx;
    }

    pub fn register(self: *IORegistry, ud: u64, ptr: *anyopaque, on_cqe: CqeDispatchFn) !void {
        const gen = @as(u32, @truncate((ud >> 32) & GEN_MASK));
        const idx = @as(u32, @truncate(ud));
        try self.streams.put(idx, .{ .ptr = ptr, .dispatch = on_cqe, .gen_id = gen });
    }

    pub fn remove(self: *IORegistry, ud: u64) void {
        const idx = @as(u32, @truncate(ud));
        _ = self.streams.remove(idx);
    }

    /// Dispatch a CQE: decode the counter for the lookup plus a gen_id check, preventing ghost events.
    pub fn dispatch(self: *IORegistry, ud: u64, res: i32) void {
        const gen = @as(u32, @truncate((ud >> 32) & GEN_MASK));
        const idx = @as(u32, @truncate(ud));
        if (self.streams.getPtr(idx)) |entry| {
            if (entry.gen_id != gen) return;
            entry.dispatch(entry.ptr, ud, res);
        }
    }
};

fn encodedGen(ud: u64) u32 {
    return @as(u32, @truncate((ud >> 32) & GEN_MASK));
}

test "IORegistry allocUserData skips zero encoded generation" {
    var registry = IORegistry.init(std.testing.allocator);
    defer registry.deinit();

    registry.gen_counter = 0;
    try std.testing.expectEqual(@as(u32, 1), encodedGen(registry.allocUserData()));
    try std.testing.expectEqual(@as(u32, 2), registry.gen_counter);

    registry.gen_counter = GEN_MASK;
    try std.testing.expectEqual(GEN_MASK, encodedGen(registry.allocUserData()));
    try std.testing.expectEqual(@as(u32, 1), registry.gen_counter);
    try std.testing.expectEqual(@as(u32, 1), encodedGen(registry.allocUserData()));
}
