const std = @import("std");
const Allocator = std.mem.Allocator;

const ConnState = @import("http/connection.zig").ConnState;
const NO_READ_BUFFER_BID = @import("constants.zig").NO_READ_BUFFER_BID;
const WORKSPACE_SENTINEL = @import("constants.zig").WORKSPACE_SENTINEL;
const NO_LIVE_POS = @import("constants.zig").NO_LIVE_POS;

/// StackPool: O(1) contiguous-array connection pool, replacing AutoHashMap.
/// user_data = (gen_id << 32) | idx, defends against FD-reuse ghost events.
pub fn StackPool(comptime T: type) type {
    return struct {
        const Self = @This();

        slots: []T,
        freelist: []u32,
        freelist_top: u32,
        capacity: usize,
        /// Active-slot index table with O(1) swap-remove. TTL scan iterates only this.
        live: std.ArrayList(u32),

        pub fn init(allocator: Allocator, capacity: usize) !Self {
            const slots = try allocator.alloc(T, capacity);
            errdefer allocator.free(slots);
            const freelist = try allocator.alloc(u32, capacity);
            errdefer allocator.free(freelist);
            // Defensive: if live preallocation fails, the two arrays above are already allocated, so an errdefer must reclaim them to avoid an init OOM leak.
            const live = try std.ArrayList(u32).initCapacity(allocator, capacity);

            for (freelist, 0..) |*f, i| {
                f.* = @intCast(i); // sequential for stream prefetcher
            }

            return Self{
                .slots = slots,
                .freelist = freelist,
                .freelist_top = @intCast(capacity),
                .capacity = capacity,
                .live = live,
            };
        }

        /// Warmup: touch the first field of each slot to force the kernel to allocate physical pages,
        /// eliminating cold-start Page Fault jitter at runtime.
        pub fn warmup(self: *Self) void {
            for (self.slots) |*slot| {
                // Defensive: allocator.alloc returns uninitialized memory, so default values must be written to initialize debug/runtime metadata like line5.sentinel.
                slot.* = std.mem.zeroes(T);
                if (@hasField(T, "line5")) {
                    slot.line5.sentinel = WORKSPACE_SENTINEL;
                }
                @atomicStore(u32, &slot.line1.gen_id, 0, .monotonic);
            }
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            self.live.deinit(allocator);
            allocator.free(self.slots);
            allocator.free(self.freelist);
        }

        pub fn acquire(self: *Self) ?u32 {
            if (self.freelist_top == 0) return null;
            self.freelist_top -= 1;
            return self.freelist[self.freelist_top];
        }

        /// Append idx to the active table and return its position in live.
        /// The caller must write the return value into slot.active_list_pos.
        pub fn liveAdd(self: *Self, idx: u32) u32 {
            self.live.appendAssumeCapacity(idx);
            return @intCast(self.live.items.len - 1);
        }

        /// swap-remove: overwrite list_pos with the last element, O(1).
        /// Returns the idx that was moved over (the caller must update its slot.active_list_pos = list_pos).
        /// Returns null when the removed element was the tail, so nothing was moved and no update is needed.
        pub fn liveRemove(self: *Self, list_pos: u32) ?u32 {
            if (list_pos >= self.live.items.len) return null;
            const last = self.live.getLast();
            self.live.items[list_pos] = last;
            self.live.items.len -= 1;
            if (list_pos < self.live.items.len) return last;
            return null;
        }

        pub fn release(self: *Self, idx: u32) void {
            self.freelist[self.freelist_top] = idx;
            self.freelist_top += 1;
        }
    };
}

pub inline fn packUserData(gen_id: u32, idx: u32) u64 {
    const g = gen_id & 0x0FFFFFFF; // 28 bits (268M), bits 60-63 reserved
    return (@as(u64, g) << 32) | (idx & 0xFFFFFFFF);
}

pub inline fn unpackGenId(ud: u64) u32 {
    return @intCast((ud >> 32) & 0x0FFFFFFF);
}

/// Flag bits reserved above gen_id range
pub const CLOSE_USER_DATA_FLAG: u64 = 1 << 60; // close SQE marker

pub inline fn unpackIdx(ud: u64) u32 {
    return @truncate(ud);
}

/// ── Cache-line substructures ───────────────────────────
const CacheLine1 = extern struct {
    gen_id: u32 = 0,
    state: ConnState = .reading,
    oversized: bool = false,
    buf_recycled: bool = false,
    fd: i32 = 0,
    write_offset: u32 = 0,
    write_headers_len: u32 = 0,
    read_bid: u16 = 0,
    write_retries: u8 = 0,
    keep_alive: bool = false,
    /// Request count in the current window (anti-flood on the CQE hot path)
    req_count: u32 = 0,
    /// Start timestamp of the current rate-limit window (ms)
    req_window_ms: i64 = 0,
    _fill: [24]u8 = [_]u8{0} ** 24,
};

comptime {
    if (@sizeOf(CacheLine1) != 64) {
        @compileError("CacheLine1 must be 64 bytes, got " ++ std.fmt.comptimePrint("{}", .{@sizeOf(CacheLine1)}));
    }
}

const CacheLine2 = extern struct {
    user_id: u64 = 0,
    last_active_ms: i64 = 0,
    write_start_ms: i64 = 0,
    is_writing: bool = false,
    conn_id: u64 = 0,
    active_list_pos: u32 = NO_LIVE_POS,
    /// Connection creation timestamp (ms), used for absolute TTL hard timeout
    birth_ms: i64 = 0,
    _pad: [4]u8 = [_]u8{0} ** 4,
};

comptime {
    if (@sizeOf(CacheLine2) != 64) {
        @compileError("CacheLine2 must be 64 bytes, got " ++ std.fmt.comptimePrint("{}", .{@sizeOf(CacheLine2)}));
    }
}

const CacheLine3 = extern struct {
    pending_buffer_ptr: u64 = 0,
    fiber_context: u64 = 0,
    waiting_since_ms: i64 = 0,
    large_buf_ptr: u64 = 0,
    large_buf_len: u32 = 0,
    large_buf_offset: u32 = 0,
    /// ChunkStream heap pointer: IO thread feed → Worker dispatch
    stream_ptr: u64 align(8) = 0,
    /// Secondary compute area: pre-parsed metadata (JSON offset/length, etc.) at Worker Pool handoff
    worker_scratch: [16]u8 = [_]u8{0} ** 16,
};

comptime {
    if (@sizeOf(CacheLine3) != 64) {
        @compileError("CacheLine3 must be 64 bytes, got " ++ std.fmt.comptimePrint("{}", .{@sizeOf(CacheLine3)}));
    }
}

const CacheLine4_6 = extern struct {
    /// NOTE: write_iovs live here (Line4), NOT in workspace (Line5).
    /// This guarantees in-flight write iovecs are never corrupted
    /// by workspace union state switches (http→ws, ws→compute).
    response_buf_tier: u8 = 0,
    /// The kernel is asynchronously reading write_iovs (writev SQE submitted but CQE not yet arrived).
    /// While set, no memcpy / reset / iovec modification of Line4 is allowed.
    writev_in_flight: u8 = 0,
    _pad: [2]u8 = [_]u8{0} ** 2,
    response_buf_len: u32 = 0,
    write_iovs: [2]std.posix.iovec_const = [_]std.posix.iovec_const{
        .{ .base = undefined, .len = 0 },
        .{ .base = undefined, .len = 0 },
    },
    ws_write_queue_tail: u64 = 0,
    /// Secondary compute area: write-path scratch (NATS sequence / checksum / protocol intermediate state)
    write_scratch: [48]u8 = [_]u8{0} ** 48,
    /// Reserved: formerly response_buf_ptr, ws_write_queue_head, ws_token_ptr,
    /// ws_token_len — dead fields removed, padding maintains 128 B cache line.
    _reserved: [32]u8 = [_]u8{0} ** 32,
};

const CacheLine5 = extern struct {
    /// Sentinel magic (WORKSPACE_SENTINEL), detects out-of-bounds writes in debug
    sentinel: u32 = WORKSPACE_SENTINEL,
    /// Secondary compute area: protocol parse / Worker Pool handoff / Fiber virtual registers
    ws: SlotWorkspace = .{ .raw = [_]u8{0} ** 56 },
};

/// ── Secondary compute area union ───────────────────────
pub const SlotWorkspace = extern union {
    http: HttpWork,
    websocket: WsWork,
    compute: ComputeWork,
    raw: [56]u8,
};

pub const HttpWork = extern struct {
    header_len: u16 = 0,
    method: u8 = 0,
    version: u8 = 0,
    content_length: u64 = 0,
    path_offset: u16 = 0,
    path_len: u16 = 0,
    /// Defensive: cache the body start here, not the raw header-end index, to support both "\r\n\r\n" and "\n\n".
    headers_end: u16 = 0,
    /// Buffer ID of the last short read (for reassembling headers across TCP segments)
    pending_bid: u16 = NO_READ_BUFFER_BID,
    /// Number of bytes accumulated so far from the last short read
    pending_len: u16 = 0,
    _fill: [30]u8 = [_]u8{0} ** 30,
};

pub const WsWork = extern struct {
    mask: [4]u8 = [_]u8{0} ** 4,
    payload_len: u64 = 0,
    is_final: bool = false,
    _fill: [39]u8 = [_]u8{0} ** 39,
};

pub const ComputeWork = extern struct {
    job_id: u64 = 0,
    buffer_ptr: u64 = 0,
    result_code: i32 = 0,
    _fill: [36]u8 = [_]u8{0} ** 36,
};

comptime {
    if (@sizeOf(CacheLine4_6) != 128) {
        @compileError("CacheLine4_6 must be 128 bytes, got " ++ std.fmt.comptimePrint("{}", .{@sizeOf(CacheLine4_6)}));
    }
    if (@sizeOf(CacheLine5) != 64) {
        @compileError("CacheLine5 must be 64 bytes, got " ++ std.fmt.comptimePrint("{}", .{@sizeOf(CacheLine5)}));
    }
    // Verify workspace variants are exactly 56 bytes
    if (@sizeOf(HttpWork) != 56) {
        @compileError("HttpWork must be 56 bytes, got " ++ std.fmt.comptimePrint("{}", .{@sizeOf(HttpWork)}));
    }
    if (@sizeOf(WsWork) != 56) {
        @compileError("WsWork must be 56 bytes, got " ++ std.fmt.comptimePrint("{}", .{@sizeOf(WsWork)}));
    }
    if (@sizeOf(ComputeWork) != 56) {
        @compileError("ComputeWork must be 56 bytes, got " ++ std.fmt.comptimePrint("{}", .{@sizeOf(ComputeWork)}));
    }
}

/// ── Connection slot (384 bytes, <400 budget) ───────────
///
/// The five substructures each occupy their own cache line; the IO loop's hottest path only touches line1.
///   line1 ( 64B): fd, gen_id, state, write_offset — CQE dispatch
///   line2 ( 64B): user_id, last_active_ms, conn_id, birth_ms — TTL scan
///   line3 ( 64B): async anchors + oversized requests — Worker Pool / LargeBufferPool
///   line4 (128B): response_buf, write_iovs, WS queue — low-frequency write path
pub const StackSlot = extern struct {
    line1: CacheLine1 align(64),
    line2: CacheLine2,
    line3: CacheLine3,
    line4: CacheLine4_6,
    line5: CacheLine5,

    comptime {
        if (@sizeOf(StackSlot) > 400) {
            @compileError("StackSlot exceeds 400 bytes: " ++ std.fmt.comptimePrint("{}", .{@sizeOf(StackSlot)}));
        }
        if (@offsetOf(StackSlot, "line2") != 64) {
            @compileError("line2 offset must be 64, got " ++ std.fmt.comptimePrint("{}", .{@offsetOf(StackSlot, "line2")}));
        }
        if (@offsetOf(StackSlot, "line3") != 128) {
            @compileError("line3 offset must be 128, got " ++ std.fmt.comptimePrint("{}", .{@offsetOf(StackSlot, "line3")}));
        }
        if (@offsetOf(StackSlot, "line4") != 192) {
            @compileError("line4 offset must be 192, got " ++ std.fmt.comptimePrint("{}", .{@offsetOf(StackSlot, "line4")}));
        }
        if (@offsetOf(StackSlot, "line5") != 320) {
            @compileError("line5 offset must be 320, got " ++ std.fmt.comptimePrint("{}", .{@offsetOf(StackSlot, "line5")}));
        }
        // Gemini: explicit offset check for hot fields to guard compiler padding drift
        if (@offsetOf(CacheLine1, "fd") != 8) {
            @compileError("CacheLine1.fd must be at offset 8, got " ++ std.fmt.comptimePrint("{}", .{@offsetOf(CacheLine1, "fd")}));
        }
        if (@offsetOf(CacheLine2, "last_active_ms") != 8) {
            @compileError("CacheLine2.last_active_ms must be at offset 8, got " ++ std.fmt.comptimePrint("{}", .{@offsetOf(CacheLine2, "last_active_ms")}));
        }
        if (@offsetOf(CacheLine5, "sentinel") != 0) {
            @compileError("CacheLine5.sentinel must be at offset 0, got " ++ std.fmt.comptimePrint("{}", .{@offsetOf(CacheLine5, "sentinel")}));
        }
    }
};

pub const OVERSIZED_THRESHOLD: usize = 32 * 1024;
pub const COMPUTATION_TIMEOUT_MS: i64 = 2000;
