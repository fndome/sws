const std = @import("std");
const Allocator = std.mem.Allocator;

const ConnState = @import("http/connection.zig").ConnState;
const NO_READ_BUFFER_BID = @import("constants.zig").NO_READ_BUFFER_BID;
const WORKSPACE_SENTINEL = @import("constants.zig").WORKSPACE_SENTINEL;
const NO_LIVE_POS = @import("constants.zig").NO_LIVE_POS;

/// StackPool: O(1) 连续数组连接池，替代 AutoHashMap。
/// user_data = (gen_id << 32) | idx，防 FD 复用幽灵事件。
pub fn StackPool(comptime T: type) type {
    return struct {
        const Self = @This();

        slots: []T,
        freelist: []u32,
        freelist_top: u32,
        capacity: usize,
        /// 活跃槽位索引表，O(1) swap-remove。TTL 扫描只遍历此项。
        live: std.ArrayList(u32),

        pub fn init(allocator: Allocator, capacity: usize) !Self {
            const slots = try allocator.alloc(T, capacity);
            errdefer allocator.free(slots);
            const freelist = try allocator.alloc(u32, capacity);
            errdefer allocator.free(freelist);
            // 修改原因：live 预分配失败时前面两个数组已经申请成功，必须用 errdefer 回收，避免初始化 OOM 泄漏。
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

        /// 预热：触碰每个 slot 的首字段，强制内核分配物理页，
        /// 消除运行时冷启动 Page Fault 抖动。
        pub fn warmup(self: *Self) void {
            for (self.slots) |*slot| {
                // 修改原因：allocator.alloc 返回未初始化内存，必须写入默认值以初始化 line5.sentinel 等调试/运行元数据。
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

        /// 将 idx 写入活跃表，返回在 live 中的位置。
        /// 调用方需将返回值写入 slot.active_list_pos。
        pub fn liveAdd(self: *Self, idx: u32) u32 {
            self.live.appendAssumeCapacity(idx);
            return @intCast(self.live.items.len - 1);
        }

        /// swap-remove：用最后一个元素覆盖 list_pos，O(1)。
        /// 返回被移过来的 idx（调用方需更新其 slot.active_list_pos = list_pos）。
        /// 返回 null 表示移除的是尾部元素，无元素被移动，无需更新。
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

/// ── 缓存行子结构 ───────────────────────────────────────
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
    /// 当前窗口内请求计数（CQE 热路径防刷）
    req_count: u32 = 0,
    /// 当前限速窗口起始时间戳 (ms)
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
    /// 连接创建时间戳 (ms)，用于绝对 TTL 硬超时
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
    /// ChunkStream 堆指针：IO 线程 feed → Worker dispatch
    stream_ptr: u64 align(8) = 0,
    /// 二级计算区：Worker Pool 移交时的预解析元数据 (JSON offset/length 等)
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
    /// 内核正在异步读取 write_iovs（writev SQE 已提交但 CQE 未到）。
    /// 置位期间严禁对 Line4 做任何 memcpy / 重置 / iovec 修改。
    writev_in_flight: u8 = 0,
    _pad: [2]u8 = [_]u8{0} ** 2,
    response_buf_len: u32 = 0,
    write_iovs: [2]std.posix.iovec_const = [_]std.posix.iovec_const{
        .{ .base = undefined, .len = 0 },
        .{ .base = undefined, .len = 0 },
    },
    ws_write_queue_tail: u64 = 0,
    /// 二级计算区：写路径临时暂存 (NATS sequence / 校验和 / 协议中间态)
    write_scratch: [48]u8 = [_]u8{0} ** 48,
    /// Reserved: formerly response_buf_ptr, ws_write_queue_head, ws_token_ptr,
    /// ws_token_len — dead fields removed, padding maintains 128 B cache line.
    _reserved: [32]u8 = [_]u8{0} ** 32,
};

const CacheLine5 = extern struct {
    /// 哨兵魔数（WORKSPACE_SENTINEL），debug 时检测内存越界
    sentinel: u32 = WORKSPACE_SENTINEL,
    /// 二级计算区：协议解析 / Worker Pool 移交 / Fiber 虚拟寄存器
    ws: SlotWorkspace = .{ .raw = [_]u8{0} ** 56 },
};

/// ── 二级计算区联合体 ───────────────────────────────────
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
    /// 修改原因：这里缓存 body 起点，而不是裸 header 结束下标，以兼容 "\r\n\r\n" 与 "\n\n"。
    headers_end: u16 = 0,
    /// 上次短读的 buffer ID（用于跨 TCP 分片的 header 拼包）
    pending_bid: u16 = NO_READ_BUFFER_BID,
    /// 上次短读已累积的字节数
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

/// ── 连接槽位 (384 bytes, <400 budget) ──────────────────
///
/// 五组子结构各占独立缓存行，IO 循环最热路径只碰 line1。
///   line1 ( 64B): fd, gen_id, state, write_offset — CQE dispatch
///   line2 ( 64B): user_id, last_active_ms, conn_id, birth_ms — TTL scan
///   line3 ( 64B): 异步锚点 + 大报文 — Worker Pool / LargeBufferPool
///   line4 (128B): response_buf, write_iovs, WS queue — 写路径低频
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
