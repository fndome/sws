const std = @import("std");
const build_options = @import("build_options");
const TlsStream = if (build_options.tls_enabled) @import("../tls/tls.zig").TlsStream else opaque {};

pub const ConnState = if (build_options.tls_enabled) enum(u8) {
    reading,
    receiving_body,
    processing,
    writing,
    closing,
    tls_handshaking,
    ws_reading,
    ws_writing,
    waiting_computation,
    streaming,
} else enum(u8) {
    reading,
    receiving_body,
    processing,
    writing,
    closing,
    ws_reading,
    ws_writing,
    waiting_computation,
    streaming,
};

pub const Connection = struct {
    id: u64,
    fd: i32,
    /// 0xFFFF = no fixed file registered; fall back to plain fd for I/O.
    fixed_index: u16 = 0xFFFF,
    state: ConnState = .reading,
    read_bid: u16 = 0,
    read_len: usize = 0,
    write_headers_len: usize = 0,
    write_offset: usize = 0,
    /// Lazy-allocated write buffer from tiered pool.
    response_buf: ?[]u8 = null,
    /// Tier index for response_buf (valid only when response_buf != null). 0xFF = slab buffer.
    response_buf_tier: u8 = 0,
    write_body: ?[]u8 = null,
    keep_alive: bool = false,
    last_active_ms: i64 = 0,
    write_start_ms: i64 = 0,
    ws_token: ?[]const u8 = null,
    ws_partial: ?[]u8 = null,
    write_retries: u8 = 0,
    /// 读 buffer 是否已归还 io_uring provided buffer pool（防止二次回收）
    read_buf_recycled: bool = false,
    /// 写 buffer (write_body + response_buf) 是否已在 close 路径释放（防止 double-free）
    write_bufs_freed: bool = false,
    /// WebSocket 写锁：防止多个 Fiber 同时串扰帧数据
    is_writing: bool = false,
    /// WebSocket 写等待队列头部指针（单 IO 线程无锁链表）
    ws_write_queue_head: ?*WsWriteQueueNode = null,
    ws_write_queue_tail: ?*WsWriteQueueNode = null,
    /// StackPool slot index (0xFFFFFFFF = not pooled)
    pool_idx: u32 = 0xFFFFFFFF,
    /// Generation ID for ghost-event defense (synced with pool slot)
    gen_id: u32 = 0,
    /// Position in pool.live list (for O(1) swap-remove)
    active_list_pos: u32 = 0xFFFFFFFF,
    pub usingnamespace if (build_options.tls_enabled) struct {
        tls: ?*TlsStream = null,
        tls_write_len: u32 = 0,
    } else struct {};
};

/// WebSocket 写队列节点（单 IO 线程，无需原子操作）
pub const WsWriteQueueNode = struct {
    opcode: @import("../ws/types.zig").Opcode,
    payload: []u8,
    next: ?*WsWriteQueueNode,
};
