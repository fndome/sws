const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const BufferPool = @import("../buffer_pool.zig").BufferPool;

const constants = @import("../constants.zig");
const RING_ENTRIES = constants.RING_ENTRIES;
const TASK_QUEUE_SIZE = constants.TASK_QUEUE_SIZE;
const BUFFER_POOL_SIZE = constants.BUFFER_POOL_SIZE;
const ACCEPT_USER_DATA = constants.ACCEPT_USER_DATA;
const IORegistry = @import("../shared/io_registry.zig").IORegistry;

const MAX_FIXED_FILES = constants.MAX_FIXED_FILES;

const uring_submit = @import("../next/queue.zig");
const SubmitQueueRegistry = uring_submit.SubmitQueueRegistry;
const Item = uring_submit.Item;
const Next = @import("../next/next.zig").Next;

const Connection = @import("connection.zig").Connection;
const Context = @import("context.zig").Context;
const Middleware = @import("types.zig").Middleware;
const Handler = @import("types.zig").Handler;
const MiddlewareStore = @import("middleware_store.zig").MiddlewareStore;
const WildcardEntry = @import("middleware_store.zig").WildcardEntry;

const helpers = @import("http_helpers.zig");
const parseIpv4 = helpers.parseIpv4;
const readResolvConfNameserver = helpers.readResolvConfNameserver;

const WsServer = @import("../ws/server.zig").WsServer;
const WsHandler = @import("../ws/server.zig").WsHandler;
const Opcode = @import("../ws/types.zig").Opcode;
const TcpServer = @import("../tcp/server.zig").TcpServer;
const TcpHandler = @import("../tcp/types.zig").TcpHandler;
const UdpServer = @import("../udp/server.zig").UdpServer;
const UdpHandler = @import("../udp/types.zig").UdpHandler;

const DnsResolver = @import("../dns/resolver.zig").DnsResolver;
const RingShared = @import("../shared/ring_shared.zig").RingShared;
const StackPool = @import("../stack_pool.zig").StackPool;
const StackSlot = @import("../stack_pool.zig").StackSlot;
const LargeBufferPool = @import("../shared/large_buffer_pool.zig").LargeBufferPool;
const sticker = @import("../stack_pool_sticker.zig");
const fiber_task = @import("fiber_task.zig");
const http_fiber = @import("http_fiber.zig");
const http_body = @import("http_body.zig");
const ws_handler = @import("ws_handler.zig");
const tcp_handler = @import("tcp_handler.zig");
const event_loop = @import("event_loop.zig");
const http_response = @import("http_response.zig");
const tcp_accept = @import("tcp_accept.zig");
const AsyncLogger = @import("../async_logger.zig").AsyncLogger;
const connection_mgr = @import("connection_mgr.zig");
const http_routing = @import("http_routing.zig");
const tcp_read = @import("tcp_read.zig");
const tcp_write = @import("tcp_write.zig");
const hook_system = @import("hook_system.zig");
const HttpTaskCtx = http_fiber.HttpTaskCtx;
const WsTaskCtx = fiber_task.WsTaskCtx;
const build_options = @import("build_options");

pub const TlsAuth = struct {
    cert_path: [:0]const u8,
    key_path: [:0]const u8,
};

const TlsConfig = if (build_options.tls_enabled) @import("../tls/tls.zig").TlsConfig else struct {};
const TlsStream = if (build_options.tls_enabled) @import("../tls/tls.zig").TlsStream else struct {};

const DeferredNode = hook_system.DeferredNode;
const deferredRespond = hook_system.deferredRespond;

fn listenSocketFd(raw_fd: usize) !i32 {
    // 修改原因：listen socket 创建失败时 linux.socket 返回 errno 编码的 usize，先 @intCast 可能在安全构建中直接失败。
    if (linux.errno(raw_fd) != .SUCCESS) return error.SocketCreationFailed;
    return @intCast(raw_fd);
}

pub const AsyncServer = struct {
    allocator: Allocator,
    io: std.Io,
    ring: linux.IoUring,
    listen_fd: i32,
    accept_addr: linux.sockaddr = undefined,
    accept_addrlen: u32 = @sizeOf(linux.sockaddr),
    next_conn_id: u64,
    connections: std.AutoHashMap(u64, Connection),
    /// StackPool array-indexed connection pool (migrating from AutoHashMap)
    pool: StackPool(StackSlot),
    /// Flat hash map: user_id → pool slot index (IM routing, L3-resident)
    user_map: ?std.AutoHashMap(u64, u32) = null,
    /// Monotonic generation ID for ghost-event defense
    conn_gen_id: u32 = 1,
    next_user_data: u64,
    app_ctx: ?*anyopaque,

    should_stop: bool = false,
    buffer_pool: BufferPool,
    /// 大报文专用缓冲池（每块 1MB），content_length > 32KB 时触发
    large_pool: LargeBufferPool(64),

    /// Set when submitAccept fails; cleared on successful submission.
    /// Used by the event loop to detect and recover broken accept chains.
    accept_stalled: bool = false,
    accept_outstanding: bool = false,

    use_fixed_files: bool = false,
    fixed_file_freelist: std.ArrayList(u16),
    fixed_file_next: u16,

    ws_server: WsServer,
    tcp_server: TcpServer,
    udp_server: ?UdpServer = null,
    tcp_listen_fd: i32 = -1,
    tcp_accept_outstanding: bool = false,
    tcp_accept_stalled: bool = false,
    tcp_accept_addr: linux.sockaddr = undefined,
    tcp_accept_addrlen: u32 = @sizeOf(linux.sockaddr),
    middlewares: MiddlewareStore,
    respond_middlewares: MiddlewareStore,
    handlers: std.StringHashMap(Handler),

    /// Parameterized routes (paths containing :id or * wildcard segments).
    /// Populated by register() when the path is not a simple exact-match literal.
    param_routes: std.ArrayList(http_routing.ParamRoute),

    /// Async logger: offloads stderr writes to a dedicated thread so IO thread
    /// never blocks on log syscalls.
    logger: ?*AsyncLogger = null,

    timeout_user_data: u64 = 0,
    timeout_ts: linux.kernel_timespec = .{ .sec = 1, .nsec = 0 },

    /// sticker TTL 增量扫描游标
    ttl_scan_cursor: u32 = 0,
    ttl_scan_out: std.ArrayList(u32),

    cfg: Config,

    /// 通用跨线程 IO 回调队列 (在 RingShared 内)
    /// 钩子列表：在 deferred 响应发送前依次调用（IO 线程内执行）
    deferred_hooks: std.ArrayList(*const fn (self: *Self, node: *DeferredNode) void),
    /// tick 钩子列表：每轮 IO 循环必触发（有/无 deferred 节点都跑）
    tick_hooks: std.ArrayList(*const fn (self: *Self) void),

    /// 客户端出站连接注册表（io_uring TCP client）
    io_registry: IORegistry,

    /// 注入的 ring 共享资源（DNS / Client / ... 均等使用）
    rs: RingShared,

    /// IO 线程已绑核标记
    io_pinned: bool = false,

    /// DNS 解析器 (io_uring 异步 UDP DNS)
    dns_resolver: *DnsResolver,

    /// HTTP 请求 fiber 执行器
    next: ?Next = null,
    /// 用户自定义队列注册表
    submit_registry: SubmitQueueRegistry,

    /// 高频对象内存池，消除 per-request alloc
    http_ctx_pool: std.heap.MemoryPool(HttpTaskCtx),
    ws_ctx_pool: std.heap.MemoryPool(WsTaskCtx),
    /// 预分配的 fiber 共享栈（单 IO 线程串行复用）
    shared_fiber_stack: []u8,
    /// 标记共享栈是否有活跃的 fiber（保护 yield 场景下的栈安全）
    shared_fiber_active: bool = false,

    /// SQ ring 溢出时暂存的写请求 (1M broadcast 场景的背压机制)
    pending_writes: std.ArrayList(u64),

    tls_config: ?TlsConfig = null,

    worker_orig_cpu_mask: usize = 0,

    const Self = @This();

    pub const Config = struct {
        max_header_buffer_size: u32 = constants.MAX_HEADER_BUFFER_SIZE,
        max_response_buffer_size: u32 = constants.MAX_RESPONSE_BUFFER_SIZE,
        max_cqes_batch: u32 = constants.MAX_CQES_BATCH,
        ring_entries: u32 = constants.RING_ENTRIES,
        task_queue_size: u32 = constants.TASK_QUEUE_SIZE,
        response_queue_size: u32 = constants.RESPONSE_QUEUE_SIZE,
        buffer_size: u32 = constants.BUFFER_SIZE,
        buffer_pool_size: u32 = constants.BUFFER_POOL_SIZE,
        max_fixed_files: u32 = constants.MAX_FIXED_FILES,
        max_path_length: u32 = constants.MAX_PATH_LENGTH,
        idle_timeout_ms: u64 = constants.IDLE_TIMEOUT_MS,
        write_timeout_ms: u64 = constants.WRITE_TIMEOUT_MS,
        fiber_stack_size_kb: u16 = 256,
        max_connections: u32 = constants.MAX_CONNECTIONS,
        io_cpu: ?u6 = null,
        log_cpu: ?u6 = null,
    };

    pub const InitConfig = struct {
        max_connections: u32 = constants.MAX_CONNECTIONS,
        buffer_pool_size: u32 = constants.BUFFER_POOL_SIZE,
        large_pool_capacity: u32 = 64,
    };

    pub const ConfigKey = enum {
        max_header_buffer_size,
        max_response_buffer_size,
        max_cqes_batch,
        ring_entries,
        task_queue_size,
        response_queue_size,
        buffer_size,
        buffer_pool_size,
        max_fixed_files,
        max_path_length,
        idle_timeout_ms,
        write_timeout_ms,
        max_connections,
        io_cpu,
        log_cpu,
    };

    pub fn config(self: *Self, key: ConfigKey, value: i32) void {
        switch (key) {
            .max_header_buffer_size => self.cfg.max_header_buffer_size = @intCast(value),
            .max_response_buffer_size => self.cfg.max_response_buffer_size = @intCast(value),
            .max_cqes_batch => self.cfg.max_cqes_batch = @intCast(value),
            .ring_entries => self.cfg.ring_entries = @intCast(value),
            .task_queue_size => self.cfg.task_queue_size = @intCast(value),
            .response_queue_size => self.cfg.response_queue_size = @intCast(value),
            .buffer_size => self.cfg.buffer_size = @intCast(value),
            .buffer_pool_size => self.cfg.buffer_pool_size = @intCast(value),
            .max_fixed_files => self.cfg.max_fixed_files = @intCast(value),
            .max_path_length => self.cfg.max_path_length = @intCast(value),
            .idle_timeout_ms => self.cfg.idle_timeout_ms = @intCast(value),
            .write_timeout_ms => self.cfg.write_timeout_ms = @intCast(value),
            .max_connections => self.cfg.max_connections = @intCast(value),
            .io_cpu => self.cfg.io_cpu = if (value < 0) null else @intCast(value),
            .log_cpu => self.cfg.log_cpu = if (value < 0) null else @intCast(value),
        }
    }

    pub fn init(allocator: Allocator, io: std.Io, listen_addr: []const u8, app_ctx: ?*anyopaque, fiber_stack_size_kb: u16, tls_auth: ?TlsAuth, init_cfg: InitConfig) !Self {
        const colon = std.mem.indexOfScalar(u8, listen_addr, ':') orelse return error.InvalidListenAddress;
        const ip_str = listen_addr[0..colon];
        const port_str = listen_addr[colon + 1 ..];
        const port = try std.fmt.parseInt(u16, port_str, 10);
        const ip_addr = try parseIpv4(ip_str);

        const raw_fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
        const fd = try listenSocketFd(raw_fd);
        errdefer _ = linux.close(fd);

        var reuse: i32 = 1;
        const rc = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @as([*]const u8, @ptrCast(&reuse)), @sizeOf(i32));
        if (rc != 0) return error.SetSockOptFailed;

        var addr_in = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = @byteSwap(port),
            .addr = ip_addr,
            .zero = [_]u8{0} ** 8,
        };
        const len: u32 = @intCast(@sizeOf(linux.sockaddr.in));
        const rc_bind = linux.bind(fd, @ptrCast(&addr_in), len);
        if (rc_bind != 0) return error.BindFailed;
        const rc_listen = linux.listen(fd, 1024);
        if (rc_listen != 0) return error.ListenFailed;

        var params = std.mem.zeroes(linux.io_uring_params);
        // 修改原因：示例会把 server 交给专用 IO 线程 run，SINGLE_ISSUER 会让 Linux 返回 InvalidThread。
        // 同时 Zig 0.16 的 IoUring.init_params 要求 sq_entries/cq_entries 由 entries 参数推导，不能手动预填。
        var ring = linux.IoUring.init_params(RING_ENTRIES, &params) catch blk: {
            break :blk try linux.IoUring.init(RING_ENTRIES, 0);
        };
        errdefer ring.deinit();

        var tls_config: if (build_options.tls_enabled) ?TlsConfig else void = if (build_options.tls_enabled) null else {};
        if (build_options.tls_enabled) {
            if (tls_auth) |auth| {
                tls_config = try TlsConfig.init(allocator, io, auth.cert_path, auth.key_path, true);
            }
        }
        errdefer if (build_options.tls_enabled) {
            if (tls_config) |*tc| tc.deinit();
        };

        const mw_store = MiddlewareStore{
            .global = std.ArrayList(Middleware).empty,
            .precise = std.StringHashMap(std.ArrayList(Middleware)).init(allocator),
            .wildcard = std.ArrayList(WildcardEntry).empty,
            .has_global = false,
        };
        const respond_mw_store = MiddlewareStore{
            .global = std.ArrayList(Middleware).empty,
            .precise = std.StringHashMap(std.ArrayList(Middleware)).init(allocator),
            .wildcard = std.ArrayList(WildcardEntry).empty,
            .has_global = false,
        };

        var use_ff = false;
        var ff_freelist = try std.ArrayList(u16).initCapacity(allocator, MAX_FIXED_FILES);
        errdefer ff_freelist.deinit(allocator);
        if (ring.register_files_sparse(MAX_FIXED_FILES)) {
            use_ff = true;
        } else |_| {}

        var bp = try BufferPool.init(allocator, init_cfg.buffer_pool_size);
        errdefer bp.deinit();

        const kb = if (fiber_stack_size_kb == 0) @as(u16, 256) else fiber_stack_size_kb;
        const cfg = Config{ .fiber_stack_size_kb = kb, .max_connections = init_cfg.max_connections, .buffer_pool_size = init_cfg.buffer_pool_size };
        const stack_size = @as(u32, @intCast(kb)) * 1024;
        const shared_stack = try allocator.alloc(u8, stack_size);
        errdefer allocator.free(shared_stack);

        var io_registry = IORegistry.init(allocator);
        errdefer io_registry.deinit();

        const ns_ip = readResolvConfNameserver() catch @as(u32, 0x0a60000a);
        const dns_resolver = try allocator.create(DnsResolver);
        errdefer allocator.destroy(dns_resolver);
        dns_resolver.* = try DnsResolver.init(allocator, io, ns_ip);
        errdefer dns_resolver.deinit();

        var conn_pool = try StackPool(StackSlot).init(allocator, cfg.max_connections);
        errdefer conn_pool.deinit(allocator);
        conn_pool.warmup();

        var large_pool_cap = init_cfg.large_pool_capacity;
        if (large_pool_cap == 0) large_pool_cap = 64;
        var large_pool = try LargeBufferPool(64).init(allocator, large_pool_cap);
        errdefer large_pool.deinit(allocator);

        var user_map = std.AutoHashMap(u64, u32).init(allocator);
        errdefer user_map.deinit();

        var server = Self{
            .allocator = allocator,
            .io = io,
            .ring = ring,
            .listen_fd = fd,
            .next_conn_id = 1,
            .connections = std.AutoHashMap(u64, Connection).init(allocator),
            .pool = conn_pool,
            .user_map = user_map,
            .deferred_hooks = std.ArrayList(*const fn (self: *Self, node: *DeferredNode) void).empty,
            .tick_hooks = std.ArrayList(*const fn (self: *Self) void).empty,
            .io_registry = io_registry,
            .rs = undefined,
            .next_user_data = 1,
            .app_ctx = app_ctx,
            .buffer_pool = bp,
            .large_pool = large_pool,
            .use_fixed_files = use_ff,
            .fixed_file_freelist = ff_freelist,
            .fixed_file_next = 0,
            .ws_server = WsServer.init(allocator, ws_handler.wsSendFn),
            .tcp_server = TcpServer.init(allocator, tcp_handler.tcpSendFn),
            .middlewares = mw_store,
            .respond_middlewares = respond_mw_store,
            .handlers = std.StringHashMap(Handler).init(allocator),
            .param_routes = std.ArrayList(http_routing.ParamRoute).empty,
            .cfg = cfg,
            .io_pinned = false,
            .next = null,
            .submit_registry = SubmitQueueRegistry.init(allocator),
            .http_ctx_pool = std.heap.MemoryPool(HttpTaskCtx).empty,
            .ws_ctx_pool = std.heap.MemoryPool(WsTaskCtx).empty,
            .shared_fiber_stack = shared_stack,
            .dns_resolver = dns_resolver,
            .ttl_scan_out = std.ArrayList(u32).initCapacity(allocator, 512) catch @panic("OOM"),
            .pending_writes = std.ArrayList(u64).empty,
        };
        if (build_options.tls_enabled) {
            server.tls_config = tls_config;
        }
        server.rs = RingShared.bind(&server.ring, &server.io_registry);
        // Register the DNS resolver on its final (heap) address with the
        // server's stable RingShared. Doing this inside DnsResolver.init would
        // store a dangling pointer because init returns by value.
        try server.dns_resolver.register(server.rs);

        try server.buffer_pool.provideAllReads(&server.ring);

        // 预分配内存池，消除冷启动时的动态分配
        try server.http_ctx_pool.addCapacity(allocator, 64);
        try server.ws_ctx_pool.addCapacity(allocator, 64);

        server.logger = try AsyncLogger.init(allocator, server.cfg.log_cpu);
        errdefer if (server.logger) |l| l.deinit();

        return server;
    }

    pub fn deinit(self: *Self) void {
        if (self.next) |*n| n.deinit();

        self.rs.invoke.drain(self.allocator);

        // Send WebSocket close frames before tearing down the ring,
        // connections, and pool. closeAllActive calls sendWsFrame which
        // requires self.ring (io_uring), self.connections (hashmap lookup),
        // and self.pool (slot access) to still be alive.
        self.ws_server.closeAllActive();
        self.ws_server.deinit();
        self.tcp_server.deinit();
        if (self.udp_server) |*us| us.deinit();

        // Clean up all connections: free resources + release pool slots
        {
            var it = self.connections.iterator();
            while (it.next()) |entry| {
                const conn = entry.value_ptr;
                if (build_options.tls_enabled) {
                    if (conn.tls) |tls_stream| {
                        tls_stream.free();
                        self.allocator.destroy(tls_stream);
                    }
                    if (conn.tls_ciphertext) |buf| {
                        self.allocator.free(buf);
                        conn.tls_ciphertext = null;
                    }
                }
                if (conn.write_body) |b| self.allocator.free(b);
                if (conn.ws_token) |t| self.allocator.free(t);
                if (conn.accum_buf) |buf| self.allocator.free(buf);
                self.drainWsWriteQueue(conn);
                if (conn.response_buf) |buf| self.buffer_pool.freeTieredWriteBuf(buf, conn.response_buf_tier);
                // Release large_pool buffer if connection still holds one
                if (conn.pool_idx != 0xFFFFFFFF) {
                    const slot = &self.pool.slots[conn.pool_idx];
                    if (slot.line3.pending_buffer_ptr != 0) {
                        const hw = sticker.httpWork(slot);
                        const saved: []u8 = @as([*]u8, @ptrFromInt(slot.line3.pending_buffer_ptr))[0..hw.header_len];
                        // 修改原因：服务器退出时也要释放等待 body 的跨分片 header 副本，避免 deinit 路径泄漏。
                        self.allocator.free(saved);
                        slot.line3.pending_buffer_ptr = 0;
                        hw.header_len = 0;
                    }
                    if (slot.line3.large_buf_ptr != 0) {
                        const buf: []u8 = @as([*]u8, @ptrFromInt(slot.line3.large_buf_ptr))[0..slot.line3.large_buf_len];
                        self.large_pool.release(buf);
                        slot.line3.large_buf_ptr = 0;
                    }
                }
                _ = linux.close(conn.fd);
                if (conn.pool_idx != 0xFFFFFFFF) {
                    sticker.slotFree(&self.pool, conn.pool_idx);
                }
            }
        }
        _ = linux.close(self.listen_fd);
        if (self.tcp_listen_fd > 0) _ = linux.close(self.tcp_listen_fd);
        self.connections.deinit();
        self.pool.deinit(self.allocator);
        self.ttl_scan_out.deinit(self.allocator);
        if (self.user_map) |*um| um.deinit();
        self.deferred_hooks.deinit(self.allocator);
        self.tick_hooks.deinit(self.allocator);
        // 修改原因：DnsResolver.deinit 会从 io_registry 中移除 dns_ud，必须早于 io_registry.deinit，否则 ReleaseFast 退出会访问已释放的 hashmap。
        self.dns_resolver.deinit();
        self.allocator.destroy(self.dns_resolver);
        self.io_registry.deinit();
        self.submit_registry.deinit();
        self.ring.deinit();
        self.buffer_pool.deinit();
        self.large_pool.deinit(self.allocator);
        self.fixed_file_freelist.deinit(self.allocator);
        self.middlewares.deinit(self.allocator);
        self.respond_middlewares.deinit(self.allocator);
        {
            var handler_it = self.handlers.iterator();
            while (handler_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
            }
        }
        self.handlers.deinit();
        {
            for (self.param_routes.items) |*pr| {
                http_routing.freeSegments(self.allocator, pr.segments);
                self.allocator.free(pr.method);
            }
            self.param_routes.deinit(self.allocator);
        }
        self.http_ctx_pool.deinit(self.allocator);
        self.ws_ctx_pool.deinit(self.allocator);
        self.allocator.free(self.shared_fiber_stack);
        self.pending_writes.deinit(self.allocator);
        if (build_options.tls_enabled) {
            if (self.tls_config) |*tc| tc.deinit();
        }
        if (self.logger) |l| l.deinit();
        self.cfg = undefined;
    }

    /// 注册中间件，在 fiber 中执行。可用 Next.submit() 卸 CPU 重活。
    pub fn use(self: *Self, pattern: []const u8, middleware: Middleware) !void {
        return http_routing.use(self, pattern, middleware);
    }

    /// 注册快速中间件，在 IO 线程内联执行。⚠️ 不可阻塞。
    pub fn useThenRespondImmediately(self: *Self, pattern: []const u8, middleware: Middleware) !void {
        return http_routing.useThenRespondImmediately(self, pattern, middleware);
    }

    fn ensureNext(self: *Self) void {
        http_routing.ensureNext(self);
    }

    fn register(self: *Self, method: []const u8, path: []const u8, handler: Handler) !void {
        return http_routing.register(self, method, path, handler);
    }

    pub fn GET(self: *Self, path: []const u8, handler: Handler) !void {
        return http_routing.GET(self, path, handler);
    }

    pub fn POST(self: *Self, path: []const u8, handler: Handler) !void {
        return http_routing.POST(self, path, handler);
    }

    pub fn PUT(self: *Self, path: []const u8, handler: Handler) !void {
        return http_routing.PUT(self, path, handler);
    }

    pub fn PATCH(self: *Self, path: []const u8, handler: Handler) !void {
        return http_routing.PATCH(self, path, handler);
    }

    pub fn DELETE(self: *Self, path: []const u8, handler: Handler) !void {
        return http_routing.DELETE(self, path, handler);
    }

    pub fn ws(self: *Self, path: []const u8, handler: WsHandler) !void {
        return http_routing.ws(self, path, handler);
    }

    pub fn tcp(self: *Self, listen_addr: []const u8, handler: TcpHandler) !void {
        const colon = std.mem.indexOfScalar(u8, listen_addr, ':') orelse return error.InvalidListenAddress;
        const ip_str = listen_addr[0..colon];
        const port_str = listen_addr[colon + 1 ..];
        const port = try std.fmt.parseInt(u16, port_str, 10);
        const ip_addr = try helpers.parseIpv4(ip_str);

        const raw_fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
        const fd: i32 = @intCast(raw_fd);
        errdefer _ = linux.close(fd);

        var reuse: i32 = 1;
        const rc = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @as([*]const u8, @ptrCast(&reuse)), @sizeOf(i32));
        if (rc != 0) return error.SetSockOptFailed;

        var addr_in = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = @byteSwap(port),
            .addr = ip_addr,
            .zero = [_]u8{0} ** 8,
        };
        const len: u32 = @intCast(@sizeOf(linux.sockaddr.in));
        if (linux.bind(fd, @ptrCast(&addr_in), len) != 0) return error.BindFailed;
        if (linux.listen(fd, 1024) != 0) return error.ListenFailed;

        self.tcp_listen_fd = fd;
        self.tcp_server.handler = handler;
        self.tcp_server.ctx = self;
    }

    pub fn udp(self: *Self, bind_addr: []const u8, handler: UdpHandler) !void {
        var us = try UdpServer.init(self.allocator, self.rs, bind_addr);
        us.handler = handler;
        us.ctx = self;
        us.sync = false;
        self.udp_server = us;
        try self.udp_server.?.register();
    }

    pub fn udp4Sync(self: *Self, bind_addr: []const u8, handler: UdpHandler) !void {
        var us = try UdpServer.init(self.allocator, self.rs, bind_addr);
        us.handler = handler;
        us.ctx = self;
        us.sync = true;
        self.udp_server = us;
        try self.udp_server.?.register();
    }

    pub fn invokeOnIoThread(
        self: *Self,
        comptime T: type,
        ctx: T,
        comptime execFn: fn (allocator: Allocator, ctx_ptr: *T) void,
    ) !void {
        return hook_system.invokeOnIoThread(self, T, ctx, execFn);
    }

    pub fn nextUserData(self: *Self) u64 {
        return connection_mgr.nextUserData(self);
    }

    fn nextConnId(self: *Self) u64 {
        return tcp_accept.nextConnId(self);
    }

    pub fn allocFixedIndex(self: *Self) !u16 {
        return tcp_accept.allocFixedIndex(self);
    }

    pub fn freeFixedIndex(self: *Self, idx: u16) void {
        tcp_accept.freeFixedIndex(self, idx);
    }

    pub fn submitAccept(self: *Self) !void {
        if (self.accept_outstanding) return;
        self.accept_addrlen = @sizeOf(linux.sockaddr);
        _ = try self.ring.accept(ACCEPT_USER_DATA, @intCast(self.listen_fd), &self.accept_addr, &self.accept_addrlen, linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC);
        self.accept_stalled = false;
        self.accept_outstanding = true;
    }

    pub fn submitTcpAccept(self: *Self) !void {
        if (!self.tcp_server.hasHandler()) return;
        if (self.tcp_accept_outstanding) return;
        self.tcp_accept_addrlen = @sizeOf(linux.sockaddr);
        _ = try self.ring.accept(constants.TCP_ACCEPT_USER_DATA, @intCast(self.tcp_listen_fd), &self.tcp_accept_addr, &self.tcp_accept_addrlen, linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC);
        self.tcp_accept_stalled = false;
        self.tcp_accept_outstanding = true;
    }

    pub fn submitRead(self: *Self, conn_id: u64, conn: *Connection) !void {
        return tcp_read.submitRead(self, conn_id, conn);
    }

    pub fn submitWrite(self: *Self, conn_id: u64, conn: *Connection) !void {
        return tcp_write.submitWrite(self, conn_id, conn);
    }

    pub fn submitBodyRead(self: *Self, conn: *Connection, large_buf: []u8, slot: *StackSlot) !void {
        return http_body.submitBodyRead(self, conn, large_buf, slot);
    }

    pub fn onReadComplete(self: *Self, conn_id: u64, res: i32, user_data: u64, cqe_flags: u32) void {
        tcp_read.onReadComplete(self, conn_id, res, user_data, cqe_flags);
    }

    pub fn onBodyChunk(self: *Self, conn_id: u64, res: i32) void {
        http_body.onBodyChunk(self, conn_id, res);
    }

    pub fn onStreamRead(self: *Self, conn_id: u64, res: i32, user_data: u64, cqe_flags: u32) void {
        http_body.onStreamRead(self, conn_id, res, user_data, cqe_flags);
    }

    pub fn processBodyRequest(self: *Self, conn_id: u64, conn: *Connection, body_buf: []u8) void {
        http_routing.processBodyRequest(self, conn_id, conn, body_buf);
    }

    pub fn getConn(self: *Self, conn_id: u64) ?*Connection {
        return connection_mgr.getConn(self, conn_id);
    }

    pub fn closeConn(self: *Self, conn_id: u64, fd: i32) void {
        connection_mgr.closeConn(self, conn_id, fd);
    }

    pub fn onAcceptComplete(self: *Self, res: i32, user_data: u64) void {
        tcp_accept.onAcceptComplete(self, res, user_data);
    }

    pub fn onWriteComplete(self: *Self, conn_id: u64, res: i32, user_data: u64) void {
        tcp_write.onWriteComplete(self, conn_id, res, user_data);
    }

    pub fn getConnToken(self: *Self, conn_id: u64) ?[]const u8 {
        return connection_mgr.getConnToken(self, conn_id);
    }

    pub fn initTlsStream(self: *Self, conn: *Connection) !void {
        if (build_options.tls_enabled) {
            if (self.tls_config) |*tc| {
                const tls_stream = try self.allocator.create(TlsStream);
                errdefer self.allocator.destroy(tls_stream);
                tls_stream.* = try TlsStream.new(tc);
                conn.tls = tls_stream;
            }
        }
    }

    pub fn registerSubmitQueue(self: *Self, queue: *uring_submit.SubmitQueue) !void {
        try self.submit_registry.register(queue);
    }

    pub fn initPool4NextSubmit(self: *Self, worker_count: u8) !void {
        self.ensureNext();
        try self.next.?.initPool4NextSubmit(worker_count);
    }

    pub fn stop(self: *Self) void {
        event_loop.stop(self);
    }

    pub fn installSigterm(self: *Self) void {
        event_loop.installSigterm(self);
    }

    pub fn run(self: *Self) !void {
        return event_loop.run(self);
    }

    fn drainPendingResumes(self: *Self) void {
        event_loop.drainPendingResumes(self);
    }

    fn dispatchCqes(self: *Self, cqes: []linux.io_uring_cqe, n: usize) void {
        event_loop.dispatchCqes(self, cqes, n);
    }

    fn drainNextTasks(self: *Self) void {
        event_loop.drainNextTasks(self);
    }

    fn executeNext(req: *const Item) void {
        event_loop.executeNext(req);
    }

    fn submitIdleTimeout(self: *Self) !void {
        return event_loop.submitIdleTimeout(self);
    }

    fn ttlScanTick(self: *Self) void {
        event_loop.ttlScanTick(self);
    }

    pub fn ensureWriteBuf(self: *Self, conn: *Connection, min_size: usize) bool {
        return http_response.ensureWriteBuf(self, conn, min_size);
    }

    pub fn respond(self: *Self, conn: *Connection, status: u16, text: []const u8) void {
        http_response.respond(self, conn, status, text);
    }

    pub fn respondWithHeader(self: *Self, conn: *Connection, status: u16, text: []const u8, extra_headers: []const u8) void {
        http_response.respondWithHeader(self, conn, status, text, extra_headers);
    }

    pub fn respondJson(self: *Self, conn: *Connection, status: u16, json_body: []const u8) void {
        http_response.respondJson(self, conn, status, json_body);
    }

    pub fn respondError(self: *Self, conn: *Connection) void {
        http_response.respondError(self, conn);
    }

    pub fn respondZeroCopy(self: *Self, conn: *Connection, status: u16, content_type: Context.ContentType, body: []u8, extra_headers: []const u8) void {
        http_response.respondZeroCopy(self, conn, status, content_type, body, extra_headers);
    }

    pub fn sendDeferredResponse(self: *Self, conn_id: u64, status: u16, ct: Context.ContentType, body: []u8) void {
        hook_system.sendDeferredResponse(self, conn_id, status, ct, body);
    }

    pub fn addHookDeferred(self: *Self, hook: *const fn (self_: *Self, node: *DeferredNode) void) !void {
        return hook_system.addHookDeferred(self, hook);
    }

    pub fn addHookTick(self: *Self, hook: *const fn (self_: *Self) void) !void {
        return hook_system.addHookTick(self, hook);
    }

    fn drainTick(self: *Self) void {
        event_loop.drainTick(self);
    }

    pub fn tryWsUpgrade(self: *Self, conn_id: u64, conn: *Connection, path: []const u8, data: []const u8, bid: u16) void {
        ws_handler.tryWsUpgrade(self, conn_id, conn, path, data, bid);
    }

    pub fn onWsFrame(self: *Self, conn_id: u64, res: i32, user_data: u64, cqe_flags: u32) void {
        ws_handler.onWsFrame(self, conn_id, res, user_data, cqe_flags);
    }

    pub fn onWsWriteComplete(self: *Self, conn_id: u64, res: i32, user_data: u64) void {
        ws_handler.onWsWriteComplete(self, conn_id, res, user_data);
    }

    fn submitWsWrite(self: *Self, conn_id: u64, conn: *Connection, opcode: Opcode, payload: []const u8) !void {
        return ws_handler.submitWsWrite(self, conn_id, conn, opcode, payload);
    }

    fn flushWsWriteQueue(self: *Self, conn_id: u64, conn: *Connection) void {
        ws_handler.flushWsWriteQueue(self, conn_id, conn);
    }

    pub fn drainWsWriteQueue(self: *Self, conn: *Connection) void {
        ws_handler.drainWsWriteQueue(self, conn);
    }

    pub fn onTcpAcceptComplete(self: *Self, res: i32) void {
        tcp_handler.onTcpAcceptComplete(self, res);
    }

    pub fn onRawData(self: *Self, conn_id: u64, res: i32, user_data: u64, cqe_flags: u32) void {
        tcp_handler.onRawData(self, conn_id, res, user_data, cqe_flags);
    }

    pub fn onTcpWriteComplete(self: *Self, conn_id: u64, res: i32, user_data: u64) void {
        tcp_handler.onTcpWriteComplete(self, conn_id, res, user_data);
    }

    fn maxWriteRetries(total: usize) u8 {
        return http_response.maxWriteRetries(total);
    }
};

const statusText = http_response.statusText;

pub const submitBodyRead = http_body.submitBodyRead;
pub const onBodyChunk = http_body.onBodyChunk;
pub const onStreamRead = http_body.onStreamRead;

test "AsyncServer socket fd conversion checks errno before casting" {
    const failed: usize = @bitCast(@as(isize, -1));
    try std.testing.expectError(error.SocketCreationFailed, listenSocketFd(failed));
    try std.testing.expectEqual(@as(i32, 5), try listenSocketFd(5));
}
