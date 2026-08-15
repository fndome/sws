const std = @import("std");
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");

const RingB = @import("ring.zig").RingB;
const RingSharedClient = @import("../shared/tcp_stream.zig").RingSharedClient;
const TinyCache = @import("tiny_cache.zig").TinyCache;
const Pipe = @import("../next/pipe.zig").Pipe;
const TlsConfig = if (build_options.tls_enabled) @import("../tls/tls.zig").TlsConfig else struct {};
const Fiber = @import("../next/fiber.zig").Fiber;

pub const Response = struct {
    status: u16,
    body: []u8,
    allocator: Allocator,

    pub fn deinit(self: *Response) void {
        // Guard: a zero-length body may be a compile-time constant from the
        // makeErrorResponse triple-fallback path. Only free heap-allocated bodies.
        if (self.body.len > 0) self.allocator.free(self.body);
    }
};

const ParsedUrl = struct {
    host: []const u8,
    authority: []const u8,
    port: u16,
    path: []const u8,
    tls: bool,
};

fn isHttpTokenChar(ch: u8) bool {
    const token_symbols = "!#$%&'*+-.^_`|~";
    return (ch >= 'A' and ch <= 'Z') or
        (ch >= 'a' and ch <= 'z') or
        (ch >= '0' and ch <= '9') or
        std.mem.indexOfScalar(u8, token_symbols, ch) != null;
}

fn isCtlOrSpace(ch: u8) bool {
    return ch <= ' ' or ch == 0x7f;
}

fn validateMethod(method: []const u8) !void {
    if (method.len == 0) return error.InvalidMethod;
    for (method) |ch| {
        if (!isHttpTokenChar(ch)) return error.InvalidMethod;
    }
}

fn validateUrlHost(host: []const u8) !void {
    if (host.len == 0) return error.InvalidUrl;
    for (host) |ch| {
        if (isCtlOrSpace(ch)) return error.InvalidUrl;
        // 修改原因：当前客户端不解析 URL userinfo，@ 出现在 authority 中不能被当成 host 字符写入 Host 头。
        if (ch == '@') return error.InvalidUrl;
    }
}

fn validateRequestTarget(path: []const u8) !void {
    if (path.len == 0) return error.InvalidUrl;
    for (path) |ch| {
        if (isCtlOrSpace(ch)) return error.InvalidUrl;
    }
}

fn firstPathOrQueryIndex(rest: []const u8) ?usize {
    const slash = std.mem.indexOfScalar(u8, rest, '/');
    const query = std.mem.indexOfScalar(u8, rest, '?');
    const fragment = std.mem.indexOfScalar(u8, rest, '#');
    var best: ?usize = null;
    if (slash) |s| best = s;
    if (query) |q| {
        best = if (best) |b| @min(b, q) else q;
    }
    if (fragment) |f| {
        best = if (best) |b| @min(b, f) else f;
    }
    return best;
}

fn stripFragmentTarget(target: []const u8) []const u8 {
    // 修改原因：URL fragment 只在客户端本地使用，不能出现在 HTTP request-target 中。
    const no_fragment = target[0..(std.mem.indexOfScalar(u8, target, '#') orelse target.len)];
    if (no_fragment.len == 0) return "/";
    return no_fragment;
}

fn parseUrl(allocator: Allocator, url: []const u8) !ParsedUrl {
    var rest = url;
    // 修改原因：URL scheme 大小写不敏感，HTTP://host 这类合法 URL 不能被误判成坏 host/port。
    const is_tls = if (std.ascii.startsWithIgnoreCase(rest, "https://")) blk: {
        rest = rest["https://".len..];
        break :blk true;
    } else if (std.ascii.startsWithIgnoreCase(rest, "http://")) blk: {
        rest = rest["http://".len..];
        break :blk false;
    } else false;
    // 修改原因：合法 URL 可以省略路径但直接带 query，例如 http://host?x=1；此时也必须从 host 中切出去。
    const path_start = firstPathOrQueryIndex(rest);
    const host_port = if (path_start) |p| rest[0..p] else rest;
    const path = if (path_start) |p| stripFragmentTarget(rest[p..]) else "/";
    const colon = std.mem.lastIndexOfScalar(u8, host_port, ':');
    const host = if (colon) |c| host_port[0..c] else host_port;
    if (std.mem.indexOfScalar(u8, host, ':') != null) return error.InvalidUrl;
    // 修改原因：host 和 request-target 会直接拼进请求行/Host 头，必须拒绝 CR/LF/空白控制字符，避免请求头注入。
    // 当前客户端只支持普通 host[:port] authority，多冒号或 IPv6 bracket 形式不能靠 lastIndex 静默解析。
    try validateUrlHost(host);
    try validateRequestTarget(path);
    const port: u16 = if (colon) |c| blk: {
        const port_text = host_port[c + 1 ..];
        // 修改原因：显式端口写错时不能静默回退到 80，否则请求会发到错误上游。
        if (port_text.len == 0) return error.InvalidUrl;
        break :blk std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidUrl;
    } else if (is_tls) 443 else 80;
    const host_dup = try allocator.dupe(u8, host);
    errdefer allocator.free(host_dup);
    // 修改原因：HTTP/1.1 Host 必须保留显式端口；连接用 host，Host 头用 authority。
    const authority_dup = try allocator.dupe(u8, host_port);
    return .{ .host = host_dup, .authority = authority_dup, .port = port, .path = path, .tls = is_tls };
}

fn parseResponse(allocator: Allocator, data: []const u8) !Response {
    return parseResponseForMethod(allocator, data, "GET");
}

fn parseResponseForMethod(allocator: Allocator, data: []const u8, method: []const u8) !Response {
    // 修改原因：HEAD 响应的 Content-Length 只描述假想正文，解析阶段必须沿用请求方法，否则会把合法 HEAD 响应误判成未读完整。
    const total_len = (try responseCompleteLenForMethod(data, method)) orelse return error.IncompleteResponse;
    const bounds = findHeaderEnd(data[0..total_len]) orelse return error.InvalidResponse;
    const first_line_end = std.mem.indexOfScalar(u8, data, '\r') orelse
        std.mem.indexOfScalar(u8, data, '\n') orelse
        return error.InvalidResponse;
    const status = try parseStatusCode(data[0..first_line_end]);
    const body_start = bounds.header_end + bounds.sep_len;
    const body = try allocator.dupe(u8, data[body_start..total_len]);
    return .{ .status = status, .body = body, .allocator = allocator };
}

const HeaderBounds = struct {
    header_end: usize,
    sep_len: usize,
};

fn findHeaderEnd(data: []const u8) ?HeaderBounds {
    if (std.mem.indexOf(u8, data, "\r\n\r\n")) |pos| {
        return .{ .header_end = pos, .sep_len = 4 };
    }
    if (std.mem.indexOf(u8, data, "\n\n")) |pos| {
        return .{ .header_end = pos, .sep_len = 2 };
    }
    return null;
}

fn getHeaderValue(headers: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, "\r");
        if (line.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(line, name)) {
            const after = line[name.len..];
            if (after.len > 0 and after[0] == ':') {
                return std.mem.trim(u8, after[1..], " \t\r\n");
            }
        }
    }
    return null;
}

fn getSingleHeaderValue(headers: []const u8, name: []const u8) !?[]const u8 {
    var seen: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, "\r");
        if (line.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(line, name)) {
            const after = line[name.len..];
            if (after.len > 0 and after[0] == ':') {
                // 修改原因：响应 Content-Length 重复会让 keep-alive 响应边界不唯一，客户端不能只信第一个值。
                if (seen != null) return error.DuplicateHeader;
                seen = std.mem.trim(u8, after[1..], " \t\r\n");
            }
        }
    }
    return seen;
}

fn headerValueHasToken(value: []const u8, token: []const u8) bool {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}

fn responseHeaderHasToken(headers: []const u8, name: []const u8, token: []const u8) bool {
    var lines = std.mem.splitScalar(u8, headers, '\n');
    _ = lines.next() orelse return false;
    while (lines.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, "\r");
        if (std.ascii.startsWithIgnoreCase(line, name)) {
            const after = line[name.len..];
            if (after.len > 0 and after[0] == ':' and headerValueHasToken(after[1..], token)) return true;
        }
    }
    return false;
}

fn responseWantsClose(data: []const u8) bool {
    const bounds = findHeaderEnd(data) orelse return false;
    const headers = data[0..bounds.header_end];
    // 修改原因：上游声明 Connection: close 时，该 TCP 连接不能放回 keep-alive 池等待复用。
    return responseHeaderHasToken(headers, "Connection", "close");
}

fn validateResponseHeaderLines(headers: []const u8) !void {
    var lines = std.mem.splitScalar(u8, headers, '\n');
    _ = lines.next() orelse return error.InvalidResponse;
    while (lines.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, "\r");
        // 修改原因：响应头行会参与 keep-alive 边界判断，内嵌 CR、缺冒号或非法字段名都不能被静默忽略。
        if (line.len == 0 or std.mem.indexOfScalar(u8, line, '\r') != null) return error.InvalidResponse;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidResponse;
        const field_name = line[0..colon];
        if (field_name.len == 0) return error.InvalidResponse;
        for (field_name) |ch| {
            if (!isHttpTokenChar(ch)) return error.InvalidResponse;
        }
    }
}

fn parseStatusCode(first_line: []const u8) !u16 {
    var parts = std.mem.splitScalar(u8, first_line, ' ');
    const version = parts.next() orelse return error.InvalidResponse;
    const code = parts.next() orelse return error.InvalidResponse;
    // 修改原因：上游状态行坏掉时不能伪装成 500 正常响应；调用方需要知道这是非法 HTTP 响应。
    if (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0")) return error.InvalidResponse;
    // 修改原因：HTTP status-code 必须正好 3 位数字，parseInt 会把 0200 这类畸形码放宽成 200。
    if (code.len != 3) return error.InvalidResponse;
    for (code) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidResponse;
    }
    const status = std.fmt.parseInt(u16, code, 10) catch return error.InvalidResponse;
    // 修改原因：HTTP status-code 只定义 100-599；放行 6xx-9xx 会把上游坏响应当成正常响应边界复用连接。
    if (status < 100 or status > 599) return error.InvalidResponse;
    return status;
}

fn responseMayOmitContentLength(status: u16) bool {
    // 修改原因：205 Reset Content 也禁止响应 body，不能按普通 2xx 去等待 Content-Length 正文。
    return status == 204 or status == 205 or status == 304;
}

fn methodForbidsResponseBody(method: []const u8) bool {
    return std.ascii.eqlIgnoreCase(method, "HEAD");
}

fn parseResponseContentLength(value: []const u8) !usize {
    // 修改原因：响应 Content-Length 也是协议边界，parseInt 会接受前导零这类非规范值并放宽响应边界判断。
    if (value.len == 0) return error.InvalidContentLength;
    if (value.len > 1 and value[0] == '0') return error.InvalidContentLength;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidContentLength;
    }
    return std.fmt.parseInt(usize, value, 10) catch error.InvalidContentLength;
}

fn responseCompleteLen(data: []const u8) !?usize {
    return responseCompleteLenForMethod(data, "GET");
}

fn responseCompleteLenForMethod(data: []const u8, method: []const u8) !?usize {
    const bounds = findHeaderEnd(data) orelse return null;
    const headers = data[0..bounds.header_end];
    try validateResponseHeaderLines(headers);
    const first_line_end = std.mem.indexOfScalar(u8, headers, '\r') orelse
        std.mem.indexOfScalar(u8, headers, '\n') orelse
        return error.InvalidResponse;
    const status = try parseStatusCode(headers[0..first_line_end]);
    // 修改原因：客户端还没有实现 1xx interim response 折叠，不能把 100 Continue 当成最终响应返回。
    if (status < 200) return error.InformationalResponseUnsupported;
    if (getHeaderValue(headers, "Transfer-Encoding")) |_| {
        // 修改原因：当前客户端只按 Content-Length 做响应边界，不会解码任何 Transfer-Encoding。
        return error.TransferEncodingUnsupported;
    }
    const content_len_header = try getSingleHeaderValue(headers, "Content-Length");
    const body_forbidden = responseMayOmitContentLength(status) or methodForbidsResponseBody(method);
    const content_len = if (body_forbidden) blk: {
        if (content_len_header) |value| {
            const declared_len = try parseResponseContentLength(value);
            // 修改原因：204/205 没有响应 body，非 0 Content-Length 不能驱动读取正文或返回伪 body。
            if ((status == 204 or status == 205) and declared_len != 0) return error.InvalidResponse;
        }
        // 修改原因：HEAD/304/205 的 Content-Length 不能作为当前响应读取边界。
        break :blk 0;
    } else if (content_len_header) |value| blk: {
        break :blk try parseResponseContentLength(value);
    } else {
        // 修改原因：200 等可带 body 响应缺少长度时无法在 keep-alive 连接上确定边界，不能按空 body 复用连接。
        return error.MissingContentLength;
    };
    // 修改原因：上游 keep-alive 时连接不会 EOF，必须按 Content-Length 判断响应边界。
    const header_total = std.math.add(usize, bounds.header_end, bounds.sep_len) catch return error.InvalidResponse;
    const total = std.math.add(usize, header_total, content_len) catch return error.InvalidResponse;
    if (data.len < total) return null;
    return total;
}

fn responseHasTrailingBytes(total_read: usize, complete_len: usize) bool {
    return total_read > complete_len;
}

fn makeErrorResponse(allocator: Allocator, status: u16, msg: []const u8) Response {
    // Triple-fallback: dupe -> alloc(0) -> zero-length compile-time literal.
    // The final literal is safe because Response.deinit guards on body.len > 0.
    const body = allocator.dupe(u8, msg) catch allocator.alloc(u8, 0) catch &.{};
    return .{ .status = status, .body = body, .allocator = allocator };
}

fn nowMs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(ts.nsec, std.time.ns_per_ms);
}

fn onData(stream: *RingSharedClient, ctx: ?*anyopaque, data: []u8) void {
    if (ctx) |ptr| {
        const cache: *TinyCache = @ptrCast(@alignCast(ptr));
        // 修改原因：多个 fiber 可交错等待回包，必须按 stream 查 Pipe，不能使用全局 active_pipe。
        if (cache.pipeForStream(stream)) |p| p.feed(data) catch {};
    }
}

fn onClose(stream: *RingSharedClient, ctx: ?*anyopaque) void {
    if (Fiber.isYielded()) {
        Fiber.resumeYielded("");
        return;
    }
    if (ctx) |ptr| {
        const cache: *TinyCache = @ptrCast(@alignCast(ptr));
        cache.evictStream(stream);
    }
}

const REQUEST_POOL_SIZE = 30;

const RequestParts = struct {
    headers: ?[]u8 = null,
    body: ?[]u8 = null,

    fn deinit(self: *RequestParts, allocator: Allocator) void {
        if (self.headers) |h| {
            allocator.free(h);
            self.headers = null;
        }
        if (self.body) |b| {
            allocator.free(b);
            self.body = null;
        }
    }
};

fn duplicateRequestParts(allocator: Allocator, headers: ?[]const u8, body: ?[]const u8) !RequestParts {
    var parts = RequestParts{};
    errdefer parts.deinit(allocator);
    if (headers) |h| {
        // 修改原因：调用方传入 headers 时复制失败必须返回 OOM，不能静默丢掉鉴权等请求头继续发送。
        parts.headers = try allocator.dupe(u8, h);
    }
    if (body) |b| {
        parts.body = try allocator.dupe(u8, b);
    }
    return parts;
}

fn initReqFreelist() [REQUEST_POOL_SIZE]usize {
    var freelist: [REQUEST_POOL_SIZE]usize = undefined;
    for (0..REQUEST_POOL_SIZE) |i| {
        freelist[REQUEST_POOL_SIZE - 1 - i] = i;
    }
    return freelist;
}

pub const HttpClient = struct {
    allocator: Allocator,
    ring_b: *RingB,
    cache: *TinyCache,
    pool_lock: std.Io.Mutex,
    req_pool_free: [REQUEST_POOL_SIZE]usize,
    req_pool_top: usize,
    req_pool_items: [REQUEST_POOL_SIZE]RequestContext,
    req_gen: [REQUEST_POOL_SIZE]u64,
    next_gen: u64,
    stop: bool,
    thread: ?std.Thread = null,
    tls_client_config: ?TlsConfig = null,

    const REQUEST_TIMEOUT_MS: i64 = 5000;

    pub fn init(allocator: Allocator, ring_b: *RingB) !*HttpClient {
        // RingB.init returns by value, so ring_b.rs.ring/registry (bound
        // inside init) point at the init frame. Re-point them at ring_b's
        // final address and refresh the resolver's stored copy.
        ring_b.rs.rebind(&ring_b.ring, &ring_b.registry);
        ring_b.dns.rebind(ring_b.rs);

        const self = try allocator.create(HttpClient);
        self.* = .{
            .allocator = allocator,
            .ring_b = ring_b,
            .cache = &ring_b.http_cache,
            .pool_lock = .init,
            .req_pool_free = initReqFreelist(),
            .req_pool_top = REQUEST_POOL_SIZE,
            .req_pool_items = undefined,
            .req_gen = [_]u64{0} ** REQUEST_POOL_SIZE,
            .next_gen = 0,
            .stop = false,
        };
        return self;
    }

    pub fn enableTls(self: *HttpClient) !void {
        if (build_options.tls_enabled) {
            if (self.tls_client_config == null) {
                self.tls_client_config = try TlsConfig.init(self.allocator, null, null, null, false);
            }
        } else {
            return error.TlsNotSupported;
        }
    }

    fn lockPool(self: *HttpClient) void {
        while (!self.pool_lock.tryLock()) std.Thread.yield() catch {};
    }

    fn unlockPool(self: *HttpClient) void {
        self.pool_lock.state.store(.unlocked, .release);
    }

    pub fn start(self: *HttpClient) !void {
        self.thread = try std.Thread.spawn(.{}, runClientThread, .{self});
    }

    fn runClientThread(self: *HttpClient) void {
        while (!@atomicLoad(bool, &self.stop, .acquire)) {
            self.ring_b.tick();
            self.ring_b.invoke.drain(self.allocator);
            _ = self.ring_b.ring.submit() catch {};
            _ = self.ring_b.ring.submit_and_wait(1) catch continue;
        }
        self.ring_b.invoke.drain(self.allocator);
    }

    pub fn deinit(self: *HttpClient) void {
        @atomicStore(bool, &self.stop, true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        for (self.req_pool_items[0..], 0..) |*ctx, i| {
            if (self.isBorrowed(i)) {
                @atomicStore(bool, &ctx.done, true, .release);
            }
        }
        if (self.tls_client_config) |*tc| tc.deinit();
        self.allocator.destroy(self);
    }

    /// Explicit close — delegates everything to deinit().
    /// Calling close() followed by deinit() is safe (idempotent).
    /// Calling close() alone does NOT free memory; use deinit() for cleanup.
    pub fn close(self: *HttpClient) void {
        _ = self;
    }

    fn isBorrowed(self: *HttpClient, idx: usize) bool {
        self.lockPool();
        defer self.unlockPool();
        return self.isBorrowedLocked(idx);
    }

    fn isBorrowedLocked(self: *HttpClient, idx: usize) bool {
        for (0..self.req_pool_top) |j| {
            if (self.req_pool_free[j] == idx) return false;
        }
        return true;
    }

    fn acquireReq(self: *HttpClient) ?*RequestContext {
        self.lockPool();
        defer self.unlockPool();
        if (self.req_pool_top == 0) return null;
        self.req_pool_top -= 1;
        const idx = self.req_pool_free[self.req_pool_top];
        const ctx = &self.req_pool_items[idx];
        ctx.* = .{
            .method = "",
            .url = "",
            .headers = null,
            .body = null,
            .response = undefined,
            .done = false,
            .allocator = self.allocator,
            .client = self,
            .pool_id = idx,
            .from_pool = true,
            .gen = self.req_gen[idx],
            .cancelled = false,
        };
        return ctx;
    }

    fn releaseReq(self: *HttpClient, ctx: *RequestContext) void {
        self.releaseReqInternal(ctx, false);
    }

    fn releaseCancelledReq(self: *HttpClient, ctx: *RequestContext) void {
        self.releaseReqInternal(ctx, true);
    }

    fn releaseReqInternal(self: *HttpClient, ctx: *RequestContext, deinit_response: bool) void {
        self.lockPool();
        defer self.unlockPool();
        if (!self.isBorrowedLocked(ctx.pool_id)) return;
        if (deinit_response) ctx.response.deinit();
        ctx.cleanup();
        self.req_gen[ctx.pool_id] +%= 1; // bump gen → 旧 fiber notify 失效
        self.req_pool_free[self.req_pool_top] = ctx.pool_id;
        self.req_pool_top += 1;
    }

    pub fn get(self: *HttpClient, url: []const u8) !Response {
        return self.request("GET", url, null, null);
    }

    pub fn post(self: *HttpClient, url: []const u8, body: []const u8) !Response {
        return self.request("POST", url, null, body);
    }

    pub fn put(self: *HttpClient, url: []const u8, body: []const u8) !Response {
        return self.request("PUT", url, null, body);
    }

    pub fn patch(self: *HttpClient, url: []const u8, body: []const u8) !Response {
        return self.request("PATCH", url, null, body);
    }

    pub fn delete(self: *HttpClient, url: []const u8) !Response {
        return self.request("DELETE", url, null, null);
    }

    pub fn request(self: *HttpClient, method: []const u8, url: []const u8, headers: ?[]const u8, body: ?[]const u8) !Response {
        var parts = try duplicateRequestParts(self.allocator, headers, body);
        errdefer parts.deinit(self.allocator);

        const ctx = self.acquireReq() orelse return error.PoolFull;
        var release_on_error = true;
        errdefer if (release_on_error) self.releaseReq(ctx);
        ctx.method = method;
        ctx.url = url;
        ctx.headers = parts.headers;
        ctx.body = parts.body;
        ctx.done = false;
        parts.headers = null; // 所有权已移交给 ctx
        parts.body = null;

        try self.ring_b.invoke.push(self.allocator, *RequestContext, ctx, handleRequest);
        {
            // Spin-wait on the atomic done flag, set by notify() on the IO thread.
            // Single-writer (IO thread) single-reader (caller thread): atomics suffice.
            const deadline_ms = nowMs() + REQUEST_TIMEOUT_MS;
            while (!@atomicLoad(bool, &ctx.done, .acquire)) {
                std.Thread.yield() catch {};
                if (@atomicLoad(bool, &ctx.done, .acquire)) break;
                if (nowMs() >= deadline_ms or @atomicLoad(bool, &self.stop, .acquire)) {
                    @atomicStore(bool, &ctx.cancelled, true, .release);
                    @atomicStore(bool, &ctx.done, true, .release);
                    // 修改原因：超时后 IO fiber 仍可能持有 ctx，不能由调用线程释放后立刻复用该槽位。
                    release_on_error = false;
                    return error.RequestTimeout;
                }
            }
        }
        const resp = ctx.response;
        self.releaseReq(ctx);
        return resp;
    }
};

const RequestContext = struct {
    method: []const u8,
    url: []const u8,
    headers: ?[]const u8,
    body: ?[]const u8,
    response: Response,
    done: bool,
    allocator: Allocator,
    client: *HttpClient,
    pool_id: usize,
    from_pool: bool,
    gen: u64,
    cancelled: bool,

    // Notify is called from the IO thread (via InvokeQueue -> handleRequest).
    // request() spins on the caller thread. Single-writer single-reader:
    // @atomicStore/.acquire is sufficient for the completion flag.
    fn notify(self: *RequestContext) void {
        if (@atomicLoad(bool, &self.cancelled, .acquire)) {
            // 修改原因：取消请求的 response 由后台 IO 完成路径创建，必须在这里释放并归还请求池槽位。
            self.client.releaseCancelledReq(self);
            return;
        }
        @atomicStore(bool, &self.done, true, .release);
    }

    fn cleanup(self: *RequestContext) void {
        // 修改原因：fiber 可能先释放请求体，主线程 releaseReq 还会再次 cleanup，释放后必须清空指针。
        if (self.headers) |h| {
            self.allocator.free(h);
            self.headers = null;
        }
        if (self.body) |b| {
            self.allocator.free(b);
            self.body = null;
        }
    }
};

fn handleRequest(allocator: Allocator, ctx_ptr: **RequestContext) void {
    _ = allocator;
    const ctx = ctx_ptr.*;
    const ring = ctx.client.ring_b;
    const stack = ring.allocator.alloc(u8, 65536) catch {
        ctx.response = makeErrorResponse(ctx.allocator, 502, "OOM");
        ctx.notify();
        return;
    };
    var fiber = Fiber.init(stack);
    fiber.exec(.{
        .userCtx = @ptrCast(ctx),
        .complete = struct {
            fn done(_: ?*anyopaque, _: []const u8) void {}
        }.done,
        .execFn = struct {
            fn run(user_ctx: ?*anyopaque, complete: *const fn (?*anyopaque, []const u8) void) void {
                httpRequestFiber(user_ctx, complete);
                const c: *RequestContext = @ptrCast(@alignCast(user_ctx));
                c.client.ring_b.allocator.free(stack);
            }
        }.run,
    });
}

fn requestHeaderTerminator(headers: []const u8) []const u8 {
    // 修改原因：调用方常传入单行 header；缺少结尾 CRLF 时直接拼接会把后续请求头拼进上一行。
    if (headers.len == 0) return "";
    if (std.mem.endsWith(u8, headers, "\n")) return "";
    return "\r\n";
}

fn isManagedRequestHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding");
}

fn validateHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |ch| {
        if (!isHttpTokenChar(ch)) return false;
    }
    return true;
}

fn validateCallerHeaders(headers: []const u8) !void {
    // 修改原因：客户端自己生成 Host/Content-Length/Connection；允许调用方重复或提前插入空行会造成请求走私或 body 边界错误。
    if (headers.len == 0) return;
    var start: usize = 0;
    while (start < headers.len) {
        const rel_end = std.mem.indexOfScalar(u8, headers[start..], '\n');
        const end = if (rel_end) |idx| start + idx else headers.len;
        const line = std.mem.trimRight(u8, headers[start..end], "\r");
        // 修改原因：headers 会原样拼接进请求；行内 CR/控制字符会变成请求头注入或畸形报文，必须在客户端边界拒绝。
        for (line) |ch| {
            if (ch == '\r' or (ch < ' ' and ch != '\t') or ch == 0x7f) return error.InvalidHeaders;
        }
        if (line.len == 0) return error.InvalidHeaders;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeaders;
        const name = line[0..colon];
        // 修改原因：headers 会原样发送，冒号前空白不能靠 trim 放行，否则客户端会生成畸形请求头。
        if (name.len != std.mem.trim(u8, name, " \t").len) return error.InvalidHeaders;
        if (!validateHeaderName(name) or isManagedRequestHeader(name)) return error.InvalidHeaders;
        if (rel_end) |_| {
            start = end + 1;
        } else {
            break;
        }
    }
}

fn requestTargetPrefix(path: []const u8) []const u8 {
    // 修改原因：URL 形如 http://host?x=1 时 path 以 ? 开头，HTTP origin-form 必须补成 /?x=1。
    if (path.len > 0 and path[0] == '?') return "/";
    return "";
}

fn buildRequest(buf: []u8, method: []const u8, path: []const u8, host: []const u8, headers: ?[]const u8, body: ?[]const u8) ![]u8 {
    try validateMethod(method);
    try validateUrlHost(host);
    try validateRequestTarget(path);
    if (headers) |h| try validateCallerHeaders(h);
    const target_prefix = requestTargetPrefix(path);
    if (body) |b| {
        if (headers) |h| {
            const header_term = requestHeaderTerminator(h);
            return std.fmt.bufPrint(
                buf,
                "{s} {s}{s} HTTP/1.1\r\nHost: {s}\r\n{s}{s}Content-Length: {d}\r\nConnection: keep-alive\r\n\r\n{s}",
                .{ method, target_prefix, path, host, h, header_term, b.len, b },
            );
        }
        return std.fmt.bufPrint(
            buf,
            "{s} {s}{s} HTTP/1.1\r\nHost: {s}\r\nContent-Length: {d}\r\nConnection: keep-alive\r\n\r\n{s}",
            .{ method, target_prefix, path, host, b.len, b },
        );
    }
    if (headers) |h| {
        const header_term = requestHeaderTerminator(h);
        return std.fmt.bufPrint(
            buf,
            "{s} {s}{s} HTTP/1.1\r\nHost: {s}\r\n{s}{s}Connection: keep-alive\r\n\r\n",
            .{ method, target_prefix, path, host, h, header_term },
        );
    }
    return std.fmt.bufPrint(
        buf,
        "{s} {s}{s} HTTP/1.1\r\nHost: {s}\r\nConnection: keep-alive\r\n\r\n",
        .{ method, target_prefix, path, host },
    );
}

fn httpRequestFiber(user_ctx: ?*anyopaque, complete: *const fn (?*anyopaque, []const u8) void) void {
    _ = complete;
    const ctx: *RequestContext = @ptrCast(@alignCast(user_ctx));
    const client = ctx.client;
    const cache = client.cache;

    const parsed = parseUrl(ctx.allocator, ctx.url) catch {
        ctx.response = makeErrorResponse(ctx.allocator, 400, "invalid URL");
        ctx.notify();
        return;
    };
    defer ctx.allocator.free(parsed.host);
    defer ctx.allocator.free(parsed.authority);

    const now = nowMs();

    var stream: *RingSharedClient = undefined;
    var pipe: *Pipe = undefined;

    if (cache.acquire(parsed.host, parsed.port, parsed.tls, now)) |borrowed| {
        stream = borrowed.stream;
        pipe = borrowed.pipe;
    } else {
        // Per-target concurrent connect cap: fail fast before SQE ring allocation
        client.ring_b.tryIncConnecting(parsed.host, parsed.port) catch {
            ctx.response = makeErrorResponse(ctx.allocator, 503, "target connect limit reached");
            ctx.notify();
            return;
        };
        defer client.ring_b.decConnecting(parsed.host, parsed.port);

        const ip = client.ring_b.dns.resolve(parsed.host) catch {
            ctx.response = makeErrorResponse(ctx.allocator, 502, "DNS resolution failed");
            ctx.notify();
            return;
        };

        stream = RingSharedClient.init(ctx.allocator, client.ring_b.rs, onData, onClose, @ptrCast(@constCast(cache)), null) catch {
            ctx.response = makeErrorResponse(ctx.allocator, 502, "client init failed");
            ctx.notify();
            return;
        };
        var connect_ok = false;
        var retries: u8 = 0;
        while (retries < 2) : (retries += 1) {
            stream.connectRawTimeout(ip, parsed.port, 5000) catch {
                if (retries == 0) {
                    stream.deinit();
                    stream = RingSharedClient.init(ctx.allocator, client.ring_b.rs, onData, onClose, @ptrCast(@constCast(cache)), null) catch {
                        ctx.response = makeErrorResponse(ctx.allocator, 502, "client init failed after retry");
                        ctx.notify();
                        return;
                    };
                    continue;
                }
                break;
            };
            connect_ok = true;
            break;
        }
        if (!connect_ok) {
            stream.deinit();
            ctx.response = makeErrorResponse(ctx.allocator, 502, "connection failed");
            ctx.notify();
            return;
        }
        if (parsed.tls) {
            if (!build_options.tls_enabled) {
                stream.deinit();
                ctx.response = makeErrorResponse(ctx.allocator, 502, "TLS not supported");
                ctx.notify();
                return;
            }
            if (client.tls_client_config) |*tc| {
                stream.startTls(tc) catch {
                    stream.deinit();
                    ctx.response = makeErrorResponse(ctx.allocator, 502, "TLS handshake failed");
                    ctx.notify();
                    return;
                };
            } else {
                client.enableTls() catch {
                    stream.deinit();
                    ctx.response = makeErrorResponse(ctx.allocator, 502, "TLS init failed");
                    ctx.notify();
                    return;
                };
                if (client.tls_client_config) |*tc| {
                    stream.startTls(tc) catch {
                        stream.deinit();
                        ctx.response = makeErrorResponse(ctx.allocator, 502, "TLS handshake failed");
                        ctx.notify();
                        return;
                    };
                } else {
                    stream.deinit();
                    ctx.response = makeErrorResponse(ctx.allocator, 502, "TLS config unavailable");
                    ctx.notify();
                    return;
                }
            }
        }
        var new_pipe = Pipe.init(ctx.allocator, stream) catch {
            stream.deinit();
            ctx.response = makeErrorResponse(ctx.allocator, 502, "pipe init failed");
            ctx.notify();
            return;
        };
        cache.store(stream, new_pipe, parsed.host, parsed.port, parsed.tls, now) catch |err| {
            new_pipe.deinit();
            stream.deinit();
            switch (err) {
                error.PoolFull => ctx.response = makeErrorResponse(ctx.allocator, 503, "connection pool full"),
                error.CacheDisabled => ctx.response = makeErrorResponse(ctx.allocator, 502, "connection cache disabled"),
                else => ctx.response = makeErrorResponse(ctx.allocator, 502, "OOM"),
            }
            ctx.notify();
            return;
        };
        const borrowed = cache.acquire(parsed.host, parsed.port, parsed.tls, now) orelse {
            ctx.response = makeErrorResponse(ctx.allocator, 502, "connection cache failed");
            ctx.notify();
            return;
        };
        stream = borrowed.stream;
        pipe = borrowed.pipe;
    }

    const reader = pipe.reader();

    var req_buf: [4096]u8 = undefined;
    const req = buildRequest(&req_buf, ctx.method, parsed.path, parsed.authority, ctx.headers, ctx.body) catch |err| {
        ctx.cleanup();
        // 修改原因：请求过大时还没有写入上游，必须归还已借出的 pipe，避免连接池项永久停在 borrowed 状态。
        cache.release(pipe, nowMs());
        ctx.response = makeErrorResponse(ctx.allocator, 502, if (err == error.InvalidHeaders) "invalid request headers" else "request too large");
        ctx.notify();
        return;
    };
    stream.write(req) catch {
        ctx.cleanup();
        cache.evictPipe(pipe);
        // Timeout → target 关服, 不重试
        if (stream.conn_errno == -125 or stream.conn_errno == -110) {
            ctx.response = makeErrorResponse(ctx.allocator, 504, "upstream timeout");
        } else {
            ctx.response = makeErrorResponse(ctx.allocator, 502, "write failed");
        }
        ctx.notify();
        return;
    };
    ctx.cleanup();

    // Allocate from ring allocator instead of the fiber stack: the fiber
    // stack is only 64KB and a 64KB local array here + other locals + the
    // fiber frame itself exceeds it, causing deterministic stack overflow.
    const resp_buf = ctx.client.ring_b.allocator.alloc(u8, 65536) catch {
        cache.evictPipe(pipe);
        ctx.response = makeErrorResponse(ctx.allocator, 502, "OOM");
        ctx.notify();
        return;
    };
    defer ctx.client.ring_b.allocator.free(resp_buf);
    var total: usize = 0;
    var complete_len: usize = 0;
    var invalid_response = false;
    const read_ok = blk: {
        while (true) {
            // 修改原因：HTTP/1.1 keep-alive 不会主动关闭连接，读到完整响应就应停止等待。
            const maybe_complete = responseCompleteLenForMethod(resp_buf[0..total], ctx.method) catch {
                invalid_response = true;
                break :blk false;
            };
            if (maybe_complete) |n_complete| {
                complete_len = n_complete;
                break :blk true;
            }
            if (total >= resp_buf.len) break :blk false;
            const n = reader.read(resp_buf[total..]) catch break :blk false;
            if (n == 0) break :blk false;
            total += n;
        }
    };
    if (!read_ok) {
        cache.evictPipe(pipe);
        const msg = if (invalid_response) "invalid response" else "read failed";
        ctx.response = makeErrorResponse(ctx.allocator, 502, msg);
        ctx.notify();
        return;
    }

    if (parseResponseForMethod(ctx.allocator, resp_buf[0..complete_len], ctx.method)) |resp| {
        ctx.response = resp;
        ctx.notify();
        if (responseHasTrailingBytes(total, complete_len) or responseWantsClose(resp_buf[0..complete_len])) {
            // 修改原因：多余字节或 Connection: close 都说明连接不能安全复用，必须从池里淘汰。
            cache.evictPipe(pipe);
        } else {
            cache.release(pipe, nowMs());
        }
    } else |_| {
        cache.evictPipe(pipe);
        ctx.response = makeErrorResponse(ctx.allocator, 502, "invalid response");
        ctx.notify();
    }
}

test "HttpClient buildRequest terminates caller headers" {
    var buf: [512]u8 = undefined;

    const get_req = try buildRequest(&buf, "GET", "/", "example.com", "Authorization: Bearer token", null);
    try std.testing.expect(std.mem.indexOf(u8, get_req, "Authorization: Bearer token\r\nConnection: keep-alive") != null);

    const post_req = try buildRequest(&buf, "POST", "/", "example.com", "Content-Type: application/json", "{}");
    try std.testing.expect(std.mem.indexOf(u8, post_req, "Content-Type: application/json\r\nContent-Length: 2") != null);

    const already_terminated = try buildRequest(&buf, "GET", "/", "example.com", "X-Test: ok\r\n", null);
    try std.testing.expect(std.mem.indexOf(u8, already_terminated, "X-Test: ok\r\nConnection: keep-alive") != null);

    const query_only_path = try buildRequest(&buf, "GET", "?x=1", "example.com", null, null);
    try std.testing.expect(std.mem.startsWith(u8, query_only_path, "GET /?x=1 HTTP/1.1\r\n"));
}

test "HttpClient buildRequest rejects managed caller headers" {
    var buf: [512]u8 = undefined;

    try std.testing.expectError(error.InvalidHeaders, buildRequest(&buf, "POST", "/", "example.com", "Content-Length: 999", "{}"));
    try std.testing.expectError(error.InvalidHeaders, buildRequest(&buf, "GET", "/", "example.com", "Connection: close", null));
    try std.testing.expectError(error.InvalidHeaders, buildRequest(&buf, "GET", "/", "example.com", "Host: other.example", null));
    try std.testing.expectError(error.InvalidHeaders, buildRequest(&buf, "POST", "/", "example.com", "Transfer-Encoding: chunked", "{}"));
    try std.testing.expectError(error.InvalidHeaders, buildRequest(&buf, "GET", "/", "example.com", "X-Test: ok\r\n\r\nX-After: injected", null));
    try std.testing.expectError(error.InvalidHeaders, buildRequest(&buf, "GET", "/", "example.com", "Bad Name: ok", null));
    try std.testing.expectError(error.InvalidHeaders, buildRequest(&buf, "GET", "/", "example.com", "X-Test : ok", null));
    try std.testing.expectError(error.InvalidHeaders, buildRequest(&buf, "GET", "/", "example.com", "X-Test: ok\rX-Injected: yes", null));
    try std.testing.expectError(error.InvalidMethod, buildRequest(&buf, "GET\r\nX-Bad: yes", "/", "example.com", null, null));
    try std.testing.expectError(error.InvalidUrl, buildRequest(&buf, "GET", "/\r\nX-Bad: yes", "example.com", null, null));
    try std.testing.expectError(error.InvalidUrl, buildRequest(&buf, "GET", "/", "example.com\r\nX-Bad: yes", null, null));
}

test "HttpClient responseCompleteLen waits for Content-Length body" {
    const partial = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello";
    try std.testing.expect(try responseCompleteLen(partial) == null);

    const full = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello worldEXTRA";
    const expected = (std.mem.indexOf(u8, full, "\r\n\r\n") orelse unreachable) + 4 + 11;
    try std.testing.expectEqual(@as(?usize, expected), try responseCompleteLen(full));

    var resp = try parseResponse(std.testing.allocator, full);
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("hello world", resp.body);
}

test "HttpClient responseCompleteLen rejects duplicate Content-Length" {
    const duplicate = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 11\r\n\r\nhello world";
    try std.testing.expectError(error.DuplicateHeader, responseCompleteLen(duplicate));
}

test "HttpClient responseCompleteLen rejects malformed Content-Length" {
    try std.testing.expectError(error.InvalidContentLength, responseCompleteLen("HTTP/1.1 200 OK\r\nContent-Length: 01\r\n\r\nx"));
    try std.testing.expectError(error.InvalidContentLength, responseCompleteLen("HTTP/1.1 200 OK\r\nContent-Length: 1x\r\n\r\nx"));
}

test "HttpClient responseCompleteLen rejects overflowing response boundary" {
    try std.testing.expectError(
        error.InvalidResponse,
        responseCompleteLen("HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n"),
    );
}

test "HttpClient responseCompleteLen rejects Transfer-Encoding" {
    const encoded = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectError(error.TransferEncodingUnsupported, responseCompleteLen(encoded));
}

test "HttpClient responseCompleteLen rejects malformed response headers" {
    try std.testing.expectError(error.InvalidResponse, responseCompleteLen("HTTP/1.1 204 No Content\r\nBad Name: x\r\n\r\n"));
    try std.testing.expectError(error.InvalidResponse, responseCompleteLen("HTTP/1.1 204 No Content\r\nX-Test : x\r\n\r\n"));
    try std.testing.expectError(error.InvalidResponse, responseCompleteLen("HTTP/1.1 204 No Content\r\nBroken\r\n\r\n"));
    try std.testing.expectError(error.InvalidResponse, responseCompleteLen("HTTP/1.1 204 No Content\r\nX-Test: ok\rBad: yes\r\n\r\n"));
}

test "HttpClient responseCompleteLen rejects unsupported informational responses" {
    try std.testing.expectError(error.InformationalResponseUnsupported, responseCompleteLen("HTTP/1.1 100 Continue\r\n\r\n"));
    try std.testing.expectError(error.InformationalResponseUnsupported, responseCompleteLen("HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n"));
}

test "HttpClient responseCompleteLen requires length for body-capable responses" {
    try std.testing.expectError(error.MissingContentLength, responseCompleteLen("HTTP/1.1 200 OK\r\n\r\nhello"));

    const no_content = "HTTP/1.1 204 No Content\r\n\r\nignored";
    const expected = (std.mem.indexOf(u8, no_content, "\r\n\r\n") orelse unreachable) + 4;
    try std.testing.expectEqual(@as(?usize, expected), try responseCompleteLen(no_content));
}

test "HttpClient responseCompleteLen frames no-body responses at header end" {
    try std.testing.expectError(error.InvalidResponse, responseCompleteLen("HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello"));
    try std.testing.expectError(error.InvalidResponse, responseCompleteLen("HTTP/1.1 205 Reset Content\r\nContent-Length: 5\r\n\r\nhello"));

    const not_modified = "HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n\r\nextra";
    const expected = (std.mem.indexOf(u8, not_modified, "\r\n\r\n") orelse unreachable) + 4;
    try std.testing.expectEqual(@as(?usize, expected), try responseCompleteLen(not_modified));

    var resp = try parseResponse(std.testing.allocator, not_modified[0..expected]);
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 304), resp.status);
    try std.testing.expectEqual(@as(usize, 0), resp.body.len);

    const reset_content = "HTTP/1.1 205 Reset Content\r\n\r\nextra";
    const reset_expected = (std.mem.indexOf(u8, reset_content, "\r\n\r\n") orelse unreachable) + 4;
    try std.testing.expectEqual(@as(?usize, reset_expected), try responseCompleteLen(reset_content));
}

test "HttpClient responseCompleteLen frames HEAD responses at header end" {
    const head_response = "HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\nextra";
    const expected = (std.mem.indexOf(u8, head_response, "\r\n\r\n") orelse unreachable) + 4;
    try std.testing.expectEqual(@as(?usize, expected), try responseCompleteLenForMethod(head_response, "HEAD"));

    var resp = try parseResponseForMethod(std.testing.allocator, head_response[0..expected], "HEAD");
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqual(@as(usize, 0), resp.body.len);
}

test "HttpClient detects trailing bytes after complete response" {
    try std.testing.expect(!responseHasTrailingBytes(42, 42));
    try std.testing.expect(responseHasTrailingBytes(43, 42));
}

test "HttpClient detects Connection close response token" {
    const close_resp = "HTTP/1.1 200 OK\r\nConnection: keep-alive, close\r\nContent-Length: 0\r\n\r\n";
    try std.testing.expect(responseWantsClose(close_resp));

    const keep_resp = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
    try std.testing.expect(!responseWantsClose(keep_resp));
}

test "HttpClient parseResponse rejects malformed status lines" {
    try std.testing.expectError(
        error.InvalidResponse,
        parseResponse(std.testing.allocator, "HTTP/1.1 abc Broken\r\nContent-Length: 0\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidResponse,
        parseResponse(std.testing.allocator, "NOTHTTP 200 OK\r\nContent-Length: 0\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidResponse,
        parseResponse(std.testing.allocator, "HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidResponse,
        parseResponse(std.testing.allocator, "HTTP/1.1BAD 200 OK\r\nContent-Length: 0\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidResponse,
        parseResponse(std.testing.allocator, "HTTP/1.1 0200 OK\r\nContent-Length: 0\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidResponse,
        parseResponse(std.testing.allocator, "HTTP/1.1 999 Weird\r\nContent-Length: 0\r\n\r\n"),
    );
}

test "HttpClient cancelled notify returns request slot once" {
    var client = HttpClient{
        .allocator = std.testing.allocator,
        .ring_b = undefined,
        .cache = undefined,
        .pool_lock = .{},
        .req_pool_free = initReqFreelist(),
        .req_pool_top = REQUEST_POOL_SIZE,
        .req_pool_items = undefined,
        .req_gen = [_]u64{0} ** REQUEST_POOL_SIZE,
        .next_gen = 0,
        .stop = false,
    };

    const ctx = client.acquireReq() orelse {
        try std.testing.expect(false);
        return;
    };
    const pool_id = ctx.pool_id;
    try std.testing.expectEqual(@as(usize, REQUEST_POOL_SIZE - 1), client.req_pool_top);

    ctx.response = makeErrorResponse(std.testing.allocator, 504, "timeout");
    @atomicStore(bool, &ctx.cancelled, true, .release);
    ctx.notify();

    try std.testing.expectEqual(@as(usize, REQUEST_POOL_SIZE), client.req_pool_top);
    var seen: usize = 0;
    for (client.req_pool_free[0..client.req_pool_top]) |idx| {
        if (idx == pool_id) seen += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), seen);

    ctx.notify();
    try std.testing.expectEqual(@as(usize, REQUEST_POOL_SIZE), client.req_pool_top);
}

test "HttpClient parseUrl rejects malformed explicit ports" {
    try std.testing.expectError(error.InvalidUrl, parseUrl(std.testing.allocator, "http://example.com:/"));
    try std.testing.expectError(error.InvalidUrl, parseUrl(std.testing.allocator, "http://example.com:abc/"));
    try std.testing.expectError(error.InvalidUrl, parseUrl(std.testing.allocator, "http://example.com:80:90/"));
    try std.testing.expectError(error.InvalidUrl, parseUrl(std.testing.allocator, "http://user@example.com/"));
    try std.testing.expectError(error.InvalidUrl, parseUrl(std.testing.allocator, "http://:8080/"));
    try std.testing.expectError(error.InvalidUrl, parseUrl(std.testing.allocator, "http://example.com\r\nX-Bad: yes/"));
    try std.testing.expectError(error.InvalidUrl, parseUrl(std.testing.allocator, "http://example.com/path\r\nX-Bad: yes"));
    try std.testing.expectError(error.InvalidUrl, parseUrl(std.testing.allocator, "http://example.com/a b"));

    const parsed = try parseUrl(std.testing.allocator, "http://example.com:8080/path");
    defer std.testing.allocator.free(parsed.host);
    defer std.testing.allocator.free(parsed.authority);
    try std.testing.expectEqualStrings("example.com", parsed.host);
    try std.testing.expectEqualStrings("example.com:8080", parsed.authority);
    try std.testing.expectEqual(@as(u16, 8080), parsed.port);
    try std.testing.expectEqualStrings("/path", parsed.path);

    var req_buf: [512]u8 = undefined;
    const explicit_port_req = try buildRequest(&req_buf, "GET", parsed.path, parsed.authority, null, null);
    try std.testing.expect(std.mem.indexOf(u8, explicit_port_req, "Host: example.com:8080\r\n") != null);

    const parsed_upper_scheme = try parseUrl(std.testing.allocator, "HTTP://example.com/upper");
    defer std.testing.allocator.free(parsed_upper_scheme.host);
    defer std.testing.allocator.free(parsed_upper_scheme.authority);
    try std.testing.expectEqualStrings("example.com", parsed_upper_scheme.host);
    try std.testing.expectEqualStrings("example.com", parsed_upper_scheme.authority);
    try std.testing.expectEqualStrings("/upper", parsed_upper_scheme.path);

    const parsed_https = try parseUrl(std.testing.allocator, "HTTPS://example.com/");
    defer std.testing.allocator.free(parsed_https.host);
    defer std.testing.allocator.free(parsed_https.authority);
    try std.testing.expectEqualStrings("example.com", parsed_https.host);
    try std.testing.expectEqualStrings("/", parsed_https.path);
    try std.testing.expect(parsed_https.tls);
    try std.testing.expectEqual(@as(u16, 443), parsed_https.port);

    const parsed_query = try parseUrl(std.testing.allocator, "http://example.com?x=1");
    defer std.testing.allocator.free(parsed_query.host);
    defer std.testing.allocator.free(parsed_query.authority);
    try std.testing.expectEqualStrings("example.com", parsed_query.host);
    try std.testing.expectEqualStrings("example.com", parsed_query.authority);
    try std.testing.expectEqual(@as(u16, 80), parsed_query.port);
    try std.testing.expectEqualStrings("?x=1", parsed_query.path);

    const parsed_fragment = try parseUrl(std.testing.allocator, "http://example.com/path?q=1#frag");
    defer std.testing.allocator.free(parsed_fragment.host);
    defer std.testing.allocator.free(parsed_fragment.authority);
    try std.testing.expectEqualStrings("example.com", parsed_fragment.host);
    try std.testing.expectEqualStrings("/path?q=1", parsed_fragment.path);

    const parsed_root_fragment = try parseUrl(std.testing.allocator, "http://example.com#frag");
    defer std.testing.allocator.free(parsed_root_fragment.host);
    defer std.testing.allocator.free(parsed_root_fragment.authority);
    try std.testing.expectEqualStrings("example.com", parsed_root_fragment.host);
    try std.testing.expectEqualStrings("/", parsed_root_fragment.path);
}

test "HttpClient preserves request headers allocation failures" {
    {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.OutOfMemory, duplicateRequestParts(failing.allocator(), "Authorization: Bearer token\r\n", null));
    }

    {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
        try std.testing.expectError(error.OutOfMemory, duplicateRequestParts(failing.allocator(), "Content-Type: application/json\r\n", "{}"));
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        try std.testing.expectEqual(failing.allocations, failing.deallocations);
    }
}
