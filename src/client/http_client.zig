const std = @import("std");
const Allocator = std.mem.Allocator;
const build_options = @import("build_options");

const RingB = @import("ring.zig").RingB;
const RingSharedClient = @import("../shared/tcp_stream.zig").RingSharedClient;
const TinyCache = @import("tiny_cache.zig").TinyCache;
const Pipe = @import("../next/pipe.zig").Pipe;
const TlsConfig = if (build_options.tls_enabled) @import("../tls/tls.zig").TlsConfig else struct {};
const Fiber = @import("../next/fiber.zig").Fiber;
const logErr = @import("../async_logger.zig").logErr;

const http_parse = @import("http_parse.zig");
pub const Response = http_parse.Response;
const makeErrorResponse = http_parse.makeErrorResponse;
const isHttpTokenChar = http_parse.isHttpTokenChar;
const validateMethod = http_parse.validateMethod;
const validateUrlHost = http_parse.validateUrlHost;
const validateRequestTarget = http_parse.validateRequestTarget;
const parseUrl = http_parse.parseUrl;
const responseCompleteLenForMethod = http_parse.responseCompleteLenForMethod;
const parseResponseForMethod = http_parse.parseResponseForMethod;
const responseHasTrailingBytes = http_parse.responseHasTrailingBytes;
const responseWantsClose = http_parse.responseWantsClose;

fn nowMs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(ts.nsec, std.time.ns_per_ms);
}

fn onData(stream: *RingSharedClient, ctx: ?*anyopaque, data: []u8) void {
    if (ctx) |ptr| {
        const cache: *TinyCache = @ptrCast(@alignCast(ptr));
        // Multiple fibers can interleave waiting for replies, so the Pipe must be looked up by stream rather than a global active_pipe.
        if (cache.pipeForStream(stream)) |p| p.feed(data) catch |err| logErr("client pipe feed failed: {s}", .{@errorName(err)});
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
        // When the caller supplies headers, a copy failure must surface as OOM instead of silently dropping auth and other headers and continuing the send.
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
            _ = self.ring_b.ring.submit() catch |err| logErr("client ring submit failed: {s}", .{@errorName(err)});
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
        if (build_options.tls_enabled) {
            if (self.tls_client_config) |*tc| tc.deinit();
        }
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
        self.req_gen[ctx.pool_id] +%= 1; // bump gen so stale fiber notify is invalidated
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
        parts.headers = null; // ownership transferred to ctx
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
                    // After a timeout the IO fiber may still hold ctx, so the caller thread cannot release and immediately reuse the slot.
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
            // The response for a cancelled request is created by the background IO completion path, so it must be freed and the request-pool slot returned here.
            self.client.releaseCancelledReq(self);
            return;
        }
        @atomicStore(bool, &self.done, true, .release);
    }

    fn cleanup(self: *RequestContext) void {
        // The fiber may free the request body first and the main thread's releaseReq will clean up again, so the pointers must be cleared after freeing.
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
    _ = fiber.exec(.{
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
    // Callers often pass a single-line header; without a trailing CRLF, direct concatenation would splice later request headers into the previous line.
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
    // The client generates Host/Content-Length/Connection itself; allowing the caller to duplicate them or insert an early blank line would cause request smuggling or body-boundary errors.
    if (headers.len == 0) return;
    var start: usize = 0;
    while (start < headers.len) {
        const rel_end = std.mem.indexOfScalar(u8, headers[start..], '\n');
        const end = if (rel_end) |idx| start + idx else headers.len;
        const line = std.mem.trimEnd(u8, headers[start..end], "\r");
        // Headers are spliced into the request verbatim; in-line CR/control characters would become header injection or a malformed message and must be rejected at the client boundary.
        for (line) |ch| {
            if (ch == '\r' or (ch < ' ' and ch != '\t') or ch == 0x7f) return error.InvalidHeaders;
        }
        if (line.len == 0) return error.InvalidHeaders;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeaders;
        const name = line[0..colon];
        // Headers are sent verbatim, so whitespace before the colon cannot be tolerated by trimming or the client would emit a malformed header.
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
    // For a URL like http://host?x=1 the path starts with '?'; the HTTP origin-form must be padded to /?x=1.
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
        // The oversized request has not been written upstream, so the borrowed pipe must be returned to avoid leaving the pool entry stuck in borrowed state.
        cache.release(pipe, nowMs());
        ctx.response = makeErrorResponse(ctx.allocator, 502, if (err == error.InvalidHeaders) "invalid request headers" else "request too large");
        ctx.notify();
        return;
    };
    stream.write(req) catch {
        ctx.cleanup();
        cache.evictPipe(pipe);
        // Timeout → target is down; do not retry
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
            // HTTP/1.1 keep-alive does not proactively close the connection, so reading stops once the complete response is available.
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
            // Trailing bytes or Connection: close both mean the connection cannot be safely reused, so it must be evicted from the pool.
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

test "HttpClient cancelled notify returns request slot once" {
    var client = HttpClient{
        .allocator = std.testing.allocator,
        .ring_b = undefined,
        .cache = undefined,
        .pool_lock = .init,
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
