const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const AsyncServer = @import("async_server.zig").AsyncServer;
const Connection = @import("connection.zig").Connection;
const Context = @import("context.zig").Context;
const Middleware = @import("types.zig").Middleware;
const Handler = @import("types.zig").Handler;
const WsHandler = @import("../ws/server.zig").WsHandler;
const MiddlewareStore = @import("middleware_store.zig").MiddlewareStore;
const WildcardEntry = @import("middleware_store.zig").WildcardEntry;
const PathRule = @import("../antpath.zig").PathRule;
const helpers = @import("http_helpers.zig");
const getMethodFromRequest = helpers.getMethodFromRequest;
const getPathFromRequestWithLimit = helpers.getPathFromRequestWithLimit;
const logErr = helpers.logErr;
const ws_upgrade = @import("../ws/upgrade.zig");
const http_fiber = @import("http_fiber.zig");
const http_response = @import("http_response.zig");
const sticker = @import("../stack_pool_sticker.zig");
const Fiber = @import("../next/fiber.zig").Fiber;
const Next = @import("../next/next.zig").Next;
const HttpTaskCtx = http_fiber.HttpTaskCtx;
const httpTaskExec = http_fiber.httpTaskExec;
const httpTaskExecWrapperWithOwnership = http_fiber.httpTaskExecWrapperWithOwnership;
const httpTaskComplete = http_fiber.httpTaskComplete;
const statusText = http_response.statusText;

pub const Segment = union(enum) {
    literal: []const u8,
    param: []const u8,
    wildcard: void,
};

pub const ParamRoute = struct {
    method: []const u8,
    segments: []const Segment,
    handler: Handler,
};

pub const RouteParam = @import("context.zig").RouteParam;

/// Maximum path parameters captured per route match.
const MAX_PARAMS: usize = 16;

pub fn parseParamPattern(allocator: Allocator, pattern: []const u8) ![]const Segment {
    var segments = std.ArrayList(Segment).empty;
    errdefer {
        for (segments.items) |seg| {
            if (seg == .literal or seg == .param) {
                allocator.free(@as([]const u8, switch (seg) {
                    .literal => |lit| lit,
                    .param => |p| p,
                    .wildcard => unreachable,
                }));
            }
        }
        segments.deinit(allocator);
    }

    var iter = std.mem.splitScalar(u8, pattern, '/');
    while (iter.next()) |part| {
        if (part.len == 0) continue;
        if (std.mem.eql(u8, part, "*")) {
            try segments.append(allocator, .wildcard);
        } else if (part[0] == ':') {
            const name = try allocator.dupe(u8, part[1..]);
            try segments.append(allocator, .{ .param = name });
        } else {
            const lit = try allocator.dupe(u8, part);
            try segments.append(allocator, .{ .literal = lit });
        }
    }
    return segments.toOwnedSlice(allocator);
}

pub fn freeSegments(allocator: Allocator, segments: []const Segment) void {
    for (segments) |seg| {
        if (seg == .literal) allocator.free(seg.literal);
        if (seg == .param) allocator.free(seg.param);
    }
    allocator.free(segments);
}

pub fn matchParamRoute(route: ParamRoute, path: []const u8, params: *[MAX_PARAMS]RouteParam) ?usize {
    var path_iter = std.mem.splitScalar(u8, path, '/');
    var param_idx: usize = 0;
    var seg_idx: usize = 0;

    while (path_iter.next()) |part| {
        if (part.len == 0) continue;
        if (seg_idx >= route.segments.len) return null;

        const segment = route.segments[seg_idx];
        switch (segment) {
            .literal => |lit| {
                if (!std.mem.eql(u8, lit, part)) return null;
            },
            .param => |name| {
                if (param_idx < params.len) {
                    params[param_idx] = .{ .name = name, .value = part };
                    param_idx += 1;
                } else {
                    return null;
                }
            },
            .wildcard => {
                return param_idx;
            },
        }
        seg_idx += 1;
    }

    return if (seg_idx == route.segments.len) param_idx else null;
}

/// Searches param_routes for a handler matching method + path.
/// Returns handler and params on match, null otherwise.
pub fn findParamHandler(server: *AsyncServer, method: []const u8, path: []const u8, params: *[MAX_PARAMS]RouteParam) ?struct { handler: Handler, param_count: usize } {
    for (server.param_routes.items) |route| {
        if (!std.mem.eql(u8, route.method, method)) continue;
        if (matchParamRoute(route, path, params)) |param_count| {
            return .{ .handler = route.handler, .param_count = param_count };
        }
    }
    return null;
}

fn appendPreciseMiddleware(allocator: Allocator, precise: *std.StringHashMap(std.ArrayList(Middleware)), pattern: []const u8, middleware: Middleware) !void {
    var owned_key: ?[]u8 = try allocator.dupe(u8, pattern);
    errdefer if (owned_key) |key| allocator.free(key);

    const key = owned_key.?;
    var inserted_new = false;
    errdefer if (inserted_new) {
        _ = precise.remove(key);
        allocator.free(key);
    };

    const gop = try precise.getOrPut(key);
    if (!gop.found_existing) {
        gop.value_ptr.* = std.ArrayList(Middleware).empty;
        owned_key = null;
        inserted_new = true;
    } else {
        allocator.free(key);
        owned_key = null;
    }

    // 修改原因：getOrPut 新插入 key 后 append 仍可能失败，失败时必须回滚 map，避免残留已释放 key。
    try gop.value_ptr.append(allocator, middleware);
}

/// 注册中间件，在 fiber 中执行。可用 Next.submit() 卸 CPU 重活。
pub fn use(self: *AsyncServer, pattern: []const u8, middleware: Middleware) !void {
    ensureNext(self);

    if (pattern.len == 0 or (pattern.len == 1 and pattern[0] == '/')) {
        return error.InvalidPattern;
    }
    if ((pattern.len == 3 and pattern[0] == '/' and pattern[1] == '*' and pattern[2] == '*') or
        (pattern.len == 2 and pattern[0] == '*' and pattern[1] == '*'))
    {
        try self.middlewares.global.append(self.allocator, middleware);
        self.middlewares.has_global = true;

        return;
    }
    if (std.mem.indexOfScalar(u8, pattern, '*') == null) {
        try appendPreciseMiddleware(self.allocator, &self.middlewares.precise, pattern, middleware);

        return;
    }
    for (self.middlewares.wildcard.items) |*entry| {
        if (std.mem.eql(u8, entry.rule.pattern, pattern)) {
            try entry.list.append(self.allocator, middleware);

            return;
        }
    }
    var new_list = std.ArrayList(Middleware).empty;
    try new_list.append(self.allocator, middleware);
    var rule = try PathRule.init(self.allocator, pattern);
    errdefer {
        new_list.deinit(self.allocator);
        rule.deinit();
    }
    try self.middlewares.wildcard.append(self.allocator, .{
        .rule = rule,
        .list = new_list,
    });
}

/// 注册快速中间件，在 IO 线程内联执行。⚠️ 不可阻塞。
pub fn useThenRespondImmediately(self: *AsyncServer, pattern: []const u8, middleware: Middleware) !void {
    if (pattern.len == 0 or (pattern.len == 1 and pattern[0] == '/')) {
        return error.InvalidPattern;
    }
    if (pattern.len == 3 and pattern[0] == '/' and pattern[1] == '*' and pattern[2] == '*') {
        try self.respond_middlewares.global.append(self.allocator, middleware);
        self.respond_middlewares.has_global = true;
        return;
    }
    if (pattern.len == 2 and pattern[0] == '*' and pattern[1] == '*') {
        try self.respond_middlewares.global.append(self.allocator, middleware);
        self.respond_middlewares.has_global = true;
        return;
    }
    if (std.mem.indexOfScalar(u8, pattern, '*') == null) {
        try appendPreciseMiddleware(self.allocator, &self.respond_middlewares.precise, pattern, middleware);
        return;
    }
    for (self.respond_middlewares.wildcard.items) |*entry| {
        if (std.mem.eql(u8, entry.rule.pattern, pattern)) {
            try entry.list.append(self.allocator, middleware);
            return;
        }
    }
    var new_list = std.ArrayList(Middleware).empty;
    try new_list.append(self.allocator, middleware);
    var rule = try PathRule.init(self.allocator, pattern);
    errdefer {
        new_list.deinit(self.allocator);
        rule.deinit();
    }
    try self.respond_middlewares.wildcard.append(self.allocator, .{
        .rule = rule,
        .list = new_list,
    });
}

pub fn ensureNext(self: *AsyncServer) void {
    if (self.next != null) return;
    const kb = if (self.cfg.fiber_stack_size_kb == 0) @as(u16, 64) else self.cfg.fiber_stack_size_kb;
    self.next = Next.init(self.allocator, @as(u32, @intCast(kb)) * 1024);
    self.next.?.setDefault();
}

pub fn register(self: *AsyncServer, method: []const u8, path: []const u8, handler: Handler) !void {
    ensureNext(self);

    if (std.mem.indexOfScalar(u8, path, ':') != null or std.mem.indexOfScalar(u8, path, '*') != null) {
        const method_dup = try self.allocator.dupe(u8, method);
        errdefer self.allocator.free(method_dup);
        const segments = try parseParamPattern(self.allocator, path);
        errdefer freeSegments(self.allocator, segments);
        try self.param_routes.append(self.allocator, .{
            .method = method_dup,
            .segments = segments,
            .handler = handler,
        });
        return;
    }

    const key = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ method, path });
    // If fetchPut fails (hashmap grow OOM), key is not stored — free it.
    errdefer self.allocator.free(key);
    const old = try self.handlers.fetchPut(key, handler);
    if (old) |kv| {
        self.allocator.free(kv.key);
    }
}

pub fn GET(self: *AsyncServer, path: []const u8, handler: Handler) !void {
    try register(self, "GET", path, handler);
}

pub fn POST(self: *AsyncServer, path: []const u8, handler: Handler) !void {
    try register(self, "POST", path, handler);
}

pub fn PUT(self: *AsyncServer, path: []const u8, handler: Handler) !void {
    try register(self, "PUT", path, handler);
}

pub fn PATCH(self: *AsyncServer, path: []const u8, handler: Handler) !void {
    try register(self, "PATCH", path, handler);
}

pub fn DELETE(self: *AsyncServer, path: []const u8, handler: Handler) !void {
    try register(self, "DELETE", path, handler);
}

pub fn ws(self: *AsyncServer, path: []const u8, handler: WsHandler) !void {
    try self.ws_server.register(path, handler);
}

pub fn processBodyRequest(self: *AsyncServer, conn_id: u64, conn: *Connection, body_buf: []u8) void {
    const bid = conn.read_bid;
    const slot = if (conn.pool_idx != 0xFFFFFFFF) &self.pool.slots[conn.pool_idx] else null;
    var owned_request_data: ?[]u8 = null;
    const effective_buf: []const u8 = blk: {
        if (slot) |s| {
            if (s.line3.pending_buffer_ptr != 0) {
                const hw = sticker.httpWork(s);
                const header_len: usize = hw.header_len;
                const saved = @as([*]u8, @ptrFromInt(s.line3.pending_buffer_ptr))[0..header_len];
                s.line3.pending_buffer_ptr = 0;
                // 修改原因：跨分片 header 进入异步 body 读取前会被复制到堆上；这里接管所有权，确保路由看到完整请求行。
                owned_request_data = saved;
                break :blk saved;
            }
        }
        const header_buf = self.buffer_pool.getReadBuf(bid);
        if (slot) |s| {
            const hw = sticker.httpWork(s);
            if (hw.header_len > 0 and hw.header_len <= header_buf.len) {
                break :blk header_buf[0..hw.header_len];
            }
        }
        break :blk header_buf;
    };
    defer {
        if (owned_request_data) |saved| self.allocator.free(saved);
    }
    const path = getPathFromRequestWithLimit(
        effective_buf,
        @as(usize, @intCast(self.cfg.max_path_length)),
    ) orelse {
        // 修改原因：大 body 完整读取后也必须使用配置的 max_path_length，不能退回默认常量或忽略限制。
        self.buffer_pool.markReplenish(bid);
        self.large_pool.release(body_buf);
        conn.read_len = 0;
        self.respond(conn, 400, "Bad Request");
        return;
    };

    if (self.respond_middlewares.has_global or
        self.respond_middlewares.precise.count() > 0 or
        self.respond_middlewares.wildcard.items.len > 0)
    {
        var temp_ctx = Context{
            .request_data = effective_buf,
            .request_body = body_buf,
            .path = path,
            .app_ctx = self.app_ctx,
            .allocator = self.allocator,
            .status = 200,
            .content_type = .plain,
            .body = null,
            .headers = null,
            .conn_id = conn_id,
            .server = @ptrCast(self),
        };
        defer temp_ctx.deinit();
        var matched_respond_middleware = false;

        if (self.respond_middlewares.has_global) {
            matched_respond_middleware = true;
            for (self.respond_middlewares.global.items) |mw| {
                _ = mw(self.allocator, &temp_ctx) catch |err| {
                    logErr("respond middleware error: {s}", .{@errorName(err)});
                    break;
                };
                if (temp_ctx.body != null) break;
            }
        }

        if (temp_ctx.body == null) {
            if (self.respond_middlewares.precise.get(path)) |list| {
                matched_respond_middleware = true;
                for (list.items) |mw| {
                    _ = mw(self.allocator, &temp_ctx) catch |err| {
                        logErr("respond middleware error: {s}", .{@errorName(err)});
                        break;
                    };
                    if (temp_ctx.body != null) break;
                }
            }
        }

        if (temp_ctx.body == null) {
            for (self.respond_middlewares.wildcard.items) |entry| {
                if (entry.rule.match(path)) {
                    matched_respond_middleware = true;
                    for (entry.list.items) |mw| {
                        _ = mw(self.allocator, &temp_ctx) catch |err| {
                            logErr("respond middleware error: {s}", .{@errorName(err)});
                            break;
                        };
                        if (temp_ctx.body != null) break;
                    }
                    if (temp_ctx.body != null) break;
                }
            }
        }

        // 修改原因：当前 path 未命中快速中间件时要继续走普通 handler，不能提前返回空 200。
        if (matched_respond_middleware) {
            self.large_pool.release(body_buf);
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;

            const extra_headers = if (temp_ctx.headers) |h| h.items else "";

            if (temp_ctx.body) |body| {
                if (!self.ensureWriteBuf(conn, 512 + body.len + extra_headers.len)) {
                    self.allocator.free(body);
                    temp_ctx.body = null;
                    self.closeConn(conn_id, conn.fd);
                    return;
                }
                const buf = conn.response_buf.?;
                const mime = switch (temp_ctx.content_type) {
                    .plain => "text/plain",
                    .json => "application/json",
                    .html => "text/html",
                };
                const reason = statusText(temp_ctx.status);
                const conn_hdr = if (conn.keep_alive) "keep-alive" else "close";
                const len = std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\n{s}Content-Length: {d}\r\nConnection: {s}\r\n\r\n{s}", .{ temp_ctx.status, reason, mime, extra_headers, body.len, conn_hdr, body }) catch {
                    self.respondError(conn);
                    return;
                };
                conn.write_headers_len = len.len;
                conn.write_offset = 0;
                conn.write_body = null;
                conn.state = .writing;
                self.submitWrite(conn_id, conn) catch {
                    self.closeConn(conn_id, conn.fd);
                };
            } else if (extra_headers.len > 0) {
                if (!self.ensureWriteBuf(conn, 256 + extra_headers.len)) {
                    self.closeConn(conn_id, conn.fd);
                    return;
                }
                const buf = conn.response_buf.?;
                const conn_hdr = if (conn.keep_alive) "keep-alive" else "close";
                const len = std.fmt.bufPrint(buf, "HTTP/1.1 200 OK\r\n{s}Content-Length: 0\r\nConnection: {s}\r\n\r\n", .{ extra_headers, conn_hdr }) catch {
                    self.respondError(conn);
                    return;
                };
                conn.write_headers_len = len.len;
                conn.write_offset = 0;
                conn.state = .writing;
                self.submitWrite(conn_id, conn) catch {
                    self.closeConn(conn_id, conn.fd);
                };
            } else {
                self.respond(conn, 200, "OK");
            }
            return;
        }
    }

    const has_async = self.middlewares.has_global or
        self.middlewares.precise.count() > 0 or
        self.middlewares.wildcard.items.len > 0 or
        self.handlers.count() > 0;
    if (has_async) {
        const request_data_owned = owned_request_data != null;
        const method_str = getMethodFromRequest(effective_buf) orelse "POST";
        const t = self.http_ctx_pool.create(self.allocator) catch {
            self.buffer_pool.markReplenish(bid);
            self.large_pool.release(body_buf);
            self.respond(conn, 500, "Internal Server Error");
            return;
        };
        const method_cap: u4 = @intCast(@min(method_str.len, 15));
        const path_cap: u8 = @intCast(@min(path.len, 255));
        t.* = .{
            .tag = 0x48540001,
            .server = self,
            .conn_id = conn_id,
            .read_bid = conn.read_bid,
            .method_len = method_cap,
            .path_len = path_cap,
            .request_data = @constCast(effective_buf),
            .request_data_owned = request_data_owned,
            .body_data = @constCast(body_buf),
        };
        if (request_data_owned) owned_request_data = null;
        @memcpy(t.method_buf[0..method_cap], method_str[0..method_cap]);
        @memcpy(t.path_buf[0..path_cap], path[0..path_cap]);

        if (self.shared_fiber_active) {
            if (self.next) |*n| {
                if (n.push(HttpTaskCtx, t.*, httpTaskExecWrapperWithOwnership, self.cfg.fiber_stack_size_kb * 1024)) {
                    self.http_ctx_pool.destroy(t);
                } else {
                    // 修改原因：入队失败时必须释放 body_buf/read buffer，避免大块池泄漏。
                    http_fiber.httpTaskCleanup(t);
                    self.respond(conn, 503, "Service Unavailable");
                }
            } else {
                http_fiber.httpTaskCleanup(t);
                self.respond(conn, 503, "Service Unavailable");
            }
        } else {
            var fiber = Fiber.init(self.shared_fiber_stack);
            self.shared_fiber_active = true;
            fiber.exec(.{
                .userCtx = t,
                .complete = httpTaskComplete,
                .execFn = httpTaskExec,
            });
        }
        conn.read_len = 0;
        return;
    }

    self.large_pool.release(body_buf);
    self.buffer_pool.markReplenish(bid);
    conn.read_len = 0;
    self.respond(conn, 404, "Not Found");
}

fn testMiddleware(_: Allocator, _: *Context) anyerror!bool {
    return true;
}

fn deinitPreciseMiddlewareMap(allocator: Allocator, precise: *std.StringHashMap(std.ArrayList(Middleware))) void {
    var it = precise.iterator();
    while (it.next()) |entry| {
        entry.value_ptr.deinit(allocator);
        allocator.free(entry.key_ptr.*);
    }
    precise.deinit();
}

test "appendPreciseMiddleware rolls back inserted key on append failure" {
    for (0..8) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        const allocator = failing.allocator();
        var precise = std.StringHashMap(std.ArrayList(Middleware)).init(allocator);
        defer deinitPreciseMiddlewareMap(allocator, &precise);

        appendPreciseMiddleware(allocator, &precise, "/oom", testMiddleware) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(@as(usize, 0), precise.count());
            continue;
        };

        try std.testing.expectEqual(@as(usize, 1), precise.count());
    }
}

test "parseParamPattern handles mixed literal and param segments" {
    const allocator = std.testing.allocator;
    const segments = try parseParamPattern(allocator, "/users/:id/posts/:postId");
    defer freeSegments(allocator, segments);

    try std.testing.expectEqual(@as(usize, 4), segments.len);
    try std.testing.expect(segments[0] == .literal);
    try std.testing.expectEqualStrings("users", segments[0].literal);
    try std.testing.expect(segments[1] == .param);
    try std.testing.expectEqualStrings("id", segments[1].param);
    try std.testing.expect(segments[2] == .literal);
    try std.testing.expectEqualStrings("posts", segments[2].literal);
    try std.testing.expect(segments[3] == .param);
    try std.testing.expectEqualStrings("postId", segments[3].param);
}

test "parseParamPattern handles wildcard" {
    const allocator = std.testing.allocator;
    const segments = try parseParamPattern(allocator, "/static/*");
    defer freeSegments(allocator, segments);

    try std.testing.expectEqual(@as(usize, 2), segments.len);
    try std.testing.expect(segments[0] == .literal);
    try std.testing.expectEqualStrings("static", segments[0].literal);
    try std.testing.expect(segments[1] == .wildcard);
}

test "matchParamRoute extracts single and multiple params" {
    const allocator = std.testing.allocator;
    const segments = try parseParamPattern(allocator, "/users/:userId/posts/:postId");
    defer freeSegments(allocator, segments);

    const route = ParamRoute{
        .method = "GET",
        .segments = segments,
        .handler = undefined,
    };

    var params_buf: [16]RouteParam = undefined;

    const count = matchParamRoute(route, "/users/42/posts/99", &params_buf);
    try std.testing.expect(count != null);
    try std.testing.expectEqual(@as(usize, 2), count.?);
    try std.testing.expectEqualStrings("userId", params_buf[0].name);
    try std.testing.expectEqualStrings("42", params_buf[0].value);
    try std.testing.expectEqualStrings("postId", params_buf[1].name);
    try std.testing.expectEqualStrings("99", params_buf[1].value);
}

test "matchParamRoute returns null on mismatch" {
    const allocator = std.testing.allocator;
    const segments = try parseParamPattern(allocator, "/users/:id");
    defer freeSegments(allocator, segments);

    const route = ParamRoute{
        .method = "GET",
        .segments = segments,
        .handler = undefined,
    };

    var params_buf: [16]RouteParam = undefined;

    try std.testing.expect(matchParamRoute(route, "/posts/42", &params_buf) == null);
    try std.testing.expect(matchParamRoute(route, "/users/42/extra", &params_buf) == null);
    try std.testing.expect(matchParamRoute(route, "/users", &params_buf) == null);
}

test "Context.param looks up captured path params" {
    const ctx = Context{
        .request_data = "GET /users/42 HTTP/1.1\r\n\r\n",
        .path = "/users/42",
        .app_ctx = null,
        .allocator = std.testing.allocator,
        .params = &.{
            .{ .name = "id", .value = "42" },
        },
    };
    try std.testing.expectEqualStrings("42", ctx.param("id").?);
    try std.testing.expect(ctx.param("name") == null);
}
