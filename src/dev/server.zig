const std = @import("std");
const Allocator = std.mem.Allocator;

const Context = @import("../http/context.zig").Context;
const RouteParam = @import("../http/context.zig").RouteParam;
const Handler = @import("../http/types.zig").Handler;
const Middleware = @import("../http/types.zig").Middleware;
const MiddlewareStore = @import("../http/middleware_store.zig").MiddlewareStore;
const helpers = @import("../http/http_helpers.zig");
const upgrade = @import("../ws/upgrade.zig");
const frame = @import("../ws/frame.zig");
const Opcode = @import("../ws/types.zig").Opcode;
const WsHandler = @import("../ws/server.zig").WsHandler;
const WsServer = @import("../ws/server.zig").WsServer;
const logErr = helpers.logErr;

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

const MAX_PARAMS: usize = 16;

fn parseParamPattern(allocator: Allocator, pattern: []const u8) ![]const Segment {
    var segments = std.ArrayList(Segment).empty;
    errdefer {
        for (segments.items) |seg| {
            if (seg == .literal) allocator.free(seg.literal);
            if (seg == .param) allocator.free(seg.param);
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

fn freeSegments(allocator: Allocator, segments: []const Segment) void {
    for (segments) |seg| {
        if (seg == .literal) allocator.free(seg.literal);
        if (seg == .param) allocator.free(seg.param);
    }
    allocator.free(segments);
}

fn matchParamRoute(route: ParamRoute, path: []const u8, params: *[MAX_PARAMS]RouteParam) ?usize {
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
                } else return null;
            },
            .wildcard => return param_idx,
        }
        seg_idx += 1;
    }
    return if (seg_idx == route.segments.len) param_idx else null;
}

pub const DevServer = struct {
    allocator: Allocator,
    listener: std.net.Server,
    handlers: std.StringHashMap(Handler),
    param_routes: std.ArrayList(ParamRoute),
    middlewares: MiddlewareStore,
    ws_server: WsServer,
    ws_streams: std.AutoHashMap(u64, std.net.Stream),
    shutdown: bool,
    next_conn_id: u64,

    pub fn init(allocator: Allocator, bind_addr: []const u8) !DevServer {
        const addr = try std.net.Address.parseIp4(bind_addr, 0);
        const listener = try addr.listen(.{
            .reuse_address = true,
            .force_nonblocking = false,
        });
        errdefer listener.deinit();

        return DevServer{
            .allocator = allocator,
            .listener = listener,
            .handlers = std.StringHashMap(Handler).init(allocator),
            .param_routes = std.ArrayList(ParamRoute).empty,
            .middlewares = MiddlewareStore.init(allocator),
            .ws_server = WsServer.init(allocator, wsSendFn),
            .ws_streams = std.AutoHashMap(u64, std.net.Stream).init(allocator),
            .shutdown = false,
            .next_conn_id = 1,
        };
    }

    pub fn deinit(self: *DevServer) void {
        self.listener.deinit();
        {
            var it = self.handlers.iterator();
            while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        }
        self.handlers.deinit();
        for (self.param_routes.items) |*pr| {
            freeSegments(self.allocator, pr.segments);
            self.allocator.free(pr.method);
        }
        self.param_routes.deinit(self.allocator);
        self.middlewares.deinit(self.allocator);
        self.ws_server.deinit();
        self.ws_streams.deinit();
    }

    pub fn port(self: *const DevServer) u16 {
        return self.listener.listen_address.getPort();
    }

    fn register(self: *DevServer, method: []const u8, path: []const u8, handler: Handler) !void {
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
        errdefer self.allocator.free(key);
        const old = try self.handlers.fetchPut(key, handler);
        if (old) |kv| self.allocator.free(kv.key);
    }

    pub fn GET(self: *DevServer, path: []const u8, handler: Handler) !void {
        try self.register("GET", path, handler);
    }
    pub fn POST(self: *DevServer, path: []const u8, handler: Handler) !void {
        try self.register("POST", path, handler);
    }
    pub fn PUT(self: *DevServer, path: []const u8, handler: Handler) !void {
        try self.register("PUT", path, handler);
    }
    pub fn PATCH(self: *DevServer, path: []const u8, handler: Handler) !void {
        try self.register("PATCH", path, handler);
    }
    pub fn DELETE(self: *DevServer, path: []const u8, handler: Handler) !void {
        try self.register("DELETE", path, handler);
    }
    pub fn ws(self: *DevServer, path: []const u8, handler: WsHandler) !void {
        try self.ws_server.register(path, handler);
    }

    pub fn run(self: *DevServer) !void {
        std.debug.print("DevServer listening on http://127.0.0.1:{d}\n", .{self.port()});

        self.ws_server.ctx = @ptrCast(self);

        while (!@atomicLoad(bool, &self.shutdown, .acquire)) {
            const conn = self.listener.accept() catch |err| {
                logErr("accept error: {s}", .{@errorName(err)});
                continue;
            };
            const conn_alloc = self.allocator;
            const server_ptr = self;
            _ = try std.Thread.spawn(.{}, handleConn, .{ server_ptr, conn, conn_alloc });
        }
    }

    fn nextId(self: *DevServer) u64 {
        const id = self.next_conn_id;
        self.next_conn_id +%= 1;
        return id;
    }

    fn handleConn(self: *DevServer, conn: std.net.Server.Connection, alloc: Allocator) void {
        defer conn.stream.close();

        var buf: [65536]u8 = undefined;
        const n = conn.stream.read(buf[0..]) catch |err| {
            logErr("read error: {s}", .{@errorName(err)});
            return;
        };
        if (n == 0) return;

        const req_data: []const u8 = buf[0..n];

        if (upgrade.isUpgradeRequest(req_data)) {
            self.handleWs(conn, req_data) catch |err| {
                logErr("ws upgrade failed: {s}", .{@errorName(err)});
            };
            return;
        }

        self.handleHttp(conn, req_data, alloc) catch |err| {
            logErr("http handler failed: {s}", .{@errorName(err)});
        };
    }

    fn handleHttp(self: *DevServer, conn: std.net.Server.Connection, req_data: []const u8, alloc: Allocator) !void {
        const path = helpers.getPathFromRequest(req_data) orelse {
            try writeResponse(conn, 400, "text/plain", "Bad Request", &.{});
            return;
        };
        const method = helpers.getMethodFromRequest(req_data) orelse "GET";
        const body_start = blk: {
            const sep = std.mem.indexOf(u8, req_data, "\r\n\r\n");
            if (sep) |s| break :blk s + 4;
            const lf_sep = std.mem.indexOf(u8, req_data, "\n\n");
            if (lf_sep) |s| break :blk s + 2;
            break :blk req_data.len;
        };

        var ctx = Context{
            .request_data = req_data,
            .request_body = req_data[body_start..],
            .path = path,
            .app_ctx = null,
            .allocator = alloc,
            .status = 200,
            .content_type = .plain,
            .body = null,
            .headers = null,
            .conn_id = 0,
            .params = &.{},
        };
        defer ctx.deinit();

        var handled = false;
        if (self.middlewares.has_global) {
            for (self.middlewares.global.items) |mw| {
                const stop = mw(alloc, &ctx) catch |err| {
                    try writeError(conn, 500, @errorName(err));
                    return;
                };
                if (stop or ctx.body != null) { handled = true; break; }
            }
        }
        if (!handled) {
            if (self.middlewares.precise.get(path)) |list| {
                for (list.items) |mw| {
                    const stop = mw(alloc, &ctx) catch |err| {
                        try writeError(conn, 500, @errorName(err));
                        return;
                    };
                    if (stop or ctx.body != null) { handled = true; break; }
                }
            }
        }
        if (!handled) {
            for (self.middlewares.wildcard.items) |entry| {
                if (entry.rule.match(path)) {
                    for (entry.list.items) |mw| {
                        const stop = mw(alloc, &ctx) catch |err| {
                            try writeError(conn, 500, @errorName(err));
                            return;
                        };
                        if (stop or ctx.body != null) { handled = true; break; }
                    }
                    if (handled) break;
                }
            }
        }
        if (!handled) {
            var key_buf: [512]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "{s}:{s}", .{ method, path }) catch null;
            if (key) |k| {
                if (self.handlers.get(k)) |handler| {
                    handler(alloc, &ctx) catch |err| {
                        try writeError(conn, 500, @errorName(err));
                        return;
                    };
                } else {
                    var params_buf: [MAX_PARAMS]RouteParam = undefined;
                    if (findParamRoute(self.param_routes.items, method, path, &params_buf)) |result| {
                        ctx.params = params_buf[0..result.param_count];
                        result.handler(alloc, &ctx) catch |err| {
                            try writeError(conn, 500, @errorName(err));
                            return;
                        };
                    } else {
                        try writeError(conn, 404, "Not Found");
                        return;
                    }
                }
            } else {
                try writeError(conn, 404, "Not Found");
                return;
            }
        }

        const content_type = switch (ctx.content_type) {
            .plain => "text/plain",
            .json => "application/json",
            .html => "text/html",
        };
        const extra_headers = if (ctx.headers) |h| h.items else "";
        const body = ctx.body orelse "";
        try writeResponse(conn, ctx.status, content_type, body, extra_headers);
    }

    fn handleWs(self: *DevServer, conn: std.net.Server.Connection, req_data: []const u8) !void {
        const path = helpers.getPathFromRequest(req_data) orelse {
            try writeResponse(conn, 400, "text/plain", "Bad Request", &.{});
            return;
        };
        const handler = self.ws_server.getHandler(path) orelse {
            try writeResponse(conn, 404, "text/plain", "WebSocket handler not found for this path", &.{});
            return;
        };

        const key = upgrade.extractWsKey(req_data) orelse {
            try writeResponse(conn, 400, "text/plain", "Missing Sec-WebSocket-Key", &.{});
            return;
        };
        var accept_buf: [29]u8 = undefined;
        upgrade.computeAcceptKey(key, &accept_buf) catch {
            try writeResponse(conn, 400, "text/plain", "Invalid Sec-WebSocket-Key", &.{});
            return;
        };

        var handshake: [256]u8 = undefined;
        const hs = try std.fmt.bufPrint(&handshake,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n",
            .{accept_buf[0..28]},
        );
        _ = try conn.stream.write(hs);

        const conn_id = self.nextId();
        try self.ws_server.addActive(conn_id, handler);
        try self.ws_streams.put(conn_id, conn.stream);
        defer {
            self.ws_server.removeActive(conn_id);
            _ = self.ws_streams.remove(conn_id);
        }

        var read_buf: [65536]u8 = undefined;
        while (true) {
            const n = conn.stream.read(read_buf[0..]) catch |err| {
                logErr("ws read error: {s}", .{@errorName(err)});
                break;
            };
            if (n == 0) break;

            const parsed = frame.parseFrame(read_buf[0..n]) catch |err| {
                logErr("ws frame parse error: {s}", .{@errorName(err)});
                break;
            };

            if (parsed.opcode == .text or parsed.opcode == .binary) {
                handler(conn_id, &parsed, @ptrCast(self));
            } else if (parsed.opcode == .ping) {
                const pong = try frame.writeFrame(&read_buf, .{ .opcode = .pong, .fin = true, .payload = parsed.payload });
                _ = conn.stream.write(read_buf[0..pong]) catch break;
            } else if (parsed.opcode == .close) {
                const close_resp = frame.writeFrame(&read_buf, .{ .opcode = .close, .fin = true, .payload = parsed.payload }) catch {
                    break;
                };
                _ = conn.stream.write(read_buf[0..close_resp]) catch {};
                break;
            }
        }
    }

    const ParamMatchResult = struct { handler: Handler, param_count: usize };

    fn findParamRoute(routes: []const ParamRoute, method: []const u8, path: []const u8, params: *[MAX_PARAMS]RouteParam) ?ParamMatchResult {
        for (routes) |route| {
            if (!std.mem.eql(u8, route.method, method)) continue;
            if (matchParamRoute(route, path, params)) |param_count| {
                return .{ .handler = route.handler, .param_count = param_count };
            }
        }
        return null;
    }

    fn wsSendFn(ctx: *anyopaque, conn_id: u64, opcode: Opcode, payload: []const u8) !void {
        const s: *DevServer = @ptrCast(@alignCast(ctx));
        const stream = s.ws_streams.get(conn_id) orelse return error.ConnectionNotFound;
        var buf: [65536]u8 = undefined;
        const total = try frame.writeFrame(&buf, .{ .opcode = opcode, .fin = true, .payload = payload });
        _ = try stream.write(buf[0..total]);
    }
};

fn writeResponse(conn: std.net.Server.Connection, status: u16, content_type: []const u8, body: []const u8, extra_headers: []const u8) !void {
    var buf: [4096]u8 = undefined;
    const reason = switch (status) {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        else => "Unknown",
    };
    const pos = if (body.len > 0)
        try std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\n{s}Content-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status, reason, content_type, extra_headers, body.len, body })
    else
        try std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\n{s}Content-Length: 0\r\nConnection: close\r\n\r\n", .{ status, reason, content_type, extra_headers });
    _ = try conn.stream.write(buf[0..pos.len]);
}

fn writeError(conn: std.net.Server.Connection, status: u16, msg: []const u8) !void {
    try writeResponse(conn, status, "text/plain", msg, &.{});
}
