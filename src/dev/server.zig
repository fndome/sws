const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag == .linux) {
        @compileError("DevServer is for non-Linux dev only. Use sws.AsyncServer (io_uring) on Linux.");
    }
}

const Context = @import("../http/context.zig").Context;
const RouteParam = @import("../http/context.zig").RouteParam;
const Handler = @import("../http/types.zig").Handler;
const Middleware = @import("../http/types.zig").Middleware;
const MiddlewareStore = @import("../http/middleware_store.zig").MiddlewareStore;
const WildcardEntry = @import("../http/middleware_store.zig").WildcardEntry;
const helpers = @import("../http/http_helpers.zig");
const upgrade = @import("../ws/upgrade.zig");
const frame = @import("../ws/frame.zig");
const Opcode = @import("../ws/types.zig").Opcode;
const WsHandler = @import("../ws/server.zig").WsHandler;
const WsServer = @import("../ws/server.zig").WsServer;
const io = @import("io.zig");
const logErr = helpers.logErr;

pub const Segment = union(enum) { literal: []const u8, param: []const u8, wildcard: void };
pub const ParamRoute = struct { method: []const u8, segments: []const Segment, handler: Handler };
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
        if (std.mem.eql(u8, part, "*")) { try segments.append(allocator, .wildcard); }
        else if (part[0] == ':') { try segments.append(allocator, .{ .param = try allocator.dupe(u8, part[1..]) }); }
        else { try segments.append(allocator, .{ .literal = try allocator.dupe(u8, part) }); }
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
        switch (route.segments[seg_idx]) {
            .literal => |lit| { if (!std.mem.eql(u8, lit, part)) return null; },
            .param => |name| {
                if (param_idx >= params.len) return null;
                params[param_idx] = .{ .name = name, .value = part };
                param_idx += 1;
            },
            .wildcard => return param_idx,
        }
        seg_idx += 1;
    }
    return if (seg_idx == route.segments.len) param_idx else null;
}

fn ip4Parse(ip_str: []const u8) ![4]u8 {
    var parts: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, ip_str, '.');
    for (0..4) |i| parts[i] = std.fmt.parseInt(u8, it.next() orelse return error.InvalidIp, 10) catch return error.InvalidIp;
    if (it.next() != null) return error.InvalidIp;
    return parts;
}

pub const DevServer = struct {
    allocator: Allocator,
    sock: io.Socket,
    listen_port: u16,
    app_ctx: ?*anyopaque,
    handlers: std.StringHashMap(Handler),
    param_routes: std.ArrayList(ParamRoute),
    middlewares: MiddlewareStore,
    ws_server: WsServer,
    ws_streams: std.AutoHashMap(u64, io.Socket),
    shutdown: bool,
    next_conn_id: u64,

    pub fn init(allocator: Allocator, bind_addr: []const u8, app_ctx: ?*anyopaque) !DevServer {
        const colon = std.mem.indexOfScalar(u8, bind_addr, ':') orelse return error.InvalidListenAddress;
        const ip = try ip4Parse(bind_addr[0..colon]);
        const addr_port = try std.fmt.parseInt(u16, bind_addr[colon + 1 ..], 10);

        const fd = try io.tcpSocket();
        errdefer io.closeSocket(fd);

        io.setReuseAddr(fd);
        try io.bindSocket(fd, ip, addr_port);
        try io.listenSocket(fd);

        return DevServer{
            .allocator = allocator,
            .sock = fd,
            .listen_port = addr_port,
            .app_ctx = app_ctx,
            .handlers = std.StringHashMap(Handler).init(allocator),
            .param_routes = std.ArrayList(ParamRoute).empty,
            .middlewares = .{
                .has_global = false,
                .global = std.ArrayList(Middleware).empty,
                .precise = std.StringHashMap(std.ArrayList(Middleware)).init(allocator),
                .wildcard = std.ArrayList(WildcardEntry).empty,
            },
            .ws_server = WsServer.init(allocator, wsSendFn),
            .ws_streams = std.AutoHashMap(u64, io.Socket).init(allocator),
            .shutdown = false,
            .next_conn_id = 1,
        };
    }

    pub fn deinit(self: *DevServer) void {
        io.closeSocket(self.sock);
        var it = self.handlers.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.handlers.deinit();
        for (self.param_routes.items) |*pr| { freeSegments(self.allocator, pr.segments); self.allocator.free(pr.method); }
        self.param_routes.deinit(self.allocator);
        self.middlewares.deinit(self.allocator);
        self.ws_server.deinit();
        self.ws_streams.deinit();
    }

    pub fn port(self: *const DevServer) u16 { return self.listen_port; }

    fn register(self: *DevServer, method: []const u8, path: []const u8, handler: Handler) !void {
        if (std.mem.indexOfScalar(u8, path, ':') != null or std.mem.indexOfScalar(u8, path, '*') != null) {
            const m = try self.allocator.dupe(u8, method); errdefer self.allocator.free(m);
            const segs = try parseParamPattern(self.allocator, path); errdefer freeSegments(self.allocator, segs);
            try self.param_routes.append(self.allocator, .{ .method = m, .segments = segs, .handler = handler });
            return;
        }
        const key = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ method, path });
        errdefer self.allocator.free(key);
        if (try self.handlers.fetchPut(key, handler)) |old| self.allocator.free(old.key);
    }

    pub fn GET(self: *DevServer, p: []const u8, h: Handler) !void { try self.register("GET", p, h); }
    pub fn POST(self: *DevServer, p: []const u8, h: Handler) !void { try self.register("POST", p, h); }
    pub fn PUT(self: *DevServer, p: []const u8, h: Handler) !void { try self.register("PUT", p, h); }
    pub fn PATCH(self: *DevServer, p: []const u8, h: Handler) !void { try self.register("PATCH", p, h); }
    pub fn DELETE(self: *DevServer, p: []const u8, h: Handler) !void { try self.register("DELETE", p, h); }
    pub fn ws(self: *DevServer, p: []const u8, h: WsHandler) !void { try self.ws_server.register(p, h); }

    pub fn run(self: *DevServer) !void {
        std.debug.print("DevServer listening on http://127.0.0.1:{d}\n", .{self.listen_port});
        self.ws_server.ctx = @ptrCast(self);

        while (!@atomicLoad(bool, &self.shutdown, .acquire)) {
            const fd = io.acceptSocket(self.sock) catch { continue; };
            _ = try std.Thread.spawn(.{}, handleConn, .{ self, fd, self.allocator });
        }
    }

    fn readReq(fd: io.Socket, buf: []u8) ![]const u8 {
        var total: usize = 0;
        while (total < buf.len) {
            const n = io.recv(fd, buf[total..]) catch return error.ReadFailed;
            if (n == 0) break;
            total += n;
            if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) break;
            if (std.mem.indexOf(u8, buf[0..total], "\n\n") != null) break;
        }
        return buf[0..total];
    }

    fn handleConn(self: *DevServer, fd: io.Socket, alloc: Allocator) void {
        defer io.closeSocket(fd);
        var buf: [65536]u8 = undefined;
        const data = readReq(fd, buf[0..]) catch |e| { logErr("read: {s}", .{@errorName(e)}); return; };
        if (data.len == 0) return;

        if (upgrade.isUpgradeRequest(data)) {
            self.handleWs(fd, data) catch |e| { logErr("ws: {s}", .{@errorName(e)}); };
            return;
        }
        self.handleHttp(fd, data, alloc) catch |e| { logErr("http: {s}", .{@errorName(e)}); };
    }

    fn handleHttp(self: *DevServer, fd: io.Socket, req_data: []const u8, alloc: Allocator) !void {
        const path = helpers.getPathFromRequest(req_data) orelse { try writeError(fd, 400, "Bad Request"); return; };
        const method = helpers.getMethodFromRequest(req_data) orelse "GET";
        const body_start = blk: {
            if (std.mem.indexOf(u8, req_data, "\r\n\r\n")) |s| break :blk s + 4;
            if (std.mem.indexOf(u8, req_data, "\n\n")) |s| break :blk s + 2;
            break :blk req_data.len;
        };
        var ctx = Context{
            .request_data = req_data, .request_body = req_data[body_start..], .path = path,
            .app_ctx = self.app_ctx, .allocator = alloc,
            .status = 200, .content_type = .plain, .body = null, .headers = null, .conn_id = 0, .params = &.{},
        };
        defer ctx.deinit();

        var handled = false;
        if (self.middlewares.has_global) for (self.middlewares.global.items) |mw| {
            if (mw(alloc, &ctx) catch |e| brk: { try writeError(fd, 500, @errorName(e)); break :brk true; } or ctx.body != null) { handled = true; break; }
        };
        if (!handled) if (self.middlewares.precise.get(path)) |list| for (list.items) |mw| {
            if (mw(alloc, &ctx) catch |e| brk: { try writeError(fd, 500, @errorName(e)); break :brk true; } or ctx.body != null) { handled = true; break; }
        };
        if (!handled) for (self.middlewares.wildcard.items) |entry| {
            if (!entry.rule.match(path)) continue;
            for (entry.list.items) |mw| {
                if (mw(alloc, &ctx) catch |e| brk: { try writeError(fd, 500, @errorName(e)); break :brk true; } or ctx.body != null) { handled = true; break; }
            }
            if (handled) break;
        };
        if (!handled) {
            var kb: [512]u8 = undefined;
            if (std.fmt.bufPrint(&kb, "{s}:{s}", .{ method, path })) |k| {
                if (self.handlers.get(k)) |h| {
                    h(alloc, &ctx) catch |e| { try writeError(fd, 500, @errorName(e)); return; };
                } else {
                    var pb: [MAX_PARAMS]RouteParam = undefined;
                    if (findParamRoute(self.param_routes.items, method, path, &pb)) |r| {
                        ctx.params = pb[0..r.param_count];
                        r.handler(alloc, &ctx) catch |e| { try writeError(fd, 500, @errorName(e)); return; };
                    } else { try writeError(fd, 404, "Not Found"); return; }
                }
            } else |_| { try writeError(fd, 404, "Not Found"); return; }
        }

        const ct = switch (ctx.content_type) { .plain => "text/plain", .json => "application/json", .html => "text/html" };
        const eh = if (ctx.headers) |h| h.items else "";
        const body = ctx.body orelse "";
        try writeResponse(fd, ctx.status, ct, body, eh);
    }

    fn handleWs(self: *DevServer, fd: io.Socket, req_data: []const u8) !void {
        const path = helpers.getPathFromRequest(req_data) orelse { try writeError(fd, 400, "Bad Request"); return; };
        const handler = self.ws_server.getHandler(path) orelse { try writeError(fd, 404, "WS not found"); return; };
        const key = upgrade.extractWsKey(req_data) orelse { try writeError(fd, 400, "Missing key"); return; };
        var ab: [29]u8 = undefined;
        upgrade.computeAcceptKey(key, &ab) catch { try writeError(fd, 400, "Invalid key"); return; };
        var hb: [256]u8 = undefined;
        const hs = try std.fmt.bufPrint(&hb, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{ab[0..28]});
        _ = try writeAll(fd, hs);

        const cid = blk: { const id = self.next_conn_id; self.next_conn_id +%= 1; break :blk id; };
        try self.ws_server.addActive(cid, handler);
        try self.ws_streams.put(cid, fd);
        defer { self.ws_server.removeActive(cid); _ = self.ws_streams.remove(cid); }

        var rb: [65536]u8 = undefined;
        while (true) {
            const nr = io.recv(fd, rb[0..]) catch break;
            if (nr == 0) break;
            const parsed = frame.parseFrame(rb[0..nr]) catch |e| { logErr("ws parse: {s}", .{@errorName(e)}); break; };
            switch (parsed.opcode) {
                .text, .binary => handler(cid, &parsed, @ptrCast(self)),
                .ping => { const pong = try frame.writeFrame(&rb, .{ .opcode = .pong, .fin = true, .payload = parsed.payload }); _ = writeAll(fd, rb[0..pong]) catch break; },
                .close => { const cr = frame.writeFrame(&rb, .{ .opcode = .close, .fin = true, .payload = parsed.payload }) catch break; _ = writeAll(fd, rb[0..cr]) catch {}; break; },
                else => {},
            }
        }
    }

    fn findParamRoute(routes: []const ParamRoute, method: []const u8, path: []const u8, params: *[MAX_PARAMS]RouteParam) ?struct { handler: Handler, param_count: usize } {
        for (routes) |r| if (std.mem.eql(u8, r.method, method)) if (matchParamRoute(r, path, params)) |pc| return .{ .handler = r.handler, .param_count = pc };
        return null;
    }

    fn wsSendFn(ctx: *anyopaque, conn_id: u64, opcode: Opcode, payload: []const u8) !void {
        const s: *DevServer = @ptrCast(@alignCast(ctx));
        const fd = s.ws_streams.get(conn_id) orelse return error.ConnectionNotFound;
        var wb: [65536]u8 = undefined;
        _ = try writeAll(fd, wb[0..try frame.writeFrame(&wb, .{ .opcode = opcode, .fin = true, .payload = payload })]);
    }
};

fn writeAll(fd: io.Socket, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const n = try io.send(fd, data[off..]);
        off += n;
    }
}

fn writeResponse(fd: io.Socket, status: u16, ct: []const u8, body: []const u8, eh: []const u8) !void {
    var buf: [4096]u8 = undefined;
    const reason = switch (status) {
        200 => "OK", 201 => "Created", 204 => "No Content",
        400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden",
        404 => "Not Found", 500 => "Internal Server Error",
        else => "Unknown",
    };
    const msg = if (body.len > 0)
        try std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\n{s}Content-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status, reason, ct, eh, body.len, body })
    else
        try std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\n{s}Content-Length: 0\r\nConnection: close\r\n\r\n", .{ status, reason, ct, eh });
    _ = try writeAll(fd, buf[0..msg.len]);
}

fn writeError(fd: io.Socket, status: u16, msg: []const u8) !void { try writeResponse(fd, status, "text/plain", msg, &.{}); }
