const std = @import("std");
const Allocator = std.mem.Allocator;

fn isHeaderNameChar(ch: u8) bool {
    const token_symbols = "!#$%&'*+-.^_`|~";
    return (ch >= 'A' and ch <= 'Z') or
        (ch >= 'a' and ch <= 'z') or
        (ch >= '0' and ch <= '9') or
        std.mem.indexOfScalar(u8, token_symbols, ch) != null;
}

fn isManagedResponseHeader(key: []const u8) bool {
    return std.ascii.eqlIgnoreCase(key, "content-length") or
        std.ascii.eqlIgnoreCase(key, "connection") or
        std.ascii.eqlIgnoreCase(key, "content-type") or
        std.ascii.eqlIgnoreCase(key, "transfer-encoding");
}

fn validateResponseHeader(key: []const u8, value: []const u8) !void {
    // setHeader serializes directly into response headers, so it must reject invalid names, CR/LF, and framework-generated headers to avoid injection and duplicate boundary headers.
    if (key.len == 0) return error.InvalidHeader;
    for (key) |ch| {
        if (!isHeaderNameChar(ch)) return error.InvalidHeader;
    }
    if (isManagedResponseHeader(key)) return error.InvalidHeader;
    for (value) |ch| {
        if (ch == '\r' or ch == '\n') return error.InvalidHeader;
    }
}

pub const RouteParam = @import("route_match.zig").RouteParam;

pub const Context = struct {
    pub const ContentType = enum { plain, json, html };

    request_data: []const u8,
    // The request body must not reuse the response body field, or POST would be misjudged as already responded.
    request_body: []const u8 = "",
    path: []const u8,
    app_ctx: ?*anyopaque,

    status: u16 = 200,
    content_type: ContentType = .plain,
    body: ?[]u8 = null,
    headers: ?std.ArrayList(u8) = null,

    allocator: Allocator,

    conn_id: u64 = 0,
    deferred: bool = false,
    server: ?*anyopaque = null,
    /// Path parameters extracted from a parameterized route (/users/:id).
    /// Slice is borrowed from a stack-local buffer, never heap-allocated.
    params: []const RouteParam = &.{},

    /// Returns a ResponseBuilder for building the response (see ResponseBuilder).
    pub fn response(self: *Context) ResponseBuilder {
        return ResponseBuilder.init(self);
    }

    pub fn json(self: *Context, status: u16, value: anytype) !void {
        self.status = status;
        self.content_type = .json;
        // Save old, null field, then free — if dupe fails, body is null
        // rather than a dangling pointer to freed memory.
        const old = self.body;
        self.body = null;
        if (old) |b| self.allocator.free(b);
        self.body = try std.json.Stringify.valueAlloc(self.allocator, value, .{});
    }

    pub fn rawJson(self: *Context, status: u16, data: []const u8) !void {
        self.status = status;
        self.content_type = .json;
        const old = self.body;
        self.body = null;
        if (old) |b| self.allocator.free(b);
        self.body = try self.allocator.dupe(u8, data);
    }

    pub fn text(self: *Context, status: u16, data: []const u8) !void {
        self.status = status;
        self.content_type = .plain;
        const old = self.body;
        self.body = null;
        if (old) |b| self.allocator.free(b);
        self.body = try self.allocator.dupe(u8, data);
    }

    pub fn html(self: *Context, status: u16, data: []const u8) !void {
        self.status = status;
        self.content_type = .html;
        const old = self.body;
        self.body = null;
        if (old) |b| self.allocator.free(b);
        self.body = try self.allocator.dupe(u8, data);
    }

    pub fn setHeader(self: *Context, key: []const u8, value: []const u8) !void {
        try validateResponseHeader(key, value);
        if (self.headers == null) {
            self.headers = std.ArrayList(u8).empty;
        }
        try self.headers.?.print(self.allocator, "{s}: {s}\r\n", .{ key, value });
    }

    pub fn getHeader(self: *Context, key: []const u8) ?[]const u8 {
        const header_name = if (key.len > 0 and key[key.len - 1] == ':') key[0 .. key.len - 1] else key;
        var lines = std.mem.splitScalar(u8, self.request_data, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, "\r");
            if (line.len == 0) break;
            if (std.ascii.startsWithIgnoreCase(line, header_name)) {
                if (line.len <= header_name.len) return null;
                const after = line[header_name.len..];
                // Support both CRLF and LF-only request headers, but still require a colon immediately after the header name so Host does not mismatch Hostile.
                if (after[0] == ':') return std.mem.trim(u8, after[1..], " \t\r\n");
            }
        }
        return null;
    }

    /// Extract a parameter value from the query string of the request path, e.g. ctx.query("to").
    pub fn query(self: *Context, name: []const u8) ?[]const u8 {
        const line_end = std.mem.indexOf(u8, self.request_data, "\r\n") orelse
            std.mem.indexOfScalar(u8, self.request_data, '\n') orelse
            self.request_data.len;
        const first_line = self.request_data[0..line_end];
        const method_end = std.mem.indexOfScalar(u8, first_line, ' ') orelse return null;
        // Old code truncated first_line at the first space, leaving only the method, so query never matched.
        const uri_part = std.mem.trimStart(u8, first_line[method_end + 1 ..], " ");
        const uri = uri_part[0..(std.mem.indexOfScalar(u8, uri_part, ' ') orelse uri_part.len)];

        const q_pos = std.mem.indexOfScalar(u8, uri, '?') orelse return null;
        const qs = uri[q_pos + 1 ..];
        var it = std.mem.splitScalar(u8, qs, '&');
        while (it.next()) |pair| {
            const eq_pos = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
            const key = pair[0..eq_pos];
            if (std.mem.eql(u8, key, name)) {
                return pair[eq_pos + 1 ..];
            }
        }
        return null;
    }

    /// Returns the value of a captured path parameter (e.g. :id in /users/:id).
    pub fn param(self: *const Context, name: []const u8) ?[]const u8 {
        for (self.params) |p| {
            if (std.mem.eql(u8, p.name, name)) return p.value;
        }
        return null;
    }

    /// Get the POST/PUT/PATCH request body.
    /// Takes the length from Content-Length automatically; returns an empty string when there is no body.
    pub fn requestBody(self: *Context) []const u8 {
        if (self.request_body.len > 0) return self.request_body;
        const header_end = std.mem.indexOf(u8, self.request_data, "\r\n\r\n") orelse
            std.mem.indexOf(u8, self.request_data, "\n\n") orelse
            return "";
        const sep: usize = if (self.request_data[header_end] == '\r') @as(usize, 4) else @as(usize, 2);
        const start = header_end + sep;
        if (start >= self.request_data.len) return "";

        if (self.getHeader("Content-Length:")) |raw_cl| {
            // Missing Content-Length and an explicit 0 are not the same; an explicit 0 must return an empty body.
            const cl = std.fmt.parseInt(usize, raw_cl, 10) catch return "";
            // A maliciously huge Content-Length must not overflow start + cl; return only the currently buffered data window.
            const available = self.request_data.len - start;
            const body_len = @min(cl, available);
            const end = start + body_len;
            return self.request_data[start..end];
        }
        return self.request_data[start..];
    }

    /// Parse the request method (GET/POST/PUT/...).
    pub fn method(self: *Context) []const u8 {
        const eol = std.mem.indexOf(u8, self.request_data, "\r\n") orelse
            std.mem.indexOfScalar(u8, self.request_data, '\n') orelse
            return "";
        const first_sp = std.mem.indexOfScalar(u8, self.request_data[0..eol], ' ') orelse return "";
        return self.request_data[0..first_sp];
    }

    /// Parse Content-Length (returns 0 when not declared).
    pub fn getContentLength(self: *Context) usize {
        const val = self.getHeader("Content-Length:") orelse return 0;
        return std.fmt.parseInt(usize, val, 10) catch 0;
    }

    /// Parse Content-Type, returning the MIME type (without parameters, e.g. "application/json").
    pub fn getContentType(self: *Context) []const u8 {
        const raw = self.getHeader("Content-Type:") orelse return "";
        const semi = std.mem.indexOfScalar(u8, raw, ';') orelse raw.len;
        return std.mem.trim(u8, raw[0..semi], " \t\r\n");
    }

    /// Check whether Content-Type is JSON.
    pub fn isJson(self: *Context) bool {
        const ct = self.getContentType();
        // HTTP Content-Type type/subtype is case-insensitive.
        return std.ascii.eqlIgnoreCase(ct, "application/json");
    }

    pub fn clearHeaders(self: *Context) void {
        if (self.headers) |*h| {
            h.clearRetainingCapacity();
        }
    }

    pub fn deinit(self: *Context) void {
        if (self.body) |b| self.allocator.free(b);
        if (self.headers) |*h| h.deinit(self.allocator);
    }

    /// Builder for HTTP responses. `status` chains into `json`/`text`/`html`;
    /// `header` is a separate step because it can fail.
    ///
    /// Usage:
    ///   try ctx.response().status(201).json(data);
    ///   try ctx.response().header("X-Custom", "val");
    ///   try ctx.response().text("ok");
    pub const ResponseBuilder = struct {
        ctx: *Context,

        pub fn init(ctx: *Context) ResponseBuilder {
            return .{ .ctx = ctx };
        }

        pub fn status(self: ResponseBuilder, code: u16) ResponseBuilder {
            self.ctx.status = code;
            return self;
        }

        pub fn header(self: ResponseBuilder, key: []const u8, value: []const u8) !void {
            try self.ctx.setHeader(key, value);
        }

        pub fn json(self: ResponseBuilder, value: anytype) !void {
            try self.ctx.json(self.ctx.status, value);
        }

        pub fn text(self: ResponseBuilder, data: []const u8) !void {
            try self.ctx.text(self.ctx.status, data);
        }

        pub fn html(self: ResponseBuilder, data: []const u8) !void {
            try self.ctx.html(self.ctx.status, data);
        }
    };
};

test "Context.query parses URI from request line" {
    var ctx = Context{
        .request_data = "GET /search?q=zig&lang=zh HTTP/1.1\r\nHost: example.com\r\n\r\n",
        .path = "/search",
        .app_ctx = null,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectEqualStrings("zig", ctx.query("q").?);
    try std.testing.expectEqualStrings("zh", ctx.query("lang").?);
    try std.testing.expect(ctx.query("missing") == null);
}

test "Context.getHeader requires exact header name" {
    var ctx = Context{
        .request_data = "GET / HTTP/1.1\r\nHostile: nope\r\nHost: example.com\r\n\r\n",
        .path = "/",
        .app_ctx = null,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectEqualStrings("example.com", ctx.getHeader("Host").?);
    try std.testing.expectEqualStrings("example.com", ctx.getHeader("Host:").?);
}

test "Context.setHeader rejects response header injection" {
    var ctx = Context{
        .request_data = "GET / HTTP/1.1\r\n\r\n",
        .path = "/",
        .app_ctx = null,
        .allocator = std.testing.allocator,
    };
    defer ctx.deinit();

    try ctx.setHeader("X-Test", "ok");
    try std.testing.expectError(error.InvalidHeader, ctx.setHeader("Bad:Name", "ok"));
    try std.testing.expectError(error.InvalidHeader, ctx.setHeader("X-Test", "ok\r\nX-Injected: yes"));
    try std.testing.expectError(error.InvalidHeader, ctx.setHeader("Content-Length", "999"));
    try std.testing.expectError(error.InvalidHeader, ctx.setHeader("Connection", "close"));
}

test "Context.requestBody prefers oversized body storage" {
    var ctx = Context{
        .request_data = "POST / HTTP/1.1\r\nContent-Length: 999\r\n\r\n",
        .request_body = "detached body",
        .path = "/",
        .app_ctx = null,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectEqualStrings("detached body", ctx.requestBody());
}

test "Context.requestBody honors Content-Length with LF-only headers" {
    var ctx = Context{
        .request_data = "POST / HTTP/1.1\nContent-Length: 4\n\nabcdef",
        .path = "/",
        .app_ctx = null,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectEqual(@as(usize, 4), ctx.getContentLength());
    try std.testing.expectEqualStrings("abcd", ctx.requestBody());
}

test "Context.requestBody returns empty body for explicit zero Content-Length" {
    var ctx = Context{
        .request_data = "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\nnext-request-bytes",
        .path = "/",
        .app_ctx = null,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectEqualStrings("", ctx.requestBody());
}

test "Context.requestBody clamps oversized Content-Length without overflow" {
    var ctx = Context{
        .request_data = "POST / HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\nabc",
        .path = "/",
        .app_ctx = null,
        .allocator = std.testing.allocator,
    };
    try std.testing.expectEqualStrings("abc", ctx.requestBody());
}

test "ResponseBuilder chains status and json" {
    var ctx = Context{
        .request_data = "GET / HTTP/1.1\r\n\r\n",
        .path = "/",
        .app_ctx = null,
        .allocator = std.testing.allocator,
    };
    defer ctx.deinit();

    try ctx.response().status(201).json(.{ .id = 42 });
    try std.testing.expectEqual(@as(u16, 201), ctx.status);
    try std.testing.expectEqual(Context.ContentType.json, ctx.content_type);
    try std.testing.expect(ctx.body != null);
}

test "ResponseBuilder chains header and text" {
    var ctx = Context{
        .request_data = "GET / HTTP/1.1\r\n\r\n",
        .path = "/",
        .app_ctx = null,
        .allocator = std.testing.allocator,
    };
    defer ctx.deinit();

    var r = ctx.response();
    try r.header("X-Test", "ok");
    try r.text("hello");
    try std.testing.expectEqual(Context.ContentType.plain, ctx.content_type);
    try std.testing.expect(ctx.headers != null);
}

test "ResponseBuilder header returns error for invalid header" {
    var ctx = Context{
        .request_data = "GET / HTTP/1.1\r\n\r\n",
        .path = "/",
        .app_ctx = null,
        .allocator = std.testing.allocator,
    };
    defer ctx.deinit();

    try std.testing.expectError(error.InvalidHeader, ctx.response().header("Bad:Name", "x"));
}
