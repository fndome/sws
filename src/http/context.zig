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
    // 修改原因：setHeader 会直接序列化到响应头，必须拒绝非法名字、CR/LF 和框架自动生成的头，避免注入与重复边界头。
    if (key.len == 0) return error.InvalidHeader;
    for (key) |ch| {
        if (!isHeaderNameChar(ch)) return error.InvalidHeader;
    }
    if (isManagedResponseHeader(key)) return error.InvalidHeader;
    for (value) |ch| {
        if (ch == '\r' or ch == '\n') return error.InvalidHeader;
    }
}

pub const Context = struct {
    pub const ContentType = enum { plain, json, html };

    request_data: []const u8,
    // 修改原因：请求体不能复用 response body 字段，否则 POST 会被误判为已响应。
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
                // 修改原因：同时支持 CRLF/LF-only 请求头，但仍要求 header 名后紧跟冒号，避免 Host 误匹配 Hostile。
                if (after[0] == ':') return std.mem.trim(u8, after[1..], " \t\r\n");
            }
        }
        return null;
    }

    /// 从请求 path 的 query string 中提取指定参数值。e.g. ctx.query("to")
    pub fn query(self: *Context, name: []const u8) ?[]const u8 {
        const line_end = std.mem.indexOf(u8, self.request_data, "\r\n") orelse
            std.mem.indexOfScalar(u8, self.request_data, '\n') orelse
            self.request_data.len;
        const first_line = self.request_data[0..line_end];
        const method_end = std.mem.indexOfScalar(u8, first_line, ' ') orelse return null;
        // 修改原因：旧代码把 first_line 截到第一个空格，只剩 method，导致 query 永远取不到。
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

    /// 获取 POST/PUT/PATCH 请求体。
    /// 自动从 Content-Length 取长度。无 body 返回空串。
    pub fn requestBody(self: *Context) []const u8 {
        if (self.request_body.len > 0) return self.request_body;
        const header_end = std.mem.indexOf(u8, self.request_data, "\r\n\r\n") orelse
            std.mem.indexOf(u8, self.request_data, "\n\n") orelse
            return "";
        const sep: usize = if (self.request_data[header_end] == '\r') @as(usize, 4) else @as(usize, 2);
        const start = header_end + sep;
        if (start >= self.request_data.len) return "";

        if (self.getHeader("Content-Length:")) |raw_cl| {
            // 修改原因：Content-Length 缺失和显式 0 不能都当成 0；显式 0 必须返回空 body。
            const cl = std.fmt.parseInt(usize, raw_cl, 10) catch return "";
            // 修改原因：恶意超大 Content-Length 不能让 start + cl 溢出；只返回当前已缓存的数据窗口。
            const available = self.request_data.len - start;
            const body_len = @min(cl, available);
            const end = start + body_len;
            return self.request_data[start..end];
        }
        return self.request_data[start..];
    }

    /// 解析请求头方法（GET/POST/PUT/...）
    pub fn method(self: *Context) []const u8 {
        const eol = std.mem.indexOf(u8, self.request_data, "\r\n") orelse
            std.mem.indexOfScalar(u8, self.request_data, '\n') orelse
            return "";
        const first_sp = std.mem.indexOfScalar(u8, self.request_data[0..eol], ' ') orelse return "";
        return self.request_data[0..first_sp];
    }

    /// 解析 Content-Length（未声明返回 0）
    pub fn getContentLength(self: *Context) usize {
        const val = self.getHeader("Content-Length:") orelse return 0;
        return std.fmt.parseInt(usize, val, 10) catch 0;
    }

    /// 解析 Content-Type，返回 MIME type（不含参数，如 "application/json"）
    pub fn getContentType(self: *Context) []const u8 {
        const raw = self.getHeader("Content-Type:") orelse return "";
        const semi = std.mem.indexOfScalar(u8, raw, ';') orelse raw.len;
        return std.mem.trim(u8, raw[0..semi], " \t\r\n");
    }

    /// 判断 Content-Type 是否为 JSON
    pub fn isJson(self: *Context) bool {
        const ct = self.getContentType();
        // 修改原因：HTTP Content-Type 的 type/subtype 大小写不敏感。
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
