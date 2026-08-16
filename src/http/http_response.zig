const std = @import("std");
const Allocator = std.mem.Allocator;

const AsyncServer = @import("async_server.zig").AsyncServer;
const Connection = @import("connection.zig").Connection;
const Context = @import("context.zig").Context;
const logErr = @import("http_helpers.zig").logErr;

pub fn statusText(code: u16) []const u8 {
    return switch (code) {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        101 => "Switching Protocols",
        else => "",
    };
}

pub fn headerOnlyCapacity(extra_headers_len: usize) usize {
    return 256 + extra_headers_len;
}

pub fn ensureWriteBuf(self: *AsyncServer, conn: *Connection, min_size: usize) bool {
    if (conn.response_buf) |existing| {
        if (existing.len >= min_size) return true;
        if (self.connSlot(conn)) |slot| {
            if (slot.line4.writev_in_flight != 0) {
                logErr("ensureWriteBuf: refusing to replace in-flight write buffer for fd={d}", .{conn.fd});
                return false;
            }
        }
        self.buffer_pool.freeTieredWriteBuf(existing, conn.response_buf_tier);
        conn.response_buf = null;
    }
    if (self.buffer_pool.allocTieredWriteBuf(min_size)) |a| {
        conn.response_buf = a.buf;
        conn.response_buf_tier = @intCast(a.tier);
        return true;
    }
    return false;
}

pub fn respond(self: *AsyncServer, conn: *Connection, status: u16, text: []const u8) void {
    if (!ensureWriteBuf(self, conn, 256)) {
        self.closeConn(conn.id, conn.fd);
        return;
    }
    const buf = conn.response_buf.?;
    const conn_hdr = if (conn.keep_alive) "keep-alive" else "close";
    const len = std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: {s}\r\n\r\n", .{ status, text, conn_hdr }) catch {
        respondError(self, conn);
        return;
    };
    conn.write_headers_len = len.len;
    conn.write_offset = 0;
    conn.write_body = null;
    conn.state = .writing;
    self.submitWrite(conn.id, conn) catch {
        self.closeConn(conn.id, conn.fd);
    };
}

pub fn respondWithHeader(self: *AsyncServer, conn: *Connection, status: u16, text: []const u8, extra_headers: []const u8) void {
    // extra_headers comes from the caller, so size by its actual length; otherwise a long header makes bufPrint fail and returns a spurious 500.
    if (!ensureWriteBuf(self, conn, headerOnlyCapacity(extra_headers.len))) {
        self.closeConn(conn.id, conn.fd);
        return;
    }
    const buf = conn.response_buf.?;
    const conn_hdr = if (conn.keep_alive) "keep-alive" else "close";
    const len = std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\n{s}Content-Length: 0\r\nConnection: {s}\r\n\r\n", .{ status, text, extra_headers, conn_hdr }) catch {
        respondError(self, conn);
        return;
    };
    conn.write_headers_len = len.len;
    conn.write_offset = 0;
    conn.write_body = null;
    conn.state = .writing;
    self.submitWrite(conn.id, conn) catch {
        self.closeConn(conn.id, conn.fd);
    };
}

test "respondWithHeader capacity scales with extra headers" {
    try std.testing.expectEqual(@as(usize, 256), headerOnlyCapacity(0));
    try std.testing.expectEqual(@as(usize, 768), headerOnlyCapacity(512));
}

pub fn respondJson(self: *AsyncServer, conn: *Connection, status: u16, json_body: []const u8) void {
    const needed = 256 + json_body.len;
    if (!ensureWriteBuf(self, conn, needed)) {
        self.closeConn(conn.id, conn.fd);
        return;
    }
    const buf = conn.response_buf.?;
    const conn_hdr = if (conn.keep_alive) "keep-alive" else "close";
    const reason = statusText(status);
    const len = std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: {s}\r\n\r\n{s}", .{ status, reason, json_body.len, conn_hdr, json_body }) catch {
        respondError(self, conn);
        return;
    };
    conn.write_headers_len = len.len;
    conn.write_offset = 0;
    conn.write_body = null;
    conn.state = .writing;
    self.submitWrite(conn.id, conn) catch {
        self.closeConn(conn.id, conn.fd);
    };
}

pub fn respondError(self: *AsyncServer, conn: *Connection) void {
    if (!ensureWriteBuf(self, conn, 256)) {
        self.closeConn(conn.id, conn.fd);
        return;
    }
    const buf = conn.response_buf.?;
    const conn_hdr = if (conn.keep_alive) "keep-alive" else "close";
    const len = std.fmt.bufPrint(buf, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: {s}\r\n\r\n", .{conn_hdr}) catch {
        self.closeConn(conn.id, conn.fd);
        return;
    };
    conn.write_headers_len = len.len;
    conn.write_offset = 0;
    conn.write_body = null;
    conn.state = .writing;
    self.submitWrite(conn.id, conn) catch {
        self.closeConn(conn.id, conn.fd);
    };
}

pub fn respondZeroCopy(self: *AsyncServer, conn: *Connection, status: u16, content_type: Context.ContentType, body: []u8, extra_headers: []const u8) void {
    if (!ensureWriteBuf(self, conn, 512 + extra_headers.len)) {
        self.allocator.free(body);
        self.closeConn(conn.id, conn.fd);
        return;
    }
    const buf = conn.response_buf.?;
    const mime = switch (content_type) {
        .plain => "text/plain",
        .json => "application/json",
        .html => "text/html",
    };
    const reason = statusText(status);
    const conn_hdr = if (conn.keep_alive) "keep-alive" else "close";
    const len = std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\n{s}Content-Length: {d}\r\nConnection: {s}\r\n\r\n", .{ status, reason, mime, extra_headers, body.len, conn_hdr }) catch {
        self.allocator.free(body);
        respondError(self, conn);
        return;
    };
    conn.write_headers_len = len.len;
    conn.write_body = body;
    conn.write_offset = 0;
    conn.state = .writing;
    self.submitWrite(conn.id, conn) catch {
        if (conn.write_body) |b| self.allocator.free(b);
        conn.write_body = null;
        self.closeConn(conn.id, conn.fd);
    };
}
