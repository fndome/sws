const std = @import("std");
const helpers = @import("http_helpers.zig");

/// Protocol-level HTTP request validation moved from tcp_read.zig.
/// These functions operate on raw buffer slices and are io_uring-agnostic —
/// they can be tested without ring setup and are reusable by DevServer.

fn isRequestHeaderNameChar(ch: u8) bool {
    const token_symbols = "!#$%&'*+-.^_`|~";
    return (ch >= 'A' and ch <= 'Z') or
        (ch >= 'a' and ch <= 'z') or
        (ch >= '0' and ch <= '9') or
        std.mem.indexOfScalar(u8, token_symbols, ch) != null;
}

pub fn requestMethodIsToken(method: []const u8) bool {
    for (method) |ch| {
        if (!isRequestHeaderNameChar(ch)) return false;
    }
    return true;
}

pub fn requestTargetIsValid(target: []const u8) bool {
    for (target) |ch| {
        if (ch <= ' ' or ch == 0x7f) return false;
        if (ch == '#') return false;
    }
    return true;
}

/// Validates: method SP target SP version, no extra tokens, all tokens valid.
pub fn requestLineIsSupported(buf: []const u8) bool {
    const end = std.mem.indexOf(u8, buf, "\r\n") orelse
        std.mem.indexOfScalar(u8, buf, '\n') orelse
        return false;
    var parts = std.mem.tokenizeScalar(u8, std.mem.trim(u8, buf[0..end], "\r"), ' ');
    const method = parts.next() orelse return false;
    const target = parts.next() orelse return false;
    const version = parts.next() orelse return false;
    if (parts.next() != null) return false;
    if (method.len == 0 or target.len == 0) return false;
    if (!requestMethodIsToken(method) or !requestTargetIsValid(target)) return false;
    return std.mem.eql(u8, version, "HTTP/1.1") or std.mem.eql(u8, version, "HTTP/1.0");
}

/// Every header line must be "Name: value" with valid token characters.
pub fn requestHeadersAreWellFormed(buf: []const u8) bool {
    var lines = std.mem.splitScalar(u8, buf, '\n');
    _ = lines.next() orelse return false;
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, "\r");
        if (line.len == 0) return true;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return false;
        if (colon == 0) return false;
        for (line[0..colon]) |ch| {
            if (!isRequestHeaderNameChar(ch)) return false;
        }
        for (line[colon + 1 ..]) |ch| {
            if ((ch < ' ' and ch != '\t') or ch == 0x7f) return false;
        }
    }
    return false;
}

/// HTTP/1.1 must have exactly one Host. HTTP/1.0 allows zero or one.
pub fn hostHeaderIsValidForRequest(buf: []const u8) bool {
    var host_count: usize = 0;
    var lines = std.mem.splitScalar(u8, buf, '\n');
    _ = lines.next() orelse return false;
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, "\r");
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return false;
        if (std.ascii.eqlIgnoreCase(line[0..colon], "Host")) {
            host_count += 1;
        }
    }
    if (helpers.requestLineIsHttp11(buf)) return host_count == 1;
    return host_count <= 1;
}

/// Parses a Content-Length value, rejecting RFC-violating forms (empty, leading zero, non-digit).
pub fn parseContentLength(value: []const u8) !u64 {
    if (value.len == 0) return error.InvalidContentLength;
    if (value.len > 1 and value[0] == '0') return error.InvalidContentLength;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidContentLength;
    }
    return std.fmt.parseInt(u64, value, 10) catch error.InvalidContentLength;
}

/// Extracts the Content-Length header value. Returns error on duplicate.
pub fn extractSingleContentLength(data: []const u8) !?[]const u8 {
    var seen: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, "\r");
        if (line.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(line, "Content-Length")) {
            const name_len = "Content-Length".len;
            if (line.len <= name_len) continue;
            const after = line[name_len..];
            if (after.len > 0 and after[0] == ':') {
                if (seen != null) return error.DuplicateContentLength;
                seen = std.mem.trim(u8, after[1..], " \t\r\n");
            }
        }
    }
    return seen;
}

test "requestLineIsSupported rejects malformed request lines" {
    try std.testing.expect(requestLineIsSupported("GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n"));
    try std.testing.expect(requestLineIsSupported("GET /hello HTTP/1.0\r\nHost: example.test\r\n\r\n"));
    try std.testing.expect(!requestLineIsSupported("GET /hello\r\nHost: example.test\r\n\r\n"));
    try std.testing.expect(!requestLineIsSupported("GET /hello HTTP/2\r\nHost: example.test\r\n\r\n"));
    try std.testing.expect(!requestLineIsSupported("GET /hello HTTP/1.1 extra\r\nHost: example.test\r\n\r\n"));
    try std.testing.expect(!requestLineIsSupported("GE:T /hello HTTP/1.1\r\nHost: example.test\r\n\r\n"));
    try std.testing.expect(!requestLineIsSupported("GET /\x01 HTTP/1.1\r\nHost: example.test\r\n\r\n"));
    try std.testing.expect(!requestLineIsSupported("GET /hello#frag HTTP/1.1\r\nHost: example.test\r\n\r\n"));
}

test "requestHeadersAreWellFormed rejects malformed header lines" {
    try std.testing.expect(requestHeadersAreWellFormed("GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: ok\r\n\r\n"));
    try std.testing.expect(!requestHeadersAreWellFormed("GET / HTTP/1.1\r\nBad Header: value\r\n\r\n"));
    try std.testing.expect(!requestHeadersAreWellFormed("GET / HTTP/1.1\r\nBrokenHeader\r\n\r\n"));
    try std.testing.expect(!requestHeadersAreWellFormed("GET / HTTP/1.1\r\nHost: ok\x01bad\r\n\r\n"));
}

test "hostHeaderIsValidForRequest enforces HTTP version rules" {
    try std.testing.expect(hostHeaderIsValidForRequest("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"));
    try std.testing.expect(!hostHeaderIsValidForRequest("GET / HTTP/1.1\r\n\r\n"));
    try std.testing.expect(!hostHeaderIsValidForRequest("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"));
    try std.testing.expect(hostHeaderIsValidForRequest("GET / HTTP/1.0\r\n\r\n"));
    try std.testing.expect(!hostHeaderIsValidForRequest("GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n"));
}

test "parseContentLength rejects malformed values" {
    try std.testing.expectEqual(@as(u64, 12), try parseContentLength("12"));
    try std.testing.expectError(error.InvalidContentLength, parseContentLength(""));
    try std.testing.expectError(error.InvalidContentLength, parseContentLength("abc"));
    try std.testing.expectError(error.InvalidContentLength, parseContentLength("12x"));
    try std.testing.expectError(error.InvalidContentLength, parseContentLength("00"));
    try std.testing.expectError(error.InvalidContentLength, parseContentLength("01"));
}

test "extractSingleContentLength rejects duplicate values" {
    const ok = "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 7\r\n\r\n";
    try std.testing.expectEqualStrings("7", (try extractSingleContentLength(ok)).?);

    const duplicate = "POST / HTTP/1.1\r\nContent-Length: 7\r\ncontent-length: 7\r\n\r\n";
    try std.testing.expectError(error.DuplicateContentLength, extractSingleContentLength(duplicate));
}
