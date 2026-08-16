//! Pure HTTP request/response parsing for the outbound client. No io_uring
//! dependency, so it is unit-testable on the host via `zig test`.

const std = @import("std");
const Allocator = std.mem.Allocator;

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

pub const ParsedUrl = struct {
    host: []const u8,
    authority: []const u8,
    port: u16,
    path: []const u8,
    tls: bool,
};

pub fn isHttpTokenChar(ch: u8) bool {
    const token_symbols = "!#$%&'*+-.^_`|~";
    return (ch >= 'A' and ch <= 'Z') or
        (ch >= 'a' and ch <= 'z') or
        (ch >= '0' and ch <= '9') or
        std.mem.indexOfScalar(u8, token_symbols, ch) != null;
}

fn isCtlOrSpace(ch: u8) bool {
    return ch <= ' ' or ch == 0x7f;
}

pub fn validateMethod(method: []const u8) !void {
    if (method.len == 0) return error.InvalidMethod;
    for (method) |ch| {
        if (!isHttpTokenChar(ch)) return error.InvalidMethod;
    }
}

pub fn validateUrlHost(host: []const u8) !void {
    if (host.len == 0) return error.InvalidUrl;
    for (host) |ch| {
        if (isCtlOrSpace(ch)) return error.InvalidUrl;
        // The client does not parse URL userinfo; '@' in the authority must not be treated as a host character written into the Host header.
        if (ch == '@') return error.InvalidUrl;
    }
}

pub fn validateRequestTarget(path: []const u8) !void {
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
    // URL fragments are client-local only and must not appear in the HTTP request-target.
    const no_fragment = target[0..(std.mem.indexOfScalar(u8, target, '#') orelse target.len)];
    if (no_fragment.len == 0) return "/";
    return no_fragment;
}

pub fn parseUrl(allocator: Allocator, url: []const u8) !ParsedUrl {
    var rest = url;
    // URL scheme is case-insensitive; a valid URL like HTTP://host must not be misparsed as a bad host/port.
    const is_tls = if (std.ascii.startsWithIgnoreCase(rest, "https://")) blk: {
        rest = rest["https://".len..];
        break :blk true;
    } else if (std.ascii.startsWithIgnoreCase(rest, "http://")) blk: {
        rest = rest["http://".len..];
        break :blk false;
    } else false;
    // A valid URL may omit the path but still carry a query, e.g. http://host?x=1; that must still be split off from the host.
    const path_start = firstPathOrQueryIndex(rest);
    const host_port = if (path_start) |p| rest[0..p] else rest;
    const path = if (path_start) |p| stripFragmentTarget(rest[p..]) else "/";
    const colon = std.mem.lastIndexOfScalar(u8, host_port, ':');
    const host = if (colon) |c| host_port[0..c] else host_port;
    if (std.mem.indexOfScalar(u8, host, ':') != null) return error.InvalidUrl;
    // host and request-target are spliced directly into the request line/Host header, so CR/LF/control whitespace must be rejected to prevent header injection.
    // The client only supports a plain host[:port] authority; multi-colon or bracketed IPv6 forms cannot be silently parsed via lastIndex.
    try validateUrlHost(host);
    try validateRequestTarget(path);
    const port: u16 = if (colon) |c| blk: {
        const port_text = host_port[c + 1 ..];
        // A malformed explicit port must not silently fall back to 80, or the request would be sent to the wrong upstream.
        if (port_text.len == 0) return error.InvalidUrl;
        break :blk std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidUrl;
    } else if (is_tls) 443 else 80;
    const host_dup = try allocator.dupe(u8, host);
    errdefer allocator.free(host_dup);
    // The HTTP/1.1 Host header must keep the explicit port; the host is used for connecting while authority is used for the Host header.
    const authority_dup = try allocator.dupe(u8, host_port);
    return .{ .host = host_dup, .authority = authority_dup, .port = port, .path = path, .tls = is_tls };
}

pub fn parseResponse(allocator: Allocator, data: []const u8) !Response {
    return parseResponseForMethod(allocator, data, "GET");
}

pub fn parseResponseForMethod(allocator: Allocator, data: []const u8, method: []const u8) !Response {
    // For HEAD responses Content-Length describes only a hypothetical body; parsing must honor the request method or a valid HEAD response would be misjudged as incompletely read.
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
        const line = std.mem.trimEnd(u8, raw_line, "\r");
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
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(line, name)) {
            const after = line[name.len..];
            if (after.len > 0 and after[0] == ':') {
                // A duplicate response Content-Length makes the keep-alive response boundary ambiguous; the client cannot trust only the first value.
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
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (std.ascii.startsWithIgnoreCase(line, name)) {
            const after = line[name.len..];
            if (after.len > 0 and after[0] == ':' and headerValueHasToken(after[1..], token)) return true;
        }
    }
    return false;
}

pub fn responseWantsClose(data: []const u8) bool {
    const bounds = findHeaderEnd(data) orelse return false;
    const headers = data[0..bounds.header_end];
    // When the upstream declares Connection: close, the TCP connection must not be returned to the keep-alive pool for reuse.
    return responseHeaderHasToken(headers, "Connection", "close");
}

fn validateResponseHeaderLines(headers: []const u8) !void {
    var lines = std.mem.splitScalar(u8, headers, '\n');
    _ = lines.next() orelse return error.InvalidResponse;
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        // Response header lines participate in keep-alive boundary determination; embedded CR, a missing colon, or an invalid field name must not be silently ignored.
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
    // A corrupt upstream status line must not be disguised as a normal 500 response; the caller needs to know this is an invalid HTTP response.
    if (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0")) return error.InvalidResponse;
    // The HTTP status-code must be exactly 3 digits; parseInt would relax a malformed code like 0200 into 200.
    if (code.len != 3) return error.InvalidResponse;
    for (code) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidResponse;
    }
    const status = std.fmt.parseInt(u16, code, 10) catch return error.InvalidResponse;
    // HTTP status-codes are only defined for 100-599; allowing 6xx-9xx would treat an upstream bad response as a normal boundary and reuse the connection.
    if (status < 100 or status > 599) return error.InvalidResponse;
    return status;
}

fn responseMayOmitContentLength(status: u16) bool {
    // 205 Reset Content also forbids a response body, so it cannot wait for a Content-Length body like an ordinary 2xx.
    return status == 204 or status == 205 or status == 304;
}

fn methodForbidsResponseBody(method: []const u8) bool {
    return std.ascii.eqlIgnoreCase(method, "HEAD");
}

fn parseResponseContentLength(value: []const u8) !usize {
    // Response Content-Length is also a protocol boundary; parseInt would accept non-canonical values like leading zeros and relax the boundary check.
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

pub fn responseCompleteLenForMethod(data: []const u8, method: []const u8) !?usize {
    const bounds = findHeaderEnd(data) orelse return null;
    const headers = data[0..bounds.header_end];
    try validateResponseHeaderLines(headers);
    // For responses with no header fields (e.g. "204 No Content\r\n\r\n"), headers contains only the status line,
    // without the trailing "\r\n", so the status-line end must be found in data or InvalidResponse is misreported.
    const first_line_end = std.mem.indexOfScalar(u8, data, '\r') orelse
        std.mem.indexOfScalar(u8, data, '\n') orelse
        return error.InvalidResponse;
    const status = try parseStatusCode(headers[0..first_line_end]);
    // The client does not implement folding of 1xx interim responses, so 100 Continue cannot be returned as the final response.
    if (status < 200) return error.InformationalResponseUnsupported;
    if (getHeaderValue(headers, "Transfer-Encoding")) |_| {
        // The client only frames responses by Content-Length and never decodes any Transfer-Encoding.
        return error.TransferEncodingUnsupported;
    }
    const content_len_header = try getSingleHeaderValue(headers, "Content-Length");
    const body_forbidden = responseMayOmitContentLength(status) or methodForbidsResponseBody(method);
    const content_len = try responseContentLen(status, content_len_header, body_forbidden);
    // On keep-alive the connection will not EOF, so the response boundary must be determined by Content-Length.
    const header_total = std.math.add(usize, bounds.header_end, bounds.sep_len) catch return error.InvalidResponse;
    const total = std.math.add(usize, header_total, content_len) catch return error.InvalidResponse;
    if (data.len < total) return null;
    return total;
}

fn responseContentLen(status: u16, content_len_header: ?[]const u8, body_forbidden: bool) !usize {
    if (body_forbidden) {
        if (content_len_header) |value| {
            const declared_len = try parseResponseContentLength(value);
            // 204/205 have no response body; a non-zero Content-Length must not drive body reads or return a fake body.
            if ((status == 204 or status == 205) and declared_len != 0) return error.InvalidResponse;
        }
        // Content-Length for HEAD/304/205 cannot serve as the read boundary for the current response.
        return 0;
    }
    if (content_len_header) |value| {
        return parseResponseContentLength(value);
    }
    // When a body-capable response (e.g. 200) lacks a length, the boundary cannot be determined on a keep-alive connection, so it cannot be treated as an empty body and the connection reused.
    return error.MissingContentLength;
}

pub fn responseHasTrailingBytes(total_read: usize, complete_len: usize) bool {
    return total_read > complete_len;
}

pub fn makeErrorResponse(allocator: Allocator, status: u16, msg: []const u8) Response {
    // Triple-fallback: dupe -> alloc(0) -> zero-length compile-time literal.
    // The final literal is safe because Response.deinit guards on body.len > 0.
    const body = allocator.dupe(u8, msg) catch allocator.alloc(u8, 0) catch @constCast(&.{});
    return .{ .status = status, .body = body, .allocator = allocator };
}

test "responseCompleteLen waits for Content-Length body" {
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

test "responseCompleteLen rejects duplicate Content-Length" {
    const duplicate = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 11\r\n\r\nhello world";
    try std.testing.expectError(error.DuplicateHeader, responseCompleteLen(duplicate));
}

test "responseCompleteLen rejects malformed Content-Length" {
    try std.testing.expectError(error.InvalidContentLength, responseCompleteLen("HTTP/1.1 200 OK\r\nContent-Length: 01\r\n\r\nx"));
    try std.testing.expectError(error.InvalidContentLength, responseCompleteLen("HTTP/1.1 200 OK\r\nContent-Length: 1x\r\n\r\nx"));
}

test "responseCompleteLen rejects overflowing response boundary" {
    try std.testing.expectError(
        error.InvalidResponse,
        responseCompleteLen("HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n"),
    );
}

test "responseCompleteLen rejects Transfer-Encoding" {
    const encoded = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectError(error.TransferEncodingUnsupported, responseCompleteLen(encoded));
}

test "responseCompleteLen rejects malformed response headers" {
    try std.testing.expectError(error.InvalidResponse, responseCompleteLen("HTTP/1.1 204 No Content\r\nBad Name: x\r\n\r\n"));
    try std.testing.expectError(error.InvalidResponse, responseCompleteLen("HTTP/1.1 204 No Content\r\nX-Test : x\r\n\r\n"));
    try std.testing.expectError(error.InvalidResponse, responseCompleteLen("HTTP/1.1 204 No Content\r\nBroken\r\n\r\n"));
    try std.testing.expectError(error.InvalidResponse, responseCompleteLen("HTTP/1.1 204 No Content\r\nX-Test: ok\rBad: yes\r\n\r\n"));
}

test "responseCompleteLen rejects unsupported informational responses" {
    try std.testing.expectError(error.InformationalResponseUnsupported, responseCompleteLen("HTTP/1.1 100 Continue\r\n\r\n"));
    try std.testing.expectError(error.InformationalResponseUnsupported, responseCompleteLen("HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n"));
}

test "responseCompleteLen requires length for body-capable responses" {
    try std.testing.expectError(error.MissingContentLength, responseCompleteLen("HTTP/1.1 200 OK\r\n\r\nhello"));

    const no_content = "HTTP/1.1 204 No Content\r\n\r\nignored";
    const expected = (std.mem.indexOf(u8, no_content, "\r\n\r\n") orelse unreachable) + 4;
    try std.testing.expectEqual(@as(?usize, expected), try responseCompleteLen(no_content));
}

test "responseCompleteLen frames no-body responses at header end" {
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

test "responseCompleteLen frames HEAD responses at header end" {
    const head_response = "HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\nextra";
    const expected = (std.mem.indexOf(u8, head_response, "\r\n\r\n") orelse unreachable) + 4;
    try std.testing.expectEqual(@as(?usize, expected), try responseCompleteLenForMethod(head_response, "HEAD"));

    var resp = try parseResponseForMethod(std.testing.allocator, head_response[0..expected], "HEAD");
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqual(@as(usize, 0), resp.body.len);
}

test "detects trailing bytes after complete response" {
    try std.testing.expect(!responseHasTrailingBytes(42, 42));
    try std.testing.expect(responseHasTrailingBytes(43, 42));
}

test "detects Connection close response token" {
    const close_resp = "HTTP/1.1 200 OK\r\nConnection: keep-alive, close\r\nContent-Length: 0\r\n\r\n";
    try std.testing.expect(responseWantsClose(close_resp));

    const keep_resp = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
    try std.testing.expect(!responseWantsClose(keep_resp));
}

test "parseResponse rejects malformed status lines" {
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

test "parseUrl rejects malformed explicit ports" {
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
