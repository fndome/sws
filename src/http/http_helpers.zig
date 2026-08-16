const std = @import("std");
const MAX_PATH_LENGTH = @import("../constants.zig").MAX_PATH_LENGTH;

pub fn getMethodFromRequest(buf: []const u8) ?[]const u8 {
    const end = std.mem.indexOf(u8, buf, "\r\n") orelse std.mem.indexOfScalar(u8, buf, '\n') orelse return null;
    const line = buf[0..end];
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    return line[0..first_space];
}

pub fn getPathFromRequestWithLimit(buf: []const u8, max_path_length: usize) ?[]const u8 {
    const end = std.mem.indexOf(u8, buf, "\r\n") orelse std.mem.indexOfScalar(u8, buf, '\n') orelse return null;
    const line = buf[0..end];
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    var rest = line[first_space + 1 ..];
    while (rest.len > 0 and rest[0] == ' ') rest = rest[1..];
    const second_space = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    const raw = rest[0..second_space];
    const q_pos = std.mem.indexOfScalar(u8, raw, '?') orelse raw.len;
    // 修改原因：max_path_length 限制的是路由 path，不应把 query string 计入；否则短路径大查询会被误拒绝。
    if (q_pos == 0 or q_pos > max_path_length) return null;
    return raw[0..q_pos];
}

pub fn getPathFromRequest(buf: []const u8) ?[]const u8 {
    return getPathFromRequestWithLimit(buf, MAX_PATH_LENGTH);
}

pub fn isKeepAliveConnection(buf: []const u8) bool {
    const http11 = requestLineIsHttp11(buf);
    var lines = std.mem.splitScalar(u8, buf, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, "\r");
        if (line.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(line, "Connection:")) {
            const value = std.mem.trim(u8, line["Connection:".len..], " \t");
            // 修改原因：Connection 是逗号分隔 token，不能用子串匹配；同时协议版本只能从请求行判断。
            if (headerValueHasToken(value, "close")) return false;
            if (headerValueHasToken(value, "keep-alive")) return true;
        }
    }
    return http11;
}

/// Returns true when the request line declares HTTP/1.1.
/// Tokenizes the third word so "HTTP/1.10" does not match (unlike endsWith).
pub fn requestLineIsHttp11(buf: []const u8) bool {
    const end = std.mem.indexOf(u8, buf, "\r\n") orelse
        std.mem.indexOfScalar(u8, buf, '\n') orelse
        return false;
    var parts = std.mem.tokenizeScalar(u8, std.mem.trim(u8, buf[0..end], "\r"), ' ');
    _ = parts.next() orelse return false;
    _ = parts.next() orelse return false;
    const version = parts.next() orelse return false;
    return std.mem.eql(u8, version, "HTTP/1.1");
}

fn headerValueHasToken(value: []const u8, token: []const u8) bool {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(trimmed, token)) return true;
    }
    return false;
}

/// 从 HTTP 请求行中提取 URI 的完整路径（含 query string）
pub fn getFullUri(buf: []const u8) ?[]const u8 {
    const end = std.mem.indexOf(u8, buf, "\r\n") orelse std.mem.indexOfScalar(u8, buf, '\n') orelse return null;
    const line = buf[0..end];
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    var rest = line[first_space + 1 ..];
    while (rest.len > 0 and rest[0] == ' ') rest = rest[1..];
    const second_space = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    return rest[0..second_space];
}

/// 从 query string 中提取指定参数的值
pub fn extractQueryParam(uri: []const u8, name: []const u8) ?[]const u8 {
    const q_pos = std.mem.indexOfScalar(u8, uri, '?') orelse return null;
    const qs = uri[q_pos + 1 ..];
    var it = std.mem.splitScalar(u8, qs, '&');
    while (it.next()) |pair| {
        const eq_pos = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq_pos];
        if (std.mem.eql(u8, key, name)) {
            const val = pair[eq_pos + 1 ..];
            return val;
        }
    }
    return null;
}

/// 从 HTTP 请求头部提取指定 header 的值（大小写不敏感）
pub fn extractHeader(data: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, "\r");
        if (line.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(line, name)) {
            if (line.len <= name.len) return null;
            const after = line[name.len..];
            // 修改原因：tcp_read 已支持 LF-only 请求头结束符，header 提取也必须同样兼容，同时仍要求冒号避免误匹配。
            if (after.len > 0 and after[0] == ':') {
                return std.mem.trim(u8, after[1..], " \t\r\n");
            }
        }
    }
    return null;
}

pub fn parseIpv4(ip_str: []const u8) !u32 {
    var parts = std.mem.splitScalar(u8, ip_str, '.');
    var octets: [4]u8 = undefined;
    var i: usize = 0;
    while (parts.next()) |part| : (i += 1) {
        if (i >= 4) return error.InvalidIp;
        octets[i] = try std.fmt.parseInt(u8, part, 10);
    }
    if (i != 4) return error.InvalidIp;
    const ip = (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        (@as(u32, octets[3]));
    // 修改原因：linux.sockaddr.in.addr 需要内存中为网络字节序，直接返回文本序数值会把 127.0.0.1 绑定成 1.0.0.127。
    return std.mem.nativeToBig(u32, ip);
}

fn parseNameserverLine(line: []const u8) ?u32 {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    const keyword = "nameserver";
    if (!std.mem.startsWith(u8, trimmed, keyword)) return null;
    const rest = trimmed[keyword.len..];
    // 修改原因：resolv.conf 允许用任意空白分隔关键字和值，不能只识别单个空格。
    if (rest.len == 0 or (rest[0] != ' ' and rest[0] != '\t')) return null;
    // 修改原因：nameserver 行允许在地址后继续写空白和注释，解析 IP 时只能取第一个字段。
    var fields = std.mem.tokenizeAny(u8, std.mem.trim(u8, rest, " \t\r"), " \t\r");
    const ip_str = fields.next() orelse return null;
    return parseIpv4(ip_str) catch null;
}

fn openReadOnly(path: [*:0]const u8) !i32 {
    const flags: std.os.linux.O = @bitCast(@as(u32, 0));
    const raw_fd = std.os.linux.open(path, flags, 0);
    // 修改原因：linux.open 返回 usize，失败时要用 errno 判断，不能用 raw_fd < 0 检查。
    if (std.os.linux.errno(raw_fd) != .SUCCESS) return error.FileNotFound;
    return @intCast(raw_fd);
}

/// Parse /etc/resolv.conf for the first nameserver entry.
/// Previously duplicated in async_server.zig and client/ring.zig.
pub fn readResolvConfNameserver() !u32 {
    const path = "/etc/resolv.conf\x00";
    const fd = try openReadOnly(@ptrCast(path));
    defer _ = std.os.linux.close(fd);

    var buf: [4096]u8 = undefined;
    const raw = std.os.linux.read(fd, &buf, buf.len);
    const n_signed: isize = @bitCast(raw);
    if (n_signed <= 0) return error.FileNotFound;
    const content = buf[0..@as(usize, @intCast(n_signed))];

    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |line| {
        if (parseNameserverLine(line)) |ip| return ip;
    }
    return error.NoNameserverFound;
}

pub fn logErr(comptime format: []const u8, args: anytype) void {
    @import("../async_logger.zig").logErr(format, args);
}

test "isKeepAliveConnection uses request line and exact Connection tokens" {
    try std.testing.expect(!isKeepAliveConnection("GET / HTTP/1.0\r\nX-Debug: HTTP/1.1\r\n\r\n"));
    try std.testing.expect(isKeepAliveConnection("GET / HTTP/1.1\r\nConnection: enclose\r\n\r\n"));
    try std.testing.expect(!isKeepAliveConnection("GET / HTTP/1.1\nConnection: close\n\n"));
    try std.testing.expect(isKeepAliveConnection("GET / HTTP/1.0\r\nConnection: keep-alive, upgrade\r\n\r\n"));
}

test "extractHeader supports LF-only request headers" {
    const req = "POST / HTTP/1.1\nHost: example.test\nContent-Length: 4\n\nbody";

    try std.testing.expectEqualStrings("4", extractHeader(req, "Content-Length").?);
    try std.testing.expect(extractHeader(req, "Content") == null);
}

test "getPathFromRequestWithLimit limits only the path part" {
    try std.testing.expectEqualStrings(
        "/search",
        getPathFromRequestWithLimit(
            "GET /search?q=abcdefghijklmnopqrstuvwxyz HTTP/1.1\r\nHost: example.test\r\n\r\n",
            7,
        ).?,
    );
    try std.testing.expect(
        getPathFromRequestWithLimit("GET /toolong HTTP/1.1\r\nHost: example.test\r\n\r\n", 3) == null,
    );
}

test "parseNameserverLine accepts whitespace separated resolv.conf entries" {
    try std.testing.expectEqual(try parseIpv4("1.1.1.1"), parseNameserverLine("nameserver\t1.1.1.1").?);
    try std.testing.expectEqual(try parseIpv4("8.8.8.8"), parseNameserverLine("  nameserver   8.8.8.8  ").?);
    try std.testing.expectEqual(try parseIpv4("1.1.1.1"), parseNameserverLine("nameserver 1.1.1.1 # cloudflare").?);
    try std.testing.expect(parseNameserverLine("nameserverfoo 9.9.9.9") == null);
}

test "openReadOnly reports missing files through errno" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    try std.testing.expectError(error.FileNotFound, openReadOnly("/tmp/sws-definitely-missing-resolv.conf\x00"));
}
