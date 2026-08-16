const std = @import("std");

const websocket_magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub fn isUpgradeRequest(data: []const u8) bool {
    if (std.mem.indexOf(u8, data, "\r\n\r\n") == null) return false;
    // 修改原因：WebSocket 握手只能使用 HTTP/1.1 GET；只看 Upgrade 头会把 POST/HTTP1.0 请求误升级。
    if (!requestLineIsWebSocketGet(data)) return false;

    var has_upgrade = false;
    var has_connection_upgrade = false;
    var has_ws_key = false;
    var ws_key_count: u8 = 0;
    var has_ws_version = false;
    var lines = std.mem.splitSequence(u8, data, "\r\n");
    while (lines.next()) |line| {
        // 修改原因：HTTP 头部到空行就结束，不能继续把 body 中伪造的 Sec-WebSocket-* 行当成握手头。
        if (line.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(line, "Upgrade:")) {
            const value = std.mem.trim(u8, line["Upgrade:".len..], " \t");
            if (std.ascii.eqlIgnoreCase(value, "websocket")) {
                has_upgrade = true;
            }
        }
        if (std.ascii.startsWithIgnoreCase(line, "Connection:")) {
            const value = std.mem.trim(u8, line["Connection:".len..], " \t\r\n");
            // 修改原因：RFC 6455 握手必须带 Connection: Upgrade；只看 Upgrade 头会把普通请求误升级。
            if (headerValueHasToken(value, "upgrade")) {
                has_connection_upgrade = true;
            }
        }
        if (std.ascii.startsWithIgnoreCase(line, "Sec-WebSocket-Key:")) {
            // 修改原因：后续 extractWsKey 只取第一个 key；重复 key 会让校验值和实际握手值不一致，必须拒绝。
            ws_key_count += 1;
            if (ws_key_count > 1) return false;
            const value = std.mem.trim(u8, line["Sec-WebSocket-Key:".len..], " \t\r\n");
            // 修改原因：Sec-WebSocket-Key 必须是 base64 后的 16 字节 nonce；只检查存在会接受非法握手。
            has_ws_key = isValidWsKey(value);
        }
        if (std.ascii.startsWithIgnoreCase(line, "Sec-WebSocket-Version:")) {
            const value = std.mem.trim(u8, line[22..], " \t\r\n");
            if (std.mem.eql(u8, value, "13")) {
                has_ws_version = true;
            }
        }
    }
    return has_upgrade and has_connection_upgrade and has_ws_key and has_ws_version;
}

fn requestLineIsWebSocketGet(data: []const u8) bool {
    const end = std.mem.indexOf(u8, data, "\r\n") orelse return false;
    const line = data[0..end];
    var parts = std.mem.tokenizeScalar(u8, line, ' ');
    const method = parts.next() orelse return false;
    _ = parts.next() orelse return false;
    const version = parts.next() orelse return false;
    return std.mem.eql(u8, method, "GET") and std.mem.eql(u8, version, "HTTP/1.1");
}

fn headerValueHasToken(value: []const u8, token: []const u8) bool {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(trimmed, token)) return true;
    }
    return false;
}

fn isValidWsKey(key: []const u8) bool {
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(key) catch return false;
    if (decoded_len != 16) return false;
    var decoded: [16]u8 = undefined;
    std.base64.standard.Decoder.decode(&decoded, key) catch return false;
    return true;
}

pub fn extractWsKey(data: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, data, "\r\n");
    while (lines.next()) |line| {
        // 修改原因：Sec-WebSocket-Key 必须来自 HTTP header，不能从 header 结束后的 body 提取。
        if (line.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(line, "Sec-WebSocket-Key:")) {
            const key_start = line[18..];
            const trimmed = std.mem.trim(u8, key_start, " \t\r\n");
            return trimmed;
        }
    }
    return null;
}

pub fn computeAcceptKey(key: []const u8, buf: *[29]u8) !void {
    const Sha1 = std.crypto.hash.Sha1;
    const max_key_len: usize = 128 - websocket_magic.len;
    if (key.len > max_key_len) return error.KeyTooLong;
    // 修改原因：computeAcceptKey 是 public API，不能只依赖调用方先跑 isUpgradeRequest；非法 nonce 不应生成 101 Accept。
    if (!isValidWsKey(key)) return error.InvalidKey;

    var concat: [128]u8 = undefined;
    @memcpy(concat[0..key.len], key);
    @memcpy(concat[key.len..][0..websocket_magic.len], websocket_magic);
    const input = concat[0 .. key.len + websocket_magic.len];

    var hash: [20]u8 = undefined;
    Sha1.hash(input, &hash, .{});

    _ = std.base64.standard.Encoder.encode(buf[0..28], &hash);
    buf[28] = 0;
}

pub fn buildUpgradeResponse(buf: []u8, accept_key: []const u8) !usize {
    const written = try std.fmt.bufPrint(
        buf,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept_key},
    );
    return written.len;
}

test "isUpgradeRequest requires Connection upgrade token" {
    const missing_connection =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expect(!isUpgradeRequest(missing_connection));

    const comma_separated_connection =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Connection: keep-alive, Upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expect(isUpgradeRequest(comma_separated_connection));
}

test "isUpgradeRequest validates Sec-WebSocket-Key nonce" {
    const invalid_key =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Sec-WebSocket-Key: not-a-valid-websocket-key\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expect(!isUpgradeRequest(invalid_key));

    const wrong_decoded_len =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Sec-WebSocket-Key: YWJj\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expect(!isUpgradeRequest(wrong_decoded_len));
}

test "isUpgradeRequest rejects duplicate Sec-WebSocket-Key" {
    const duplicate_key =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Sec-WebSocket-Key: not-a-valid-websocket-key\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expect(!isUpgradeRequest(duplicate_key));
}

test "isUpgradeRequest ignores WebSocket fields after header terminator" {
    const key_in_body =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";

    try std.testing.expect(!isUpgradeRequest(key_in_body));
    try std.testing.expect(extractWsKey(key_in_body) == null);
}

test "computeAcceptKey validates WebSocket nonce" {
    var accept: [29]u8 = undefined;

    try computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==", &accept);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept[0..28]);
    try std.testing.expectError(error.InvalidKey, computeAcceptKey("not-a-valid-websocket-key", &accept));
}

test "isUpgradeRequest requires GET HTTP/1.1 request line" {
    const post_upgrade =
        "POST /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expect(!isUpgradeRequest(post_upgrade));

    const http10_upgrade =
        "GET /ws HTTP/1.0\r\n" ++
        "Host: example.com\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expect(!isUpgradeRequest(http10_upgrade));
}
