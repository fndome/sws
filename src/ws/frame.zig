const std = @import("std");
const Opcode = @import("types.zig").Opcode;
pub const Frame = @import("types.zig").Frame;

pub fn parseFrame(data: []u8) !Frame {
    if (data.len < 2) return error.IncompleteFrame;

    const first_byte = data[0];
    const second_byte = data[1];

    const fin = (first_byte & 0x80) != 0;
    const rsv = first_byte & 0x70;
    const opcode = Opcode.fromByte(first_byte) orelse return error.UnknownOpcode;
    const mask = (second_byte & 0x80) != 0;
    var payload_len: u64 = @intCast(second_byte & 0x7F);

    // The server must reject RSV bits for unnegotiated extensions and unmasked frames when parsing client frames,
    // otherwise it would accept RFC 6455-violating input and pass the protocol error to the later business path.
    if (rsv != 0 or !mask) return error.InvalidFrame;

    var offset: usize = 2;

    if (payload_len == 126) {
        if (data.len < 4) return error.IncompleteFrame;
        payload_len = std.mem.readInt(u16, data[2..4], .big);
        // RFC 6455 requires the payload length to use its minimal encoding; accepting non-minimal encodings would relax the protocol boundary and bypass the length-branch check.
        if (payload_len < 126) return error.InvalidFrame;
        offset = 4;
    } else if (payload_len == 127) {
        if (data.len < 10) return error.IncompleteFrame;
        payload_len = std.mem.readInt(u64, data[2..10], .big);
        if (payload_len & 0x8000_0000_0000_0000 != 0) return error.InvalidFrame;
        if (payload_len <= 0xFFFF) return error.InvalidFrame;
        offset = 10;
    }

    // Control frames must not be fragmented per the protocol, and their payload cannot exceed 125 bytes;
    // rejecting early avoids the ping/close response path allocating for an invalid length or failing to write the frame.
    switch (opcode) {
        .close, .ping, .pong => if (!fin or payload_len > 125) return error.InvalidFrame,
        else => {},
    }
    switch (opcode) {
        .continuation => return error.InvalidFrame,
        .text, .binary => {
            // The server does not maintain WebSocket fragmented-message state; accepting FIN=0 would hand a half-message directly to the business handler.
            if (!fin) return error.InvalidFrame;
        },
        else => {},
    }
    if (opcode == .close and payload_len == 1) {
        // A Close frame payload is either empty or at least 2 bytes for the status code; 1 byte would make close-reason parsing read half of the data.
        return error.InvalidFrame;
    }

    var mask_key: [4]u8 = undefined;
    if (mask) {
        if (data.len < offset + 4) return error.IncompleteFrame;
        @memcpy(&mask_key, data[offset..][0..4]);
        offset += 4;
    }

    if (payload_len > std.math.maxInt(usize)) return error.FrameTooLarge;
    const payload_len_usize: usize = @intCast(payload_len);
    if (payload_len_usize > data.len - offset) return error.IncompleteFrame;
    const payload = data[offset..][0..payload_len_usize];

    if (mask) {
        maskPayload(payload, mask_key);
    }
    if (opcode == .close and payload.len >= 2) {
        const code = std.mem.readInt(u16, payload[0..2], .big);
        // Close frame status codes have reserved ranges; not validating would hand an illegal close reason to the business layer and break the WebSocket protocol boundary.
        if (!isValidCloseCode(code)) return error.InvalidFrame;
    }

    return Frame{ .opcode = opcode, .fin = fin, .payload = payload };
}

fn isValidCloseCode(code: u16) bool {
    if (code < 1000) return false;
    if (code >= 1000 and code <= 1015) {
        return switch (code) {
            1004, 1005, 1006, 1015 => false,
            else => true,
        };
    }
    if (code >= 3000 and code <= 4999) return true;
    return false;
}

test "parseFrame rejects invalid client control frames" {
    var unmasked = [_]u8{ 0x89, 0x00 };
    try std.testing.expectError(error.InvalidFrame, parseFrame(&unmasked));

    var fragmented_ping = [_]u8{ 0x09, 0x80, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidFrame, parseFrame(&fragmented_ping));

    var oversized_ping = [_]u8{ 0x89, 0xFE, 0, 126, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidFrame, parseFrame(&oversized_ping));

    var one_byte_close = [_]u8{ 0x88, 0x81, 0, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidFrame, parseFrame(&one_byte_close));

    var invalid_close_code = [_]u8{ 0x88, 0x82, 0, 0, 0, 0, 0x03, 0xE7 };
    try std.testing.expectError(error.InvalidFrame, parseFrame(&invalid_close_code));
}

test "parseFrame rejects non-minimal payload length encoding" {
    var small_as_126 = [_]u8{ 0x81, 0xFE, 0, 125 };
    try std.testing.expectError(error.InvalidFrame, parseFrame(&small_as_126));

    var medium_as_127 = [_]u8{ 0x81, 0xFF, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
    try std.testing.expectError(error.InvalidFrame, parseFrame(&medium_as_127));
}

test "parseFrame treats huge declared payload as incomplete" {
    var huge = [_]u8{ 0x81, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0 };
    try std.testing.expectError(error.IncompleteFrame, parseFrame(&huge));
}

test "parseFrame rejects unsupported fragmented data frames" {
    var fragmented_text = [_]u8{ 0x01, 0x80, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidFrame, parseFrame(&fragmented_text));

    var orphan_continuation = [_]u8{ 0x80, 0x80, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidFrame, parseFrame(&orphan_continuation));
}

test "control frames allow the RFC maximum payload" {
    var ping = [_]u8{0} ** (2 + 4 + 125);
    ping[0] = 0x89;
    ping[1] = 0x80 | 125;

    const parsed = try parseFrame(ping[0..]);
    try std.testing.expectEqual(Opcode.ping, parsed.opcode);
    try std.testing.expectEqual(@as(usize, 125), parsed.payload.len);

    var out: [127]u8 = undefined;
    const written = try writeFrame(&out, .{ .opcode = .pong, .fin = true, .payload = parsed.payload });
    try std.testing.expectEqual(@as(usize, out.len), written);
}

test "writeFrame rejects invalid outbound control frames" {
    var out: [256]u8 = undefined;
    var oversized = [_]u8{0} ** 126;
    var empty = [_]u8{};
    var one_byte_close = [_]u8{0};
    var invalid_close_code = [_]u8{ 0x03, 0xE7 };

    try std.testing.expectError(error.InvalidFrame, writeFrame(&out, .{ .opcode = .ping, .fin = true, .payload = oversized[0..] }));
    try std.testing.expectError(error.InvalidFrame, writeFrame(&out, .{ .opcode = .pong, .fin = false, .payload = empty[0..] }));
    try std.testing.expectError(error.InvalidFrame, writeFrame(&out, .{ .opcode = .close, .fin = true, .payload = one_byte_close[0..] }));
    try std.testing.expectError(error.InvalidFrame, writeFrame(&out, .{ .opcode = .close, .fin = true, .payload = invalid_close_code[0..] }));
}

pub fn frameSize(payload_len: usize) usize {
    var hdr: usize = 2;
    if (payload_len > 125) {
        if (payload_len > 0xFFFF) {
            hdr += 8;
        } else {
            hdr += 2;
        }
    }
    return hdr + payload_len;
}

fn validateOutboundFrame(frame: Frame) !void {
    switch (frame.opcode) {
        .close, .ping, .pong => {
            // The server must also follow RFC 6455 when generating control frames; otherwise the application layer could send overlong ping/pong or an illegal close payload.
            if (!frame.fin or frame.payload.len > 125) return error.InvalidFrame;
            if (frame.opcode == .close) {
                if (frame.payload.len == 1) return error.InvalidFrame;
                if (frame.payload.len >= 2) {
                    const code = std.mem.readInt(u16, frame.payload[0..2], .big);
                    if (!isValidCloseCode(code)) return error.InvalidFrame;
                }
            }
        },
        else => {},
    }
}

pub fn writeFrame(buf: []u8, frame: Frame) !usize {
    try validateOutboundFrame(frame);
    const total = frameSize(frame.payload.len);
    if (buf.len < total) return error.BufferTooSmall;

    var first_byte: u8 = 0;
    if (frame.fin) first_byte |= 0x80;
    first_byte |= @as(u8, @intFromEnum(frame.opcode));
    buf[0] = first_byte;

    var offset: usize = 1;

    if (frame.payload.len <= 125) {
        buf[1] = @as(u8, @intCast(frame.payload.len));
        offset = 2;
    } else if (frame.payload.len <= 0xFFFF) {
        buf[1] = 126;
        std.mem.writeInt(u16, buf[2..4], @as(u16, @intCast(frame.payload.len)), .big);
        offset = 4;
    } else {
        buf[1] = 127;
        std.mem.writeInt(u64, buf[2..10], @as(u64, @intCast(frame.payload.len)), .big);
        offset = 10;
    }

    @memcpy(buf[offset..][0..frame.payload.len], frame.payload);
    return total;
}

/// SIMD-accelerated WebSocket masking.
/// Replicates the 4-byte mask_key into a 16-byte vector and XORs 16 bytes per round.
fn maskPayload(payload: []u8, mask_key: [4]u8) void {
    const Vec = @Vector(16, u8);
    const mask_vec: Vec = [_]u8{
        mask_key[0], mask_key[1], mask_key[2], mask_key[3],
        mask_key[0], mask_key[1], mask_key[2], mask_key[3],
        mask_key[0], mask_key[1], mask_key[2], mask_key[3],
        mask_key[0], mask_key[1], mask_key[2], mask_key[3],
    };

    var i: usize = 0;
    const chunk_count = payload.len / 16;
    if (chunk_count > 0 and @intFromPtr(&payload[0]) & 15 == 0) {
        // Aligned fast path: SIMD XOR 16 bytes at a time
        for (0..chunk_count) |_| {
            const chunk: *Vec = @ptrCast(@alignCast(&payload[i]));
            chunk.* ^= mask_vec;
            i += 16;
        }
    } else if (chunk_count > 0) {
        // Unaligned payload: fall back to 4-byte-at-a-time XOR using
        // readInt/writeInt which handle unaligned access safely.
        // Avoids the byte-by-byte slow path for moderate-sized frames.
        const mask_u32 = (@as(u32, mask_key[0])) |
            (@as(u32, mask_key[1]) << 8) |
            (@as(u32, mask_key[2]) << 16) |
            (@as(u32, mask_key[3]) << 24);
        const bulk_end = chunk_count * 16;
        i = 0;
        while (i + 4 <= bulk_end) : (i += 4) {
            const val = std.mem.readInt(u32, payload[i..][0..4], .little);
            std.mem.writeInt(u32, payload[i..][0..4], val ^ mask_u32, .little);
        }
    }
    // Tail: remaining < 16 bytes
    while (i < payload.len) : (i += 1) {
        payload[i] ^= mask_key[i & 3];
    }
}
