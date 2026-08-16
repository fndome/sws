const std = @import("std");

pub const DNS_PORT: u16 = 53;
pub const MAX_PACKET_SIZE: u16 = 512;

pub const RecordType = enum(u16) {
    A = 1,
    CNAME = 5,
    AAAA = 28,
    _,
};

pub const Rcode = enum(u4) {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    _,
};

pub const AddrList = struct {
    addrs: [MAX_ADDRS]u32,
    len: u8,
    pub const MAX_ADDRS = 8;
};

pub const ParsedResponse = struct {
    rcode: Rcode,
    ttl: u32,
    addrs: AddrList,
};

pub const QueryPacket = struct {
    buf: [MAX_PACKET_SIZE]u8,
    len: usize,

    pub fn bytes(self: *const QueryPacket) []const u8 {
        return self.buf[0..self.len];
    }
};

pub fn buildQuery(hostname: []const u8, txid: u16) !QueryPacket {
    var buf: [MAX_PACKET_SIZE]u8 = [_]u8{0} ** MAX_PACKET_SIZE;
    var off: usize = 0;

    std.mem.writeInt(u16, buf[off..][0..2], txid, .big);
    off += 2;
    buf[off] = 0x01;
    off += 1;
    buf[off] = 0x00;
    off += 1;
    std.mem.writeInt(u16, buf[off..][0..2], 1, .big);
    off += 2;
    std.mem.writeInt(u16, buf[off..][0..2], 0, .big);
    off += 2;
    std.mem.writeInt(u16, buf[off..][0..2], 0, .big);
    off += 2;
    std.mem.writeInt(u16, buf[off..][0..2], 0, .big);
    off += 2;

    off += try encodeName(hostname, buf[off..]);

    std.mem.writeInt(u16, buf[off..][0..2], 1, .big);
    off += 2;
    std.mem.writeInt(u16, buf[off..][0..2], 1, .big);
    off += 2;

    // A DNS UDP request must only send the actually written message length, not the whole 512-byte buffer.
    return .{ .buf = buf, .len = off };
}

fn encodeName(name: []const u8, out: []u8) !usize {
    if (name.len == 0) {
        out[0] = 0;
        return 1;
    }
    // Absolute DNS names allow a trailing dot, e.g. example.com.; the trailing dot only denotes the root and must not be reported as an empty label.
    const wire_name = if (name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
    if (wire_name.len == 0) {
        out[0] = 0;
        return 1;
    }
    var off: usize = 0;
    var it = std.mem.splitScalar(u8, wire_name, '.');
    while (it.next()) |label| {
        if (label.len > 63) return error.LabelTooLong;
        if (label.len == 0) return error.EmptyLabel;
        // The DNS name wire format is at most 255 bytes; an overlong hostname must error out instead of continuing to write into a fixed buffer and overflowing.
        if (off + 1 + label.len + 1 > 255) return error.NameTooLong;
        if (off + 1 + label.len > out.len) return error.NameTooLong;
        out[off] = @intCast(label.len);
        off += 1;
        @memcpy(out[off..][0..label.len], label);
        off += label.len;
    }
    if (off + 1 > out.len) return error.NameTooLong;
    out[off] = 0;
    off += 1;
    return off;
}

pub fn parseResponse(packet: []const u8) ParsedResponse {
    var resp = ParsedResponse{
        .rcode = .NOERROR,
        .ttl = 60,
        .addrs = .{ .addrs = [_]u32{0} ** AddrList.MAX_ADDRS, .len = 0 },
    };

    if (packet.len < 12) {
        resp.rcode = .SERVFAIL;
        return resp;
    }

    const flags1 = packet[2];
    const qr = (flags1 >> 7) & 1;
    if (qr != 1) {
        resp.rcode = .SERVFAIL;
        return resp;
    }
    // The resolver only sends standard QUERY; a response with a non-zero opcode cannot be parsed as a normal hostname query result.
    if (((flags1 >> 3) & 0x0F) != 0) {
        resp.rcode = .SERVFAIL;
        return resp;
    }
    // TC means the UDP response was truncated; using its A records would treat an incomplete answer as a complete result.
    if ((flags1 & 0x02) != 0) {
        resp.rcode = .SERVFAIL;
        return resp;
    }

    const flags2 = packet[3];
    resp.rcode = @enumFromInt(flags2 & 0x0F);
    if (resp.rcode != .NOERROR) return resp;

    const qdcount = std.mem.readInt(u16, packet[4..6], .big);
    // The resolver only sends a single-question query; a response with an unexpected question count cannot be reliably matched to the current hostname.
    if (qdcount != 1) {
        resp.rcode = .SERVFAIL;
        return resp;
    }

    const ancount = std.mem.readInt(u16, packet[6..8], .big);
    // A records in the authority/additional section are not answers for the queried name and must not be returned as the result.
    const total = ancount;

    var off: usize = 12;

    var qi: u16 = 0;
    _ = &qi;
    var q: u16 = 0;
    while (q < qdcount) : (q += 1) {
        off = skipName(packet, off) orelse {
            resp.rcode = .SERVFAIL;
            return resp;
        };
        if (off + 4 > packet.len) {
            resp.rcode = .SERVFAIL;
            return resp;
        }
        const qtype = std.mem.readInt(u16, packet[off..][0..2], .big);
        const qclass = std.mem.readInt(u16, packet[off + 2 ..][0..2], .big);
        // The resolver only queries A/IN; when the echoed question does not match, the subsequent answers cannot be trusted.
        if (qtype != 1 or qclass != 1) {
            resp.rcode = .SERVFAIL;
            return resp;
        }
        off += 4;
    }

    var min_ttl: u32 = std.math.maxInt(u32);
    var i: u16 = 0;
    while (i < total) : (i += 1) {
        off = skipName(packet, off) orelse {
            // When the answer section is structurally corrupt, the already-parsed A records must not be returned, or a malformed DNS response would be cached.
            resp.rcode = .SERVFAIL;
            resp.addrs.len = 0;
            return resp;
        };
        if (off + 10 > packet.len) {
            // A truncated RR header means the whole packet's answer section is untrusted, so the preceding complete records must not be treated as the final result.
            resp.rcode = .SERVFAIL;
            resp.addrs.len = 0;
            return resp;
        }
        const rtype = std.mem.readInt(u16, packet[off..][0..2], .big);
        off += 2;
        const rclass = std.mem.readInt(u16, packet[off..][0..2], .big);
        off += 2; // class
        const ttl = std.mem.readInt(u32, packet[off..][0..4], .big);
        off += 4;
        const rdlen = std.mem.readInt(u16, packet[off..][0..2], .big);
        off += 2;

        if (off + rdlen > packet.len) {
            // Truncated RDATA likewise makes the answer count inconsistent with the content, so the whole packet must be rejected rather than using partial addresses.
            resp.rcode = .SERVFAIL;
            resp.addrs.len = 0;
            return resp;
        }

        // Only IN-class A records are IPv4 address answers; A records of other classes (CHAOS/HS, etc.) must not be written into the connect address.
        if (rtype == 1 and rclass == 1 and rdlen == 4) {
            if (resp.addrs.len < AddrList.MAX_ADDRS) {
                const ip: u32 = (@as(u32, packet[off]) << 24) |
                    (@as(u32, packet[off + 1]) << 16) |
                    (@as(u32, packet[off + 2]) << 8) |
                    @as(u32, packet[off + 3]);
                // A records are written directly into sockaddr by the later TCP connect, so they must be stored in network byte order.
                resp.addrs.addrs[resp.addrs.len] = std.mem.nativeToBig(u32, ip);
                resp.addrs.len += 1;
            }
            if (ttl < min_ttl) min_ttl = ttl;
        }
        off += rdlen;
    }

    if (min_ttl != std.math.maxInt(u32)) resp.ttl = min_ttl;
    return resp;
}

fn skipName(packet: []const u8, start: usize) ?usize {
    var off = start;
    while (off < packet.len) {
        const len = packet[off];
        if (len == 0) return off + 1;
        if (len & 0xC0 == 0xC0) {
            // A compression pointer must occupy a full 2 bytes; a missing second byte means the following fields cannot be parsed.
            if (off + 2 > packet.len) return null;
            return off + 2;
        }
        // A normal DNS label must have its top two bits set to 00; reserved formats and overlong labels are both malformed names.
        if ((len & 0xC0) != 0 or len > 63) return null;
        if (off + 1 + @as(usize, len) > packet.len) return null;
        off += @as(usize, len) + 1;
    }
    return null;
}

pub fn parseTxid(packet: []const u8) u16 {
    if (packet.len < 2) return 0;
    return std.mem.readInt(u16, packet[0..2], .big);
}

fn appendTestRootARecord(buf: []u8, off: *usize, ip: [4]u8) void {
    appendTestRootARecordWithClass(buf, off, ip, 1);
}

// DNS response test samples must include the single question the resolver actually sends, to avoid bypassing the QDCOUNT check.
fn appendTestRootQuestion(buf: []u8, off: *usize) void {
    appendTestRootQuestionWithTypeClass(buf, off, 1, 1);
}

fn appendTestRootQuestionWithTypeClass(buf: []u8, off: *usize, qtype: u16, qclass: u16) void {
    buf[off.*] = 0;
    off.* += 1;
    std.mem.writeInt(u16, buf[off.*..][0..2], qtype, .big);
    off.* += 2;
    std.mem.writeInt(u16, buf[off.*..][0..2], qclass, .big);
    off.* += 2;
}

fn appendTestRootARecordWithClass(buf: []u8, off: *usize, ip: [4]u8, class: u16) void {
    buf[off.*] = 0;
    off.* += 1;
    std.mem.writeInt(u16, buf[off.*..][0..2], 1, .big);
    off.* += 2;
    std.mem.writeInt(u16, buf[off.*..][0..2], class, .big);
    off.* += 2;
    std.mem.writeInt(u32, buf[off.*..][0..4], 60, .big);
    off.* += 4;
    std.mem.writeInt(u16, buf[off.*..][0..2], 4, .big);
    off.* += 2;
    @memcpy(buf[off.*..][0..4], &ip);
    off.* += 4;
}

test "buildQuery reports actual DNS message length" {
    const query = try buildQuery("example.com", 0x1234);

    try std.testing.expectEqual(@as(usize, 29), query.len);
    try std.testing.expectEqual(query.len, query.bytes().len);
    try std.testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, query.buf[0..2], .big));
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, query.buf[query.len - 4 ..][0..2], .big));
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, query.buf[query.len - 2 ..][0..2], .big));
}

test "buildQuery rejects DNS names longer than wire limit" {
    var name_buf: [259]u8 = undefined;
    var pos: usize = 0;
    for (0..130) |i| {
        if (i != 0) {
            name_buf[pos] = '.';
            pos += 1;
        }
        name_buf[pos] = 'a';
        pos += 1;
    }

    try std.testing.expectError(error.NameTooLong, buildQuery(name_buf[0..pos], 0x1234));
}

test "buildQuery accepts trailing root dot" {
    const relative = try buildQuery("example.com", 0x1234);
    const absolute = try buildQuery("example.com.", 0x1234);
    try std.testing.expectEqualSlices(u8, relative.bytes(), absolute.bytes());

    const root = try buildQuery(".", 0x1234);
    try std.testing.expectEqual(@as(usize, 17), root.len);
    try std.testing.expectEqual(@as(u8, 0), root.buf[12]);
}

test "parseResponse tolerates malformed answer name" {
    var pkt = [_]u8{0} ** 24;
    pkt[2] = 0x80; // QR response
    pkt[5] = 1; // QDCOUNT = 1
    pkt[7] = 1; // ANCOUNT = 1
    var off: usize = 12;
    appendTestRootQuestion(&pkt, &off);
    pkt[off] = 20; // label claims more bytes than the packet contains

    const parsed = parseResponse(&pkt);
    try std.testing.expectEqual(Rcode.SERVFAIL, parsed.rcode);
    try std.testing.expectEqual(@as(u8, 0), parsed.addrs.len);
}

test "parseResponse rejects truncated answer after valid record" {
    var pkt = [_]u8{0} ** 64;
    pkt[2] = 0x80; // QR response
    pkt[5] = 1; // QDCOUNT = 1
    pkt[7] = 2; // ANCOUNT = 2, second answer will be truncated

    var off: usize = 12;
    appendTestRootQuestion(&pkt, &off);
    appendTestRootARecord(&pkt, &off, .{ 1, 2, 3, 4 });
    pkt[off] = 0; // second answer name only; RR header is missing
    off += 1;

    const parsed = parseResponse(pkt[0..off]);
    try std.testing.expectEqual(Rcode.SERVFAIL, parsed.rcode);
    try std.testing.expectEqual(@as(u8, 0), parsed.addrs.len);
}

test "parseResponse ignores additional A records" {
    var pkt = [_]u8{0} ** 47;
    pkt[2] = 0x80; // QR response
    pkt[5] = 1; // QDCOUNT = 1
    pkt[7] = 1; // ANCOUNT = 1
    pkt[11] = 1; // ARCOUNT = 1

    var off: usize = 12;
    appendTestRootQuestion(&pkt, &off);
    appendTestRootARecord(&pkt, &off, .{ 1, 2, 3, 4 });
    appendTestRootARecord(&pkt, &off, .{ 5, 6, 7, 8 });

    const parsed = parseResponse(pkt[0..off]);
    try std.testing.expectEqual(@as(u8, 1), parsed.addrs.len);
    try std.testing.expectEqual(std.mem.nativeToBig(u32, 0x01020304), parsed.addrs.addrs[0]);
}

test "parseResponse ignores non-IN A records" {
    var pkt = [_]u8{0} ** 32;
    pkt[2] = 0x80; // QR response
    pkt[5] = 1; // QDCOUNT = 1
    pkt[7] = 1; // ANCOUNT = 1

    var off: usize = 12;
    appendTestRootQuestion(&pkt, &off);
    appendTestRootARecordWithClass(&pkt, &off, .{ 9, 9, 9, 9 }, 3);

    const parsed = parseResponse(pkt[0..off]);
    try std.testing.expectEqual(@as(u8, 0), parsed.addrs.len);
}

test "parseResponse rejects truncated question" {
    var pkt = [_]u8{0} ** 16;
    pkt[2] = 0x80; // QR response
    pkt[5] = 1; // QDCOUNT = 1
    pkt[12] = 20; // malformed question name

    const parsed = parseResponse(&pkt);
    try std.testing.expectEqual(Rcode.SERVFAIL, parsed.rcode);
}

test "parseResponse rejects reserved question label format" {
    var pkt = [_]u8{0} ** 17;
    pkt[2] = 0x80; // QR response
    pkt[5] = 1; // QDCOUNT = 1
    pkt[12] = 0x40; // reserved label format, not a length or compression pointer

    const parsed = parseResponse(&pkt);
    try std.testing.expectEqual(Rcode.SERVFAIL, parsed.rcode);
}

test "parseResponse rejects unexpected question count" {
    var pkt = [_]u8{0} ** 28;
    pkt[2] = 0x80; // QR response
    pkt[7] = 1; // ANCOUNT = 1, but QDCOUNT stays 0

    var off: usize = 12;
    appendTestRootARecord(&pkt, &off, .{ 1, 2, 3, 4 });

    const parsed = parseResponse(pkt[0..off]);
    try std.testing.expectEqual(Rcode.SERVFAIL, parsed.rcode);
    try std.testing.expectEqual(@as(u8, 0), parsed.addrs.len);
}

test "parseResponse rejects truncated response" {
    var pkt = [_]u8{0} ** 32;
    pkt[2] = 0x82; // QR response + TC truncated flag
    pkt[5] = 1; // QDCOUNT = 1
    pkt[7] = 1; // ANCOUNT = 1

    var off: usize = 12;
    appendTestRootQuestion(&pkt, &off);
    appendTestRootARecord(&pkt, &off, .{ 1, 2, 3, 4 });

    const parsed = parseResponse(pkt[0..off]);
    try std.testing.expectEqual(Rcode.SERVFAIL, parsed.rcode);
    try std.testing.expectEqual(@as(u8, 0), parsed.addrs.len);
}

test "parseResponse rejects non-query opcode response" {
    var pkt = [_]u8{0} ** 32;
    pkt[2] = 0x88; // QR response + opcode 1 instead of standard QUERY
    pkt[5] = 1; // QDCOUNT = 1
    pkt[7] = 1; // ANCOUNT = 1

    var off: usize = 12;
    appendTestRootQuestion(&pkt, &off);
    appendTestRootARecord(&pkt, &off, .{ 1, 2, 3, 4 });

    const parsed = parseResponse(pkt[0..off]);
    try std.testing.expectEqual(Rcode.SERVFAIL, parsed.rcode);
    try std.testing.expectEqual(@as(u8, 0), parsed.addrs.len);
}

test "parseResponse rejects mismatched question type" {
    var pkt = [_]u8{0} ** 32;
    pkt[2] = 0x80; // QR response
    pkt[5] = 1; // QDCOUNT = 1
    pkt[7] = 1; // ANCOUNT = 1

    var off: usize = 12;
    appendTestRootQuestionWithTypeClass(&pkt, &off, 28, 1);
    appendTestRootARecord(&pkt, &off, .{ 1, 2, 3, 4 });

    const parsed = parseResponse(pkt[0..off]);
    try std.testing.expectEqual(Rcode.SERVFAIL, parsed.rcode);
    try std.testing.expectEqual(@as(u8, 0), parsed.addrs.len);
}
