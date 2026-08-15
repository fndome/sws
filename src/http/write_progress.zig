//! Pure write-path decision helpers, extracted so they can be unit-tested on
//! the host (no `std.os.linux` / io_uring imports) and shared by all four
//! write-completion handlers (http plain, http TLS, ws, raw tcp).

const std = @import("std");

/// Max partial-write retries before giving up on a response whose client is
/// draining too slowly. Sized by total bytes so a large body gets a larger
/// retry budget, clamped to [4, 64]; small responses (<= 1460) get a flat 3.
pub fn maxWriteRetries(total: usize) u8 {
    if (total <= 1460) return 3;
    const base: usize = total / 4096;
    const retries: usize = if (base < 4) @as(usize, 4) else if (base > 64) @as(usize, 64) else base;
    return @intCast(retries);
}

/// Total bytes to write for a response = header bytes + optional body bytes.
pub fn writeTotal(headers_len: usize, body_len: usize) usize {
    return headers_len + body_len;
}

/// Advance offset after a write CQE. Returns the new offset (saturating at
/// `total`); callers decide complete-vs-partial from the result.
pub fn advanceOffset(offset: usize, written: usize, total: usize) usize {
    const next = offset + written;
    return if (next > total) total else next;
}

/// Plaintext bytes advanced per TLS write completion chunk. The TLS path
/// advances by the chunk of plaintext it encrypted (<= 16384) rather than by
/// the ciphertext bytes actually written.
pub fn tlsChunkAdvance(total: usize, offset: usize) usize {
    const remaining = if (total > offset) total - offset else 0;
    return @min(remaining, @as(usize, 16384));
}

test "maxWriteRetries small responses" {
    try std.testing.expectEqual(@as(u8, 3), maxWriteRetries(0));
    try std.testing.expectEqual(@as(u8, 3), maxWriteRetries(1460));
}

test "maxWriteRetries clamps low base to 4" {
    try std.testing.expectEqual(@as(u8, 4), maxWriteRetries(1461));
    try std.testing.expectEqual(@as(u8, 4), maxWriteRetries(4096));
    try std.testing.expectEqual(@as(u8, 4), maxWriteRetries(4 * 4096 - 1));
}

test "maxWriteRetries scales with size" {
    try std.testing.expectEqual(@as(u8, 4), maxWriteRetries(4 * 4096));
    try std.testing.expectEqual(@as(u8, 5), maxWriteRetries(5 * 4096));
    try std.testing.expectEqual(@as(u8, 64), maxWriteRetries(64 * 4096));
}

test "maxWriteRetries clamps high base to 64" {
    try std.testing.expectEqual(@as(u8, 64), maxWriteRetries(65 * 4096));
    try std.testing.expectEqual(@as(u8, 64), maxWriteRetries(1 << 30));
}

test "advanceOffset saturates at total" {
    try std.testing.expectEqual(@as(usize, 100), advanceOffset(0, 100, 100));
    try std.testing.expectEqual(@as(usize, 100), advanceOffset(90, 30, 100));
    try std.testing.expectEqual(@as(usize, 60), advanceOffset(0, 60, 100));
}

test "tlsChunkAdvance caps at 16KiB and clamps to remaining" {
    try std.testing.expectEqual(@as(usize, 16384), tlsChunkAdvance(20000, 0));
    try std.testing.expectEqual(@as(usize, 5000), tlsChunkAdvance(20000, 15000));
    try std.testing.expectEqual(@as(usize, 0), tlsChunkAdvance(20000, 20000));
    try std.testing.expectEqual(@as(usize, 0), tlsChunkAdvance(100, 200));
}
