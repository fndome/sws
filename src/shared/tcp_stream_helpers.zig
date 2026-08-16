//! Pure helpers for the outbound tcp_stream client (no io_uring dependency),
//! so they are unit-testable on the host via `zig test`.

const std = @import("std");

/// user_data flag bit marking a client write CQE (set together with the
/// CLIENT_USER_DATA_FLAG bit 62, never alone).
pub const CLIENT_WRITE_USER_DATA_FLAG: u64 = 1 << 61;

pub fn isWriteCqe(user_data: u64) bool {
    return (user_data & CLIENT_WRITE_USER_DATA_FLAG) != 0;
}

pub fn hasConnectSqeCapacity(ready: usize, capacity: usize, timeout_ms: u32) bool {
    if (ready > capacity) return false;
    const needed: usize = if (timeout_ms > 0) 2 else 1;
    return capacity - ready >= needed;
}

test "distinguishes write CQE user data" {
    const base = @as(u64, 1) << 62;
    try std.testing.expect(!isWriteCqe(base));
    try std.testing.expect(isWriteCqe(base | CLIENT_WRITE_USER_DATA_FLAG));
}

test "connect submit checks timeout SQE capacity" {
    try std.testing.expect(hasConnectSqeCapacity(254, 256, 5000));
    try std.testing.expect(!hasConnectSqeCapacity(255, 256, 5000));
    try std.testing.expect(hasConnectSqeCapacity(255, 256, 0));
}
