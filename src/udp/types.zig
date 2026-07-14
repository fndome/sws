const std = @import("std");
const linux = std.os.linux;

pub const SenderAddr = struct {
    ip: u32,
    port: u16,
};

pub const UdpHandler = *const fn (sender: SenderAddr, data: []u8, ctx: *anyopaque) void;
