const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const logErr = @import("../async_logger.zig").logErr;
const RingShared = @import("../shared/ring_shared.zig").RingShared;
const Fiber = @import("../next/fiber.zig").Fiber;

pub const DNS_FD_MAGIC: u64 = 0xCADE_0000_0000_0000;

// c-ares externs (replace @cImport for Zig 0.16.0 compatibility)
const fd_set = extern struct {
    fds_bits: [32]u32 align(8),
};
const FD_SET_WORD_BITS: usize = 32;
const FD_SET_CAPACITY: usize = 32 * FD_SET_WORD_BITS;

const struct_hostent = extern struct {
    h_name: [*:0]u8,
    h_aliases: [*:0][*:0]u8,
    h_addrtype: i32,
    h_length: i32,
    h_addr_list: [*:0][*:0]u8,
};

const ARES_SUCCESS: i32 = 0;
const AF_INET: i32 = 2;

extern fn ares_init(channel: *?*anyopaque) i32;
extern fn ares_destroy(channel: ?*anyopaque) void;
extern fn ares_gethostbyname(channel: ?*anyopaque, name: [*:0]const u8, family: i32, callback: ?*anyopaque, arg: ?*anyopaque) void;
extern fn ares_process_fd(channel: ?*anyopaque, read_fd: i32, write_fd: i32) void;
extern fn ares_fds(channel: ?*anyopaque, read_fds: *fd_set, write_fds: *fd_set) i32;
extern fn ares_strerror(status: i32) [*:0]const u8;

fn fdSetHas(set: *const fd_set, fd: i32) bool {
    if (fd < 0) return false;
    const fd_index: usize = @intCast(fd);
    if (fd_index >= FD_SET_CAPACITY) return false;
    const word = fd_index / FD_SET_WORD_BITS;
    const bit: u5 = @intCast(fd_index % FD_SET_WORD_BITS);
    return (set.fds_bits[word] & (@as(u32, 1) << bit)) != 0;
}

pub const CaresDns = struct {
    allocator: Allocator,
    channel: ?*anyopaque,
    rs: RingShared,
    result_ip: u32 = 0,
    result_ok: bool = false,
    slot: Fiber.DnsYieldSlot = undefined,
    registered_fds: [8]i32 = [_]i32{-1} ** 8,

    pub fn init(allocator: Allocator, rs: RingShared) !CaresDns {
        var channel: ?*anyopaque = null;
        const status = ares_init(&channel);
        if (status != ARES_SUCCESS) {
            logErr("c-ares init failed: {s}", .{std.mem.span(ares_strerror(status))});
            return error.DnsInitFailed;
        }
        return CaresDns{
            .allocator = allocator,
            .channel = channel,
            .rs = rs,
        };
    }

    pub fn deinit(self: *CaresDns) void {
        self.removeFds();
        ares_destroy(self.channel);
    }

    pub fn resolve(self: *CaresDns, hostname: []const u8) !u32 {
        const host_z = try self.allocator.alloc(u8, hostname.len + 1);
        defer self.allocator.free(host_z);
        @memcpy(host_z[0..hostname.len], hostname);
        host_z[hostname.len] = 0;

        self.result_ok = false;
        self.result_ip = 0;

        ares_gethostbyname(
            self.channel,
            @ptrCast(host_z.ptr),
            AF_INET,
            @ptrCast(&dnsCallback),
            self,
        );

        self.registerFds();
        Fiber.dnsYield(&self.slot);
        self.removeFds();

        if (!self.result_ok) return error.DomainNotFound;
        return self.result_ip;
    }

    pub fn tick(self: *CaresDns) void {
        ares_process_fd(self.channel, -1, -1);
    }

    pub fn handleCqe(self: *CaresDns, ud: u64, res: i32) void {
        _ = res;
        const fd: i32 = @intCast(ud - DNS_FD_MAGIC);
        ares_process_fd(self.channel, fd, -1);
        self.registerFds();
    }

    fn registerFds(self: *CaresDns) void {
        self.removeFds();
        var fds: fd_set = undefined;
        var wfds: fd_set = undefined;
        _ = @memset(@as([*]u8, @ptrCast(&fds))[0..@sizeOf(fd_set)], 0);
        _ = @memset(@as([*]u8, @ptrCast(&wfds))[0..@sizeOf(fd_set)], 0);

        const nfds = ares_fds(self.channel, &fds, &wfds);
        if (nfds <= 0) return;
        // 修改原因：c-ares 返回最高 fd+1，fd 可能超过本地 fd_set 容量，必须截断避免 fds_bits 越界。
        const fd_limit = @min(@as(usize, @intCast(nfds)), FD_SET_CAPACITY);
        var registered_count: usize = 0;
        var fd: usize = 0;
        while (fd < fd_limit and registered_count < self.registered_fds.len) : (fd += 1) {
            const fd_i32: i32 = @intCast(fd);
            const read_set = fdSetHas(&fds, fd_i32);
            const write_set = fdSetHas(&wfds, fd_i32);
            if (!read_set and !write_set) continue;

            const user_data = DNS_FD_MAGIC + @as(u64, @intCast(fd));
            const sqe = self.rs.ring.nop(user_data) catch continue;
            sqe.opcode = @enumFromInt(6);
            sqe.fd = fd_i32;
            sqe.poll_events = if (write_set) @as(u32, 5) else @as(u32, 1);
            sqe.len = 1;

            self.registered_fds[registered_count] = fd_i32;
            registered_count += 1;
        }
        _ = self.rs.ring.submit() catch {};
    }

    fn removeFds(self: *CaresDns) void {
        for (&self.registered_fds) |*fd_ptr| {
            if (fd_ptr.* >= 0) {
                const fd = fd_ptr.*;
                const user_data = DNS_FD_MAGIC + @as(u64, @intCast(fd));
                // 修改原因：POLL_REMOVE 用 target_user_data 定位原 poll，单独写 fd 不能取消对应的 DNS poll SQE。
                _ = self.rs.ring.poll_remove(user_data, user_data) catch continue;
                fd_ptr.* = -1;
            }
        }
        _ = self.rs.ring.submit() catch {};
    }
};

fn dnsCallback(
    arg: ?*anyopaque,
    status: i32,
    timeouts: i32,
    hostent: ?*struct_hostent,
) callconv(.c) void {
    _ = timeouts;
    const self: *CaresDns = @ptrCast(@alignCast(arg));
    if (status != ARES_SUCCESS or hostent == null) {
        self.result_ok = false;
        return;
    }
    const h = hostent.?;
    if (h.h_addr_list[0]) |first_addr| {
        self.result_ip = @as(*align(1) const u32, @ptrCast(first_addr)).*;
        self.result_ok = true;
    } else {
        self.result_ok = false;
    }
}

test "fdSetHas ignores descriptors outside fixed fd_set capacity" {
    var fds = std.mem.zeroes(fd_set);
    fds.fds_bits[0] = 1;
    fds.fds_bits[31] = @as(u32, 1) << 31;

    try std.testing.expect(fdSetHas(&fds, 0));
    try std.testing.expect(fdSetHas(&fds, 1023));
    try std.testing.expect(!fdSetHas(&fds, 1024));
    try std.testing.expect(!fdSetHas(&fds, -1));
}
