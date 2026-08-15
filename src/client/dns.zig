const std = @import("std");
const Allocator = std.mem.Allocator;

const logErr = @import("../async_logger.zig").logErr;
const Fiber = @import("../next/fiber.zig").Fiber;

// c-ares externs (replace @cImport for Zig 0.16.0 compatibility).
// NOTE: this backend must be linked with libc-ares and is opt-in; the default
// resolver is src/dns/resolver.zig (io_uring async UDP DNS).
const struct_hostent = extern struct {
    h_name: [*:0]u8,
    h_aliases: [*:0][*:0]u8,
    h_addrtype: i32,
    h_length: i32,
    h_addr_list: [*:0][*:0]u8,
};

const fd_set = extern struct {
    fds_bits: [32]u32 align(8),
};
const FD_SET_WORD_BITS: usize = 32;
const FD_SET_CAPACITY: usize = 32 * FD_SET_WORD_BITS;

fn fdSetHas(set: *const fd_set, fd: i32) bool {
    if (fd < 0) return false;
    const fd_index: usize = @intCast(fd);
    if (fd_index >= FD_SET_CAPACITY) return false;
    const word = fd_index / FD_SET_WORD_BITS;
    const bit: u5 = @intCast(fd_index % FD_SET_WORD_BITS);
    return (set.fds_bits[word] & (@as(u32, 1) << bit)) != 0;
}

const ARES_SUCCESS: i32 = 0;
const AF_INET: i32 = 2;

extern fn ares_init(channel: *?*anyopaque) i32;
extern fn ares_destroy(channel: ?*anyopaque) void;
extern fn ares_gethostbyname(channel: ?*anyopaque, name: [*:0]const u8, family: i32, callback: ?*anyopaque, arg: ?*anyopaque) void;
extern fn ares_process_fd(channel: ?*anyopaque, read_fd: i32, write_fd: i32) void;
extern fn ares_fds(channel: ?*anyopaque, read_fds: *fd_set, write_fds: *fd_set) i32;
extern fn ares_strerror(status: i32) [*:0]const u8;

/// c-ares async DNS adapter.
///
/// resolve() submits the query and suspends the calling fiber; tick() must be
/// driven from the event loop to pump c-ares and resume the fiber once the
/// callback has fired. This is intentionally polling-based rather than using
/// io_uring POLL on c-ares' internal fds: the previous poll approach registered
/// its SQEs with a DNS_FD_MAGIC user_data that collided with the CLIENT flag
/// bit (1<<62) and was never dispatched back, so resolve() hung forever.
pub const CaresDns = struct {
    allocator: Allocator,
    channel: ?*anyopaque,
    result_ip: u32 = 0,
    result_ok: bool = false,
    /// Set by dnsCallback once the query completes (success or failure).
    query_done: bool = false,
    /// True while a fiber is suspended in resolve().
    waiting: bool = false,
    slot: Fiber.DnsYieldSlot = undefined,

    pub fn init(allocator: Allocator) !CaresDns {
        var channel: ?*anyopaque = null;
        const status = ares_init(&channel);
        if (status != ARES_SUCCESS) {
            logErr("c-ares init failed: {s}", .{std.mem.span(ares_strerror(status))});
            return error.DnsInitFailed;
        }
        return CaresDns{
            .allocator = allocator,
            .channel = channel,
        };
    }

    pub fn deinit(self: *CaresDns) void {
        ares_destroy(self.channel);
    }

    pub fn resolve(self: *CaresDns, hostname: []const u8) !u32 {
        const host_z = try self.allocator.alloc(u8, hostname.len + 1);
        defer self.allocator.free(host_z);
        @memcpy(host_z[0..hostname.len], hostname);
        host_z[hostname.len] = 0;

        self.result_ok = false;
        self.result_ip = 0;
        self.query_done = false;

        ares_gethostbyname(
            self.channel,
            @ptrCast(host_z.ptr),
            AF_INET,
            @ptrCast(&dnsCallback),
            self,
        );

        self.waiting = true;
        Fiber.dnsYield(&self.slot);
        // resumed by tick() once the c-ares callback has fired

        if (!self.result_ok) return error.DomainNotFound;
        return self.result_ip;
    }

    /// Pump c-ares and wake the fiber suspended in resolve() once the query
    /// completes. Must be called periodically from the event loop.
    pub fn tick(self: *CaresDns) void {
        var read_fds: fd_set = undefined;
        var write_fds: fd_set = undefined;
        @memset(@as([*]u8, @ptrCast(&read_fds))[0..@sizeOf(fd_set)], 0);
        @memset(@as([*]u8, @ptrCast(&write_fds))[0..@sizeOf(fd_set)], 0);

        const nfds = ares_fds(self.channel, &read_fds, &write_fds);

        // ares_process_fd(-1, -1) only drains timeouts; it never reads socket
        // data, so without polling the real fds the DNS response would never
        // be consumed and every query would end in ARES_ETIMEOUT. Poll the
        // c-ares sockets non-blockingly and hand ready fds to c-ares.
        var pfd: [FD_SET_CAPACITY]std.posix.pollfd = undefined;
        var npfd: usize = 0;
        var fd: i32 = 0;
        const fd_limit: i32 = @min(nfds, @as(i32, @intCast(FD_SET_CAPACITY)));
        while (fd < fd_limit and npfd < pfd.len) : (fd += 1) {
            const read_set = fdSetHas(&read_fds, fd);
            const write_set = fdSetHas(&write_fds, fd);
            if (!read_set and !write_set) continue;
            var events: i16 = 0;
            if (read_set) events |= std.posix.POLL.IN;
            if (write_set) events |= std.posix.POLL.OUT;
            pfd[npfd] = .{ .fd = fd, .events = events, .revents = 0 };
            npfd += 1;
        }
        if (npfd > 0) {
            _ = std.posix.poll(pfd[0..npfd], 0) catch {};
            for (pfd[0..npfd]) |p| {
                const rfd: i32 = if ((p.revents & std.posix.POLL.IN) != 0) p.fd else -1;
                const wfd: i32 = if ((p.revents & std.posix.POLL.OUT) != 0) p.fd else -1;
                if (rfd >= 0 or wfd >= 0) {
                    ares_process_fd(self.channel, rfd, wfd);
                }
            }
        }
        // Drain pending timeouts regardless of socket readiness.
        ares_process_fd(self.channel, -1, -1);

        if (self.waiting and self.query_done) {
            self.waiting = false;
            Fiber.dnsResume(&self.slot);
        }
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
    self.query_done = true;
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
