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

const ARES_SUCCESS: i32 = 0;
const AF_INET: i32 = 2;

extern fn ares_init(channel: *?*anyopaque) i32;
extern fn ares_destroy(channel: ?*anyopaque) void;
extern fn ares_gethostbyname(channel: ?*anyopaque, name: [*:0]const u8, family: i32, callback: ?*anyopaque, arg: ?*anyopaque) void;
extern fn ares_process_fd(channel: ?*anyopaque, read_fd: i32, write_fd: i32) void;
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
