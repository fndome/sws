const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const RingShared = @import("../shared/ring_shared.zig").RingShared;
const UdpHandler = @import("types.zig").UdpHandler;
const SenderAddr = @import("types.zig").SenderAddr;
const helpers = @import("../http/http_helpers.zig");
const logErr = helpers.logErr;

const MAX_UDP_PAYLOAD: usize = 65536;

fn udpDispatch(ptr: *anyopaque, user_data: u64, res: i32) void {
    _ = user_data;
    const self: *UdpServer = @ptrCast(@alignCast(ptr));
    self.onRecvCqe(res);
}

pub const UdpServer = struct {
    allocator: Allocator,
    rs: RingShared,
    udp_fd: i32,
    udp_ud: u64,
    handler: ?UdpHandler = null,
    ctx: *anyopaque = undefined,
    recv_buf: [MAX_UDP_PAYLOAD]u8 align(8) = [_]u8{0} ** MAX_UDP_PAYLOAD,
    recv_addr: linux.sockaddr.in = undefined,
    recv_iov: std.posix.iovec = undefined,
    recv_hdr: linux.msghdr = undefined,
    recv_outstanding: bool = false,

    pub fn init(allocator: Allocator, rs: RingShared, bind_addr: []const u8) !UdpServer {
        const colon = std.mem.indexOfScalar(u8, bind_addr, ':') orelse return error.InvalidListenAddress;
        const ip_str = bind_addr[0..colon];
        const port_str = bind_addr[colon + 1 ..];
        const port = try std.fmt.parseInt(u16, port_str, 10);
        const ip_addr = try helpers.parseIpv4(ip_str);

        const raw_fd = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
        const fd: i32 = @intCast(raw_fd);
        if (fd < 0) return error.UdpSocketFailed;
        errdefer _ = linux.close(fd);

        var reuse: i32 = 1;
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @as([*]const u8, @ptrCast(&reuse)), @sizeOf(i32));

        var addr_in = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = @byteSwap(port),
            .addr = ip_addr,
            .zero = [_]u8{0} ** 8,
        };
        const len: u32 = @intCast(@sizeOf(linux.sockaddr.in));
        if (linux.bind(fd, @ptrCast(&addr_in), len) != 0) {
            return error.BindFailed;
        }

        return UdpServer{
            .allocator = allocator,
            .rs = rs,
            .udp_fd = fd,
            .udp_ud = 0,
        };
    }

    pub fn register(self: *UdpServer) !void {
        self.udp_ud = try self.rs.alloc(@ptrCast(@constCast(self)), &udpDispatch);
        self.submitRecv();
    }

    pub fn deinit(self: *UdpServer) void {
        self.rs.remove(self.udp_ud);
        if (self.udp_fd >= 0) {
            _ = linux.close(self.udp_fd);
            self.udp_fd = -1;
        }
    }

    pub fn send(self: *UdpServer, addr: SenderAddr, data: []const u8) void {
        var sock_addr = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = @byteSwap(addr.port),
            .addr = addr.ip,
            .zero = [_]u8{0} ** 8,
        };
        const rc = linux.sendto(self.udp_fd, data.ptr, data.len, 0, @ptrCast(&sock_addr), @sizeOf(linux.sockaddr.in));
        if (rc < 0) {
            logErr("udp sendto failed for {d}.{d}.{d}.{d}:{d}", .{
                (addr.ip >> 24) & 0xFF,
                (addr.ip >> 16) & 0xFF,
                (addr.ip >> 8) & 0xFF,
                addr.ip & 0xFF,
                addr.port,
            });
        }
    }

    pub fn hasHandler(self: *const UdpServer) bool {
        return self.handler != null;
    }

    fn submitRecv(self: *UdpServer) void {
        if (self.recv_outstanding) return;

        self.recv_iov = .{
            .base = @as(?*anyopaque, &self.recv_buf),
            .len = self.recv_buf.len,
        };
        self.recv_hdr = .{
            .name = @ptrCast(&self.recv_addr),
            .namelen = @sizeOf(linux.sockaddr.in),
            .iov = @ptrCast(&self.recv_iov),
            .iovlen = 1,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };

        const sqe = self.rs.ring.nop(self.udp_ud) catch return;
        sqe.opcode = @enumFromInt(10); // IORING_OP_RECVMSG
        sqe.fd = self.udp_fd;
        sqe.addr = @intFromPtr(&self.recv_hdr);
        sqe.len = 1;
        sqe.off = 0;
        sqe.flags = 0;
        self.recv_outstanding = true;
        _ = self.rs.ring.submit() catch {};
    }

    fn onRecvCqe(self: *UdpServer, res: i32) void {
        self.recv_outstanding = false;
        if (res <= 0) {
            self.submitRecv();
            return;
        }
        const n: usize = @intCast(res);
        if (self.handler) |h| {
            const sender = SenderAddr{
                .ip = self.recv_addr.addr,
                .port = @byteSwap(self.recv_addr.port),
            };
            h(sender, self.recv_buf[0..n], self.ctx);
        }
        self.submitRecv();
    }
};

test "UdpServer init bind and deinit" {
    const allocator = std.testing.allocator;
    const rs = undefined;
    var server = try UdpServer.init(allocator, rs, "0.0.0.0:0");
    defer server.deinit();
    try std.testing.expect(server.udp_fd >= 0);
    try std.testing.expect(!server.hasHandler());

    server.handler = struct {
        fn h(_: SenderAddr, _: []u8, _: *anyopaque) void {}
    }.h;
    try std.testing.expect(server.hasHandler());
}
