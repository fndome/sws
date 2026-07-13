const std = @import("std");

pub const Socket = std.c.fd_t;

pub const Err = error{
    SocketFailed,
    BindFailed,
    ListenFailed,
    WriteFailed,
    ReadFailed,
};

pub fn tcpSocket() !Socket {
    const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM | std.c.SOCK.CLOEXEC, 0);
    if (fd < 0) return error.SocketFailed;
    return @intCast(fd);
}

pub fn setReuseAddr(fd: Socket) void {
    const one: c_int = 1;
    _ = std.c.setsockopt(fd, std.c.SOL.SOCKET, std.c.SO.REUSEADDR, &one, @sizeOf(c_int));
}

pub fn bindSocket(fd: Socket, ip: [4]u8, port: u16) !void {
    var addr: extern struct { family: u16, port: u16, addr: u32, zero: [8]u8 } = .{
        .family = std.c.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = (@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) | (@as(u32, ip[2]) << 8) | @as(u32, ip[3]),
        .zero = [_]u8{0} ** 8,
    };
    if (std.c.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))) != 0) return error.BindFailed;
}

pub fn listenSocket(fd: Socket) !void {
    if (std.c.listen(fd, 128) != 0) return error.ListenFailed;
}

pub fn acceptSocket(fd: Socket) !Socket {
    const raw = std.c.accept(fd, null, null);
    if (raw < 0) return error.SocketFailed;
    return @intCast(raw);
}

pub fn closeSocket(fd: Socket) void {
    _ = std.c.close(fd);
}

pub fn recv(fd: Socket, buf: []u8) !usize {
    const n = std.c.read(fd, @ptrCast(buf.ptr), buf.len);
    if (n < 0) return error.ReadFailed;
    return @intCast(n);
}

pub fn send(fd: Socket, data: []const u8) !usize {
    const n = std.c.write(fd, @ptrCast(data.ptr), data.len);
    if (n < 0) return error.WriteFailed;
    return @intCast(n);
}
