const std = @import("std");

pub const Socket = usize; // SOCKET = UINT_PTR

pub const Err = error{
    SocketFailed,
    BindFailed,
    ListenFailed,
    WriteFailed,
    ReadFailed,
};

const w = struct {
    const ws2 = @cImport({
        @cInclude("winsock2.h");
        @cInclude("ws2tcpip.h");
    });

    var init: bool = false;

    fn startup() void {
        if (init) return;
        init = true;
        var data: ws2.WSADATA = undefined;
        _ = ws2.WSAStartup(0x0202, &data);
    }
};

pub fn tcpSocket() !Socket {
    w.startup();
    const fd = w.ws2.socket(w.ws2.AF_INET, w.ws2.SOCK_STREAM, 0);
    if (fd == w.ws2.INVALID_SOCKET) return error.SocketFailed;
    return @intCast(fd);
}

pub fn setReuseAddr(fd: Socket) void {
    const one: c_int = 1;
    _ = w.ws2.setsockopt(@intCast(fd), w.ws2.SOL_SOCKET, w.ws2.SO_REUSEADDR, @ptrCast(&one), @sizeOf(c_int));
}

pub fn bindSocket(fd: Socket, ip: [4]u8, port: u16) !void {
    var addr = std.mem.zeroes(w.ws2.sockaddr_in);
    addr.sin_family = w.ws2.AF_INET;
    addr.sin_port = std.mem.nativeToBig(u16, port);
    addr.sin_addr.S_un.S_addr = (@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) | (@as(u32, ip[2]) << 8) | @as(u32, ip[3]);
    if (w.ws2.bind(@intCast(fd), @ptrCast(&addr), @sizeOf(w.ws2.sockaddr_in)) != 0) return error.BindFailed;
}

pub fn listenSocket(fd: Socket) !void {
    if (w.ws2.listen(@intCast(fd), 128) != 0) return error.ListenFailed;
}

pub fn acceptSocket(fd: Socket) !Socket {
    const raw = w.ws2.accept(@intCast(fd), null, null);
    if (raw == w.ws2.INVALID_SOCKET) return error.SocketFailed;
    return @intCast(raw);
}

pub fn closeSocket(fd: Socket) void {
    _ = w.ws2.closesocket(@intCast(fd));
}

pub fn recv(fd: Socket, buf: []u8) !usize {
    const n = w.ws2.recv(@intCast(fd), @ptrCast(buf.ptr), @intCast(buf.len), 0);
    if (n == w.ws2.SOCKET_ERROR) return error.ReadFailed;
    if (n == 0) return 0;
    return @intCast(n);
}

pub fn send(fd: Socket, data: []const u8) !usize {
    const n = w.ws2.send(@intCast(fd), @ptrCast(@constCast(data.ptr)), @intCast(data.len), 0);
    if (n == w.ws2.SOCKET_ERROR) return error.WriteFailed;
    return @intCast(n);
}
