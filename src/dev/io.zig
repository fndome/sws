const builtin = @import("builtin");

const impl = if (builtin.os.tag == .windows) @import("io_win.zig") else @import("io_posix.zig");

pub const Socket = impl.Socket;
pub const Err = impl.Err;

pub const tcpSocket = impl.tcpSocket;
pub const setReuseAddr = impl.setReuseAddr;
pub const bindSocket = impl.bindSocket;
pub const listenSocket = impl.listenSocket;
pub const acceptSocket = impl.acceptSocket;
pub const closeSocket = impl.closeSocket;
pub const recv = impl.recv;
pub const send = impl.send;
