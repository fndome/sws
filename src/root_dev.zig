const std = @import("std");

pub const AsyncServer = @import("dev/compat.zig").CompatServer;
pub const DevServer = @import("dev/server.zig").DevServer;

pub const Context = @import("http/context.zig").Context;
pub const RouteParam = @import("http/context.zig").RouteParam;
pub const Handler = @import("http/types.zig").Handler;
pub const Middleware = @import("http/types.zig").Middleware;

pub const WsServer = @import("ws/server.zig").WsServer;
pub const WsHandler = @import("ws/server.zig").WsHandler;
pub const Frame = @import("ws/types.zig").Frame;
pub const Opcode = @import("ws/types.zig").Opcode;

test {
    // Pure modules with host-runnable tests (no io_uring/linux dependency).
    _ = @import("client/http_parse.zig");
    _ = @import("http/route_match.zig");
    _ = @import("http/context.zig");
    _ = @import("http/write_progress.zig");
    _ = @import("shared/tcp_stream_helpers.zig");
    _ = @import("dns/packet.zig");
    _ = @import("dns/cache.zig");
    _ = @import("spsc_ringbuffer.zig");
    _ = @import("ws/frame.zig");
    _ = @import("ws/upgrade.zig");
    _ = @import("ws/server.zig");
    _ = @import("udp/buffer.zig");
}
