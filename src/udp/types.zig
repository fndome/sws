pub const SenderAddr = struct {
    ip: u32,
    port: u16,
};

/// UDP message handler, invoked on the IO thread.
///
/// sender: remote address
/// data:   received payload.
///         - Default mode (server.udp): already heap-copied by the framework.
///           Safe to pass to Next.go / Next.submit. Freed on return.
///         - Zero-copy mode (server.udp4Sync): points into pool slab buffer.
///           Returned to the pool on handler return. Must complete synchronously;
///           must not retain the pointer across return.
/// ctx:    user context (AsyncServer pointer)
pub const UdpHandler = *const fn (sender: SenderAddr, data: []u8, ctx: *anyopaque) void;
