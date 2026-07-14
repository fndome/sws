pub const SenderAddr = struct {
    ip: u32,
    port: u16,
};

/// UDP 消息处理函数，在 IO 线程中调用。
///
/// sender: 发送方地址
/// data:   收到的数据。
///         - 默认模式 (server.udp): 框架已拷贝到 heap，handler 可安全传递
///           给 Next.go / Next.submit，返回后框架自动 free。
///         - 零拷贝模式 (server.udp4Sync): data 指向 pool slab buffer，
///           返回后立即回收。handler 必须同步快速返回，不得持有 data 指针。
/// ctx:    用户上下文（AsyncServer 指针）
pub const UdpHandler = *const fn (sender: SenderAddr, data: []u8, ctx: *anyopaque) void;
