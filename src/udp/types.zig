pub const SenderAddr = struct {
    ip: u32,
    port: u16,
};

/// UDP 消息处理函数，在 IO 线程中同步调用。
///
/// sender: 发送方地址
/// data:   收到的数据，指向 UdpBufferPool 预分配 slab buffer。
///         handler 返回后 buffer 立即回收并用于下次 recvmsg。
///         如需异步处理（Next.go / Next.submit），必须在 handler 内
///         将 data 拷贝到自有内存，不得持有该指针跨越返回边界。
/// ctx:    用户上下文（AsyncServer 指针）
pub const UdpHandler = *const fn (sender: SenderAddr, data: []u8, ctx: *anyopaque) void;
