pub const TcpHandler = *const fn (conn_id: u64, data: []u8) void;
