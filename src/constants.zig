pub const MAX_HEADER_BUFFER_SIZE = 8192;
pub const MAX_RESPONSE_BUFFER_SIZE = 4096;
pub const MAX_CQES_BATCH = 128;
pub const RING_ENTRIES = 4096;
pub const TASK_QUEUE_SIZE = 1024;
pub const RESPONSE_QUEUE_SIZE = 1024;
/// io_uring provided buffer block size. 4KB is the sweet spot for 1M connections.
pub const BUFFER_SIZE = 4096;
/// Number of BUFFER_SIZE blocks in the slab for io_uring provided read buffers.
pub const BUFFER_POOL_SIZE = 16384;
/// All blocks are for io_uring provided read buffers. Write buffers come from tiered pool.
pub const READ_BUF_COUNT = BUFFER_POOL_SIZE;
pub const READ_BUF_GROUP_ID = 0;
pub const ACCEPT_USER_DATA: u64 = (1 << 63);
/// Raw-TCP accept marker. Must NOT share a bit with CLIENT_USER_DATA_FLAG
/// (1<<62) or ACCEPT_USER_DATA (1<<63), otherwise a TCP-accept CQE could be
/// misrouted to the client registry. Bit 61 is free: CLIENT_WRITE_USER_DATA_FLAG
/// (1<<61) is only ever set together with bit 62, so a lone bit-61 value is
/// unambiguous.
pub const TCP_ACCEPT_USER_DATA: u64 = 1 << 61;
pub const MAX_FIXED_FILES = 65535; // 0..65534 valid, 0xFFFF sentinel reserved
pub const MAX_PATH_LENGTH = 2048;
pub const IDLE_TIMEOUT_MS = 30000;
pub const WRITE_TIMEOUT_MS = 5000;
pub const MAX_CONNECTIONS = 1_048_576;

pub const USER_TASK_BATCH = 64;

pub const UDP_RECV_BUF_SIZE: usize = 65536;
pub const UDP_RECV_POOL_SIZE: u16 = 256;

/// Size classes for tiered write buffer pool, like greatws bytespool.
/// 512B for status codes, 1KB-4KB for API responses, 8KB-64KB for larger payloads.
pub const TIER_SIZES = [_]usize{ 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
pub const TIER_COUNT = TIER_SIZES.len;

