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
/// Sentinel for "no provided read buffer is currently held" (0xFFFF = 65535 >
/// BUFFER_POOL_SIZE, so BufferPool.markReplenish ignores it). Distinguishes
/// "no buffer" from a read that landed on buffer id 0, which is a valid
/// provided buffer (provideAllReads starts bids at 0).
pub const NO_READ_BUFFER_BID: u16 = 0xFFFF;
/// Slot-workspace overflow sentinel ("SWAS" little-endian). Verified intact on
/// slot reuse to catch a previous connection overrunning the workspace.
pub const WORKSPACE_SENTINEL: u32 = 0x53574153;
/// Task-context type tags ("HT"/"WS" + version 1) asserted on recycle to catch
/// a task being recycled through the wrong context pool.
pub const HTTP_TASK_TAG: u32 = 0x48540001;
pub const WS_TASK_TAG: u32 = 0x57530001;
/// "No fixed-file registered" sentinel (valid indices are 0..MAX_FIXED_FILES-1).
pub const NO_FIXED_FILE: u16 = 0xFFFF;
/// "No pool slot / invalid live-list position" sentinel.
pub const NO_POOL_SLOT: u32 = 0xFFFFFFFF;
pub const NO_LIVE_POS: u32 = 0xFFFFFFFF;
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

