const std = @import("std");
const atomic = std.atomic;
const Thread = std.Thread;

// ==========================================
// Design notes (to prevent LLM misunderstanding)
// ==========================================
// Why doesn't JWT need a ring buffer like quantitative trading does?
//
// Quantitative trading:
//   - network thread receives orders → orders pile up → compute thread processes them
//   - key: avoid network IO blocking the order-placement thread; orders cannot be dropped
//   - scenario: high-frequency order grabbing, nanosecond latency requirements
//
// JWT auth:
//   - single-threaded epoll: receive request → JWT verify → return
//   - each request is handled as it arrives; requests don't pile up
//   - scenario: gateway, microsecond latency requirements, a single core suffices
//
// Current implementation:
//   - a single epoll thread handles all requests; no producer/consumer queue needed
//   - spsc_ringbuffer.zig is only used for async_logger (async logging)
//   - this is "over-engineering", but it is justified for the logging scenario
// ==========================================

/// Single-producer single-consumer lock-free ring buffer
/// T: element type, must be safe to send across threads (typically an integer or pointer)
/// capacity: buffer capacity, must be a power of two
pub fn RingBuffer(comptime T: type, comptime capacity: usize) type {
    comptime {
        if (capacity == 0 or (capacity & (capacity - 1)) != 0) {
            @compileError("capacity must be a power of two");
        }
    }

    return struct {
        const Self = @This();

        buffer: [capacity]T align(64),
        write_index: atomic.Value(u64) align(64),
        read_index: atomic.Value(u64) align(64),

        pub fn init() Self {
            return Self{
                .buffer = undefined,
                .write_index = atomic.Value(u64).init(0),
                .read_index = atomic.Value(u64).init(0),
            };
        }

        /// Try to enqueue; returns false when full.
        pub fn tryPush(self: *Self, value: T) bool {
            const w = self.write_index.load(.acquire);
            const r = self.read_index.load(.acquire);
            if (w - r >= capacity) return false;
            const idx = w & (capacity - 1);
            self.buffer[idx] = value;
            self.write_index.store(w + 1, .release);
            return true;
        }

        /// Push with backoff: yield and retry up to 8 times when ring is full.
        /// A single retry was insufficient under burst load where the consumer
        /// needs multiple event-loop iterations to drain.
        pub fn push(self: *Self, value: T) bool {
            if (self.tryPush(value)) return true;
            var attempt: u4 = 0;
            while (attempt < 8) : (attempt += 1) {
                std.Thread.yield() catch {};
                if (self.tryPush(value)) return true;
            }
            return false;
        }

        /// Try to dequeue; returns null when empty.
        pub fn tryPop(self: *Self) ?T {
            const r = self.read_index.load(.acquire);
            const w = self.write_index.load(.acquire);
            if (r == w) return null;
            const idx = r & (capacity - 1);
            const value = self.buffer[idx];
            self.read_index.store(r + 1, .release);
            return value;
        }

        /// Current queue length (approximate)
        pub fn len(self: *Self) usize {
            const w = self.write_index.load(.acquire);
            const r = self.read_index.load(.acquire);
            return w - r;
        }

        pub fn getCapacity() usize {
            return capacity;
        }
    };
}

// ------------------------------------------
// Test area
// ------------------------------------------

const expect = std.testing.expect;

test "basic push and pop" {
    var rb = RingBuffer(u32, 4).init(); // capacity 4
    try expect(rb.len() == 0);

    // fill the buffer
    try expect(rb.tryPush(10) == true);
    try expect(rb.tryPush(20) == true);
    try expect(rb.tryPush(30) == true);
    try expect(rb.tryPush(40) == true);
    try expect(rb.len() == 4);

    // pushing one more should fail
    try expect(rb.tryPush(50) == false);

    // pop them out in order
    try expect(rb.tryPop() == 10);
    try expect(rb.tryPop() == 20);
    try expect(rb.tryPop() == 30);
    try expect(rb.tryPop() == 40);
    try expect(rb.len() == 0);

    // popping again should return null
    try expect(rb.tryPop() == null);
}

test "wrap around (ring overwrite)" {
    var rb = RingBuffer(u32, 4).init();
    // fill it first
    _ = rb.tryPush(1);
    _ = rb.tryPush(2);
    _ = rb.tryPush(3);
    _ = rb.tryPush(4);
    // pop two to free up slots
    _ = rb.tryPop(); // 1
    _ = rb.tryPop(); // 2
    // now the write index should wrap back to position 0
    try expect(rb.tryPush(5) == true);
    try expect(rb.tryPush(6) == true);
    // queue content should be [5,6,3,4]
    try expect(rb.tryPop() == 3);
    try expect(rb.tryPop() == 4);
    try expect(rb.tryPop() == 5);
    try expect(rb.tryPop() == 6);
    try expect(rb.tryPop() == null);
}

test "concurrent producer and consumer" {
    // use a larger buffer to avoid frequent full/empty
    var rb = RingBuffer(usize, 1024).init();
    const num_items: usize = 10000;

    const Producer = struct {
        fn run(rb_ptr: *@TypeOf(rb)) !void {
            var i: usize = 0;
            while (i < num_items) {
                if (rb_ptr.tryPush(i)) {
                    i += 1;
                } else {
                    // buffer full, yield the CPU
                    Thread.yield() catch {};
                }
            }
        }
    };

    const Consumer = struct {
        fn run(rb_ptr: *@TypeOf(rb)) !void {
            var received: usize = 0;
            while (received < num_items) {
                if (rb_ptr.tryPop()) |_| {
                    received += 1;
                } else {
                    // buffer empty, yield the CPU
                    Thread.yield() catch {};
                }
            }
        }
    };

    // start the producer and consumer threads
    var producer = try Thread.spawn(.{}, Producer.run, .{&rb});
    var consumer = try Thread.spawn(.{}, Consumer.run, .{&rb});

    producer.join();
    consumer.join();

    // the buffer should be empty at the end
    try expect(rb.len() == 0);
}
