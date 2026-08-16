const std = @import("std");
const Allocator = std.mem.Allocator;
const Fiber = @import("fiber.zig").Fiber;
const RingSharedClient = @import("../shared/tcp_stream.zig").RingSharedClient;

/// Pipe: adapts RingSharedClient's push model (on_data callback) into a pull model (reader.read/writer.write).
///
/// Protocol libraries (pgz / myzql / nats) call reader.read() inside a fiber;
/// with no data available they suspend via fiber yield, then RingSharedClient.on_data → feed() → fiber resume.
/// Runs entirely on the IO thread: zero locks, zero worker threads.
pub const Pipe = struct {
    allocator: Allocator,
    stream: *RingSharedClient,

    read_buf: std.ArrayList(u8),
    write_buf: std.ArrayList(u8),
    max_read: usize,

    const DEFAULT_MAX_READ: usize = 1024 * 1024; // 1MB

    pub fn init(allocator: Allocator, stream: *RingSharedClient) !Pipe {
        return Pipe{
            .allocator = allocator,
            .stream = stream,
            .read_buf = std.ArrayList(u8).empty,
            .write_buf = std.ArrayList(u8).empty,
            .max_read = DEFAULT_MAX_READ,
        };
    }

    pub fn initWithLimit(allocator: Allocator, stream: *RingSharedClient, max_read: usize) !Pipe {
        var p = try Pipe.init(allocator, stream);
        p.max_read = max_read;
        return p;
    }

    pub fn deinit(self: *Pipe) void {
        self.read_buf.deinit(self.allocator);
        self.write_buf.deinit(self.allocator);
    }

    pub fn reader(self: *Pipe) Reader {
        return Reader{ .pipe = self };
    }

    pub fn writer(self: *Pipe) Writer {
        return Writer{ .pipe = self };
    }

    /// Entry point for the RingSharedClient.on_data callback.
    /// Rejects data and wakes the fiber with an error when max_read is exceeded.
    pub fn feed(self: *Pipe, data: []const u8) !void {
        if (self.read_buf.items.len + data.len > self.max_read) {
            // Defensive: a read-buffer overflow must not silently return success, otherwise the upper layer keeps reusing a connection that is already missing bytes.
            if (Fiber.isYielded()) {
                Fiber.pushResume(0, 0, &.{});
            }
            return error.BufferFull;
        }
        self.read_buf.appendSlice(self.allocator, data) catch |err| {
            // Defensive: on append OOM, the fiber waiting in reader.read() must still be woken, otherwise the request hangs forever.
            if (Fiber.isYielded()) {
                Fiber.pushResume(0, 0, &.{});
            }
            return err;
        };
        if (Fiber.isYielded()) {
            Fiber.pushResume(0, 0, data);
        }
    }

    /// Flush the write buffer to RingSharedClient
    pub fn flushWrite(self: *Pipe) !void {
        if (self.write_buf.items.len == 0) return;
        try self.stream.write(self.write_buf.items);
        self.write_buf.clearRetainingCapacity();
    }

    /// Reset all buffers (called on disconnect/reconnect)
    pub fn reset(self: *Pipe) void {
        self.read_buf.clearRetainingCapacity();
        self.write_buf.clearRetainingCapacity();
        self.stream.resetForReuse();
    }

    pub const Reader = struct {
        pipe: *Pipe,

        pub fn read(self: Reader, dest: []u8) !usize {
            // Defensive: a zero-length read should return 0 immediately per Reader semantics; it must not yield and then misreport Closed when no data arrives.
            if (dest.len == 0) return 0;
            if (self.pipe.read_buf.items.len > 0) {
                const n = @min(dest.len, self.pipe.read_buf.items.len);
                @memcpy(dest[0..n], self.pipe.read_buf.items[0..n]);
                try self.pipe.read_buf.replaceRange(self.pipe.allocator, 0, n, &.{});
                return n;
            }
            // no data → yield the fiber, wait for RingSharedClient feed() to wake it
            Fiber.currentYield();
            // on wake the buffer must have data (feed already filled it)
            if (self.pipe.read_buf.items.len == 0) return error.Closed;
            const n = @min(dest.len, self.pipe.read_buf.items.len);
            @memcpy(dest[0..n], self.pipe.read_buf.items[0..n]);
            try self.pipe.read_buf.replaceRange(self.pipe.allocator, 0, n, &.{});
            return n;
        }

        /// Fill dest completely, otherwise yield and wait
        pub fn readAll(self: Reader, dest: []u8) !void {
            var offset: usize = 0;
            while (offset < dest.len) {
                const n = try self.read(dest[offset..]);
                if (n == 0) return error.Closed;
                offset += n;
            }
        }
    };

    pub const Writer = struct {
        pipe: *Pipe,

        pub fn write(self: Writer, data: []const u8) !usize {
            try self.pipe.write_buf.appendSlice(self.pipe.allocator, data);
            return data.len;
        }

        pub fn writeAll(self: Writer, data: []const u8) !void {
            _ = try self.write(data);
        }

        pub fn flush(self: Writer) !void {
            try self.pipe.flushWrite();
        }
    };
};

test "Pipe.Reader.read returns zero for empty destination" {
    var pipe = Pipe{
        .allocator = std.testing.allocator,
        .stream = undefined,
        .read_buf = std.ArrayList(u8).empty,
        .write_buf = std.ArrayList(u8).empty,
        .max_read = 1,
    };
    defer pipe.deinit();

    var empty: [0]u8 = .{};
    try std.testing.expectEqual(@as(usize, 0), try pipe.reader().read(empty[0..]));
}

test "Pipe.feed reports max_read overflow" {
    var pipe = Pipe{
        .allocator = std.testing.allocator,
        .stream = undefined,
        .read_buf = std.ArrayList(u8).empty,
        .write_buf = std.ArrayList(u8).empty,
        .max_read = 3,
    };
    defer pipe.deinit();

    try pipe.feed("abc");
    try std.testing.expectError(error.BufferFull, pipe.feed("d"));
    try std.testing.expectEqualStrings("abc", pipe.read_buf.items);
}

test "Pipe.feed reports append allocation failure" {
    var backing: [1]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var pipe = Pipe{
        .allocator = fba.allocator(),
        .stream = undefined,
        .read_buf = std.ArrayList(u8).empty,
        .write_buf = std.ArrayList(u8).empty,
        .max_read = 8,
    };
    defer pipe.deinit();

    try std.testing.expectError(error.OutOfMemory, pipe.feed("overflow"));
}
