const std = @import("std");
const Allocator = std.mem.Allocator;
const Fiber = @import("fiber.zig").Fiber;
const RingSharedClient = @import("../shared/tcp_stream.zig").RingSharedClient;

/// Pipe: 将 RingSharedClient 的推模型（on_data 回调）适配为拉模型（reader.read/writer.write）。
///
/// 协议库（pgz / myzql / nats）在 fiber 内调用 reader.read()，
/// 无数据时通过 fiber yield 挂起，RingSharedClient.on_data → feed() → fiber resume。
/// 全程跑在 IO 线程，零锁，零 worker 线程。
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

    /// RingSharedClient.on_data 回调入口。
    /// 超出 max_read 时拒绝数据、唤醒 fiber 报错。
    pub fn feed(self: *Pipe, data: []const u8) !void {
        if (self.read_buf.items.len + data.len > self.max_read) {
            // 修改原因：读缓冲溢出不能静默返回成功，否则上层会继续复用已经缺字节的连接。
            if (Fiber.isYielded()) {
                Fiber.pushResume(0, 0, &.{});
            }
            return error.BufferFull;
        }
        self.read_buf.appendSlice(self.allocator, data) catch |err| {
            // 修改原因：append OOM 时也要唤醒正在 reader.read() 里等待的 fiber，否则请求会一直挂起。
            if (Fiber.isYielded()) {
                Fiber.pushResume(0, 0, &.{});
            }
            return err;
        };
        if (Fiber.isYielded()) {
            Fiber.pushResume(0, 0, data);
        }
    }

    /// 冲刷写缓冲区到 RingSharedClient
    pub fn flushWrite(self: *Pipe) !void {
        if (self.write_buf.items.len == 0) return;
        try self.stream.write(self.write_buf.items);
        self.write_buf.clearRetainingCapacity();
    }

    /// 重置所有缓冲区（连接断开/重连时调用）
    pub fn reset(self: *Pipe) void {
        self.read_buf.clearRetainingCapacity();
        self.write_buf.clearRetainingCapacity();
        self.stream.resetForReuse();
    }

    pub const Reader = struct {
        pipe: *Pipe,

        pub fn read(self: Reader, dest: []u8) !usize {
            // 修改原因：零长度读取按 Reader 语义应立即返回 0，不能进入 yield 后在无数据时误报 Closed。
            if (dest.len == 0) return 0;
            if (self.pipe.read_buf.items.len > 0) {
                const n = @min(dest.len, self.pipe.read_buf.items.len);
                @memcpy(dest[0..n], self.pipe.read_buf.items[0..n]);
                try self.pipe.read_buf.replaceRange(self.pipe.allocator, 0, n, &.{});
                return n;
            }
            // 无数据 → yield fiber，等 RingSharedClient feed() 唤醒
            Fiber.currentYield();
            // 醒来后缓冲区必有数据（feed 已填充）
            if (self.pipe.read_buf.items.len == 0) return error.Closed;
            const n = @min(dest.len, self.pipe.read_buf.items.len);
            @memcpy(dest[0..n], self.pipe.read_buf.items[0..n]);
            try self.pipe.read_buf.replaceRange(self.pipe.allocator, 0, n, &.{});
            return n;
        }

        /// 读满 dest，否则 yield 等待
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
