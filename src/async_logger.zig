const std = @import("std");
const Allocator = std.mem.Allocator;
const RingBuffer = @import("spsc_ringbuffer.zig").RingBuffer;
const linux = std.os.linux;

const LOG_ENTRY_SIZE = 256;
const RING_CAPACITY = 4096;

const LogEntry = struct {
    buf: [LOG_ENTRY_SIZE]u8,
    len: u16,
};

var g_logger: ?*AsyncLogger = null;

pub const AsyncLogger = struct {
    ring: RingBuffer(LogEntry, RING_CAPACITY),
    allocator: Allocator,
    thread: ?std.Thread,
    stop: bool,
    log_cpu: ?u6,
    eventfd: i32,

    pub fn init(allocator: Allocator, log_cpu: ?u6) !*AsyncLogger {
        const self = try allocator.create(AsyncLogger);
        errdefer allocator.destroy(self);
        const efd_raw = linux.eventfd(0, 0);
        if (@as(isize, @bitCast(efd_raw)) < 0) return error.EventFdFailed;
        self.* = .{
            .ring = RingBuffer(LogEntry, RING_CAPACITY).init(),
            .allocator = allocator,
            .thread = null,
            .stop = false,
            .log_cpu = log_cpu,
            .eventfd = @intCast(efd_raw),
        };
        self.startThread();
        @atomicStore(?*AsyncLogger, &g_logger, self, .release);
        return self;
    }

    fn startThread(self: *AsyncLogger) void {
        const t = std.Thread.spawn(.{}, writerLoop, .{self}) catch {
            @atomicStore(?*AsyncLogger, &g_logger, null, .release);
            return;
        };
        self.thread = t;
    }

    fn writerLoop(self: *AsyncLogger) void {
        if (self.log_cpu) |cpu| {
            var mask: linux.cpu_set_t = [_]usize{0} ** (linux.CPU_SETSIZE / @sizeOf(usize));
            mask[0] = @as(usize, 1) << @as(u6, cpu);
            _ = linux.sched_setaffinity(0, &mask) catch {};
        }

        var pfds: [1]linux.pollfd = undefined;
        pfds[0] = .{ .fd = self.eventfd, .events = linux.POLL.IN, .revents = 0 };

        while (!@atomicLoad(bool, &self.stop, .acquire)) {
            while (self.ring.tryPop()) |entry| {
                _ = linux.write(std.posix.STDERR_FILENO, entry.buf[0..entry.len].ptr, entry.len);
            }
            _ = linux.poll(&pfds, pfds.len, -1);
            if (pfds[0].revents & linux.POLL.IN != 0) {
                var val: u64 = 0;
                _ = linux.read(self.eventfd, @as([*]u8, @ptrCast(&val)), @sizeOf(u64));
            }
        }

        while (self.ring.tryPop()) |entry| {
            _ = linux.write(std.posix.STDERR_FILENO, entry.buf[0..entry.len].ptr, entry.len);
        }
    }

    pub fn deinit(self: *AsyncLogger) void {
        @atomicStore(bool, &self.stop, true, .release);
        const val: u64 = 1;
        _ = linux.write(self.eventfd, @as([*]const u8, @ptrCast(&val)), @sizeOf(u64));
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        _ = linux.close(self.eventfd);
        @atomicStore(?*AsyncLogger, &g_logger, null, .release);
        self.allocator.destroy(self);
    }
};

pub fn log(comptime format: []const u8, args: anytype) void {
    if (@atomicLoad(?*AsyncLogger, &g_logger, .acquire)) |logger| {
        var entry: LogEntry = undefined;
        const result = std.fmt.bufPrint(&entry.buf, format ++ "\n", args) catch return;
        entry.len = @as(u16, @intCast(result.len));
        _ = logger.ring.tryPush(entry);
        const val: u64 = 1;
        _ = linux.write(logger.eventfd, @as([*]const u8, @ptrCast(&val)), @sizeOf(u64));
    } else {
        std.debug.print(format ++ "\n", args);
    }
}

pub fn logErr(comptime format: []const u8, args: anytype) void {
    log("[ERROR] " ++ format, args);
}

pub fn logWarn(comptime format: []const u8, args: anytype) void {
    log("[WARN] " ++ format, args);
}
