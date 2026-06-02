const std = @import("std");
const Allocator = std.mem.Allocator;
const RingBuffer = @import("spsc_ringbuffer.zig").RingBuffer;

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

    pub fn init(allocator: Allocator, log_cpu: ?u6) !*AsyncLogger {
        const self = try allocator.create(AsyncLogger);
        errdefer allocator.destroy(self);
        self.* = .{
            .ring = RingBuffer(LogEntry, RING_CAPACITY).init(),
            .allocator = allocator,
            .thread = null,
            .stop = false,
            .log_cpu = log_cpu,
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
            var mask: std.os.linux.cpu_set_t = [_]usize{0} ** (std.os.linux.CPU_SETSIZE / @sizeOf(usize));
            mask[0] = @as(usize, 1) << @as(u6, cpu);
            _ = std.os.linux.sched_setaffinity(0, &mask) catch {};
        }

        while (!@atomicLoad(bool, &self.stop, .acquire)) {
            var drained = false;
            while (self.ring.tryPop()) |entry| {
                drained = true;
                _ = std.os.linux.write(std.posix.STDERR_FILENO, entry.buf[0..entry.len].ptr, entry.len);
            }
            if (!drained) {
                std.time.sleep(10 * std.time.ns_per_ms);
            }
        }

        while (self.ring.tryPop()) |entry| {
            _ = std.os.linux.write(std.posix.STDERR_FILENO, entry.buf[0..entry.len].ptr, entry.len);
        }
    }

    pub fn deinit(self: *AsyncLogger) void {
        @atomicStore(bool, &self.stop, true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
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
    } else {
        // Fallback: logger not yet initialized or thread creation failed.
        // Direct stderr write — acceptable during early startup / late shutdown.
        std.debug.print(format ++ "\n", args);
    }
}

pub fn logErr(comptime format: []const u8, args: anytype) void {
    log("[ERROR] " ++ format, args);
}

pub fn logWarn(comptime format: []const u8, args: anytype) void {
    log("[WARN] " ++ format, args);
}
