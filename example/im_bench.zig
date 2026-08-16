// im_bench.zig — sws AsyncServer HTTP throughput benchmark
//
// Target: 1 core, 600MB, 1M concurrent connections (C31K).
//
// ── Kernel tuning (required before 1M connection test) ──────────────
//
//   # File descriptor limits
//   sysctl -w fs.nr_open=2097152
//   sysctl -w fs.file-max=2097152
//   ulimit -n 1048576
//
//   # If systemd, also set in /etc/systemd/system.conf:
//   #   DefaultLimitNOFILE=1048576:1048576
//
//   # Network stack
//   sysctl -w net.core.somaxconn=65535
//   sysctl -w net.ipv4.ip_local_port_range="1024 65535"
//   sysctl -w net.ipv4.tcp_tw_reuse=1
//
//   # CPU governor (prevent frequency scaling jitter)
//   echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
//
//   # io_uring (kernel 5.1+ required)
//   # IORING_SETUP_SINGLE_ISSUER + IORING_SETUP_COOP_TASKRUN
//   # (removed by default; SINGLE_ISSUER breaks cross-thread run)
//
// ── Known scale blockers (fixed in third audit round) ────────────────
//
//   1. flushReplenish crash: ring full → try → server exit
//      Fix: catch error, retry next iteration
//   2. TTL scanner killed active connections after 30s
//      Fix: refresh slot.line2.last_active_ms on every request
//   3. Pool-full accept spin: tight accept-fail-close loop
//      Fix: stall accept, resume from closeConn when slot freed
//
// ── Bench run ────────────────────────────────────────────────────────
//
//   # Small smoke test (50 conns, 5k reqs, keep-alive)
//   SWS_BENCH_PORT=19090 zig build run-im-bench
//
//   # Scale test
//   # Monitor: htop, ss -s, free -h, cat /proc/sys/fs/file-nr
//
//   SWS_BENCH_CONNS=500 SWS_BENCH_REQS_PER_CONN=1000 SWS_BENCH_PORT=19090 ./zig-out/bin/im-bench
const std = @import("std");
const linux = std.os.linux;
const sws = @import("sws");
const AsyncServer = sws.AsyncServer;

const DEFAULT_PORT = 19090;
const DEFAULT_CONNS = 50;
const DEFAULT_REQS_PER_CONN = 100;
const DRAIN_IDLE_ROUNDS = 20;
const DRAIN_POLL_TIMEOUT_MS = 10;
const RESPONSE_MARKER = "{\"ok\":true}";

fn benchHandler(allocator: std.mem.Allocator, ctx: *sws.Context) anyerror!void {
    _ = allocator;
    try ctx.rawJson(200, "{\"ok\":true}");
}

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

fn countResponses(data: []const u8) usize {
    var count: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOf(u8, data[pos..], RESPONSE_MARKER)) |idx| {
        count += 1;
        pos += idx + RESPONSE_MARKER.len;
    }
    return count;
}

fn readPortEnv(default_port: u16) u16 {
    const raw = std.c.getenv("SWS_BENCH_PORT") orelse return default_port;
    // Benchmark follows the self-test script's port config to avoid a stale process holding the fixed 19090 and blocking verification.
    return std.fmt.parseInt(u16, std.mem.span(raw), 10) catch default_port;
}

fn readUsizeEnv(comptime name: [:0]const u8, default_value: usize) usize {
    const raw = std.c.getenv(name) orelse return default_value;
    // Benchmark needs to distinguish a small smoke test from a scale test; connection/request counts must not be hardcoded in the source.
    const parsed = std.fmt.parseInt(usize, std.mem.span(raw), 10) catch return default_value;
    return if (parsed == 0) default_value else parsed;
}

fn drainAvailable(fd: i32, buf: []u8) usize {
    var recv: usize = 0;
    while (true) {
        const raw = linux.recvfrom(fd, buf.ptr, buf.len, linux.MSG.DONTWAIT, null, null);
        const n_signed: isize = @bitCast(raw);
        if (n_signed <= 0) break;
        recv += countResponses(buf[0..@intCast(n_signed)]);
    }
    return recv;
}

fn writeAllRequest(fd: i32, req: []const u8) bool {
    // Under high connection counts write may short-write; a partial HTTP request entering the connection corrupts subsequent requests, so the benchmark must only count fully written requests.
    var written_total: usize = 0;
    while (written_total < req.len) {
        const raw_written = linux.write(fd, req.ptr + written_total, req.len - written_total);
        const written: isize = @bitCast(raw_written);
        if (written <= 0) return false;
        written_total += @intCast(written);
    }
    return true;
}

fn waitReadable(fds: []const i32, poll_fds: []std.posix.pollfd) bool {
    var count: usize = 0;
    for (fds) |dfd| {
        if (dfd == 0) continue;
        poll_fds[count] = .{
            .fd = dfd,
            .events = std.posix.POLL.IN | std.posix.POLL.ERR | std.posix.POLL.HUP,
            .revents = 0,
        };
        count += 1;
    }
    if (count == 0) return false;
    return (std.posix.poll(poll_fds[0..count], DRAIN_POLL_TIMEOUT_MS) catch return false) != 0;
}

fn drainUntil(fds: []const i32, poll_fds: []std.posix.pollfd, buf: []u8, recv: *usize, target: usize, max_idle_rounds: usize) void {
    var idle_rounds: usize = 0;
    while (recv.* < target and idle_rounds < max_idle_rounds) {
        var progressed = false;
        for (fds) |dfd| {
            if (dfd == 0) continue;
            const n = drainAvailable(dfd, buf);
            if (n != 0) progressed = true;
            recv.* += n;
        }
        if (progressed) {
            idle_rounds = 0;
        } else {
            // A fixed 10ms sleep would artificially cap the 100-round smoke benchmark at ~5k req/s; poll lets it continue as soon as a response arrives.
            if (waitReadable(fds, poll_fds)) {
                idle_rounds = 0;
            } else {
                idle_rounds += 1;
            }
        }
    }
}

pub fn main() !void {
    // The benchmark targets the HTTP/io_uring path, so DebugAllocator's checking overhead must not count toward QPS.
    const alloc = std.heap.c_allocator;

    const port = readPortEnv(DEFAULT_PORT);
    const conns = readUsizeEnv("SWS_BENCH_CONNS", DEFAULT_CONNS);
    const reqs_per_conn = readUsizeEnv("SWS_BENCH_REQS_PER_CONN", DEFAULT_REQS_PER_CONN);
    const addr = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{port});
    defer alloc.free(addr);

    var io_backend = std.Io.Threaded.init(alloc, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    var server = try AsyncServer.init(alloc, io, .{ .listen_addr = addr });
    defer server.deinit();
    try server.GET("/bench", benchHandler);
    server.installSigterm();

    const server_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *AsyncServer) void {
            s.run() catch @panic("server run failed");
        }
    }.run, .{&server});

    _ = linux.nanosleep(&linux.timespec{ .sec = 0, .nsec = 300_000_000 }, null);

    const t0 = nowMs();

    // connect clients
    const fds = try alloc.alloc(i32, conns);
    defer alloc.free(fds);
    @memset(fds, 0);
    const poll_fds = try alloc.alloc(std.posix.pollfd, conns);
    defer alloc.free(poll_fds);

    var connected: usize = 0;
    for (fds) |*fd| {
        const raw = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (raw < 0) continue;
        const fd_val: i32 = @intCast(raw);
        const sa = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = @byteSwap(@as(u16, port)),
            .addr = 0x0100007F,
            .zero = [_]u8{0} ** 8,
        };
        if (linux.connect(fd_val, @ptrCast(&sa), @sizeOf(linux.sockaddr.in)) == 0) {
            fd.* = fd_val;
            connected += 1;
        } else {
            _ = linux.close(fd_val);
        }
    }

    const t_conn = nowMs();

    // send requests
    var buf: [65536]u8 = undefined;
    const req = "GET /bench HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n";
    var sent: usize = 0;
    var recv: usize = 0;

    const t_send0 = nowMs();
    var round: usize = 0;
    while (round < reqs_per_conn) : (round += 1) {
        for (fds) |fd| {
            if (fd == 0) continue;
            if (writeAllRequest(fd, req)) sent += 1;
        }
        // The server does not support unbounded HTTP pipelining on a single connection, so all responses for this round must be drained before sending the next round.
        drainUntil(fds, poll_fds, buf[0..], &recv, sent, DRAIN_IDLE_ROUNDS);
    }
    // final drain
    // keep-alive connections never EOF on their own, so a blocking read would stall the benchmark during teardown.
    drainUntil(fds, poll_fds, buf[0..], &recv, sent, DRAIN_IDLE_ROUNDS);
    for (fds) |dfd| {
        if (dfd == 0) continue;
        _ = linux.close(dfd);
    }

    const t_end = nowMs();
    server.stop();
    server_thread.join();

    const conn_ms = t_conn - t0;
    const send_ms: i64 = @max(t_end - t_send0, 1);
    const per_sec = @divTrunc(@as(i64, @intCast(sent)) * 1000, send_ms);

    std.debug.print("\n", .{});
    std.debug.print("  config:      {d} conns x {d} req/conn\n", .{ conns, reqs_per_conn });
    std.debug.print("  connections: {d} ({d} ms)\n", .{ connected, conn_ms });
    std.debug.print("  sent:        {d} req in {d} ms\n", .{ sent, send_ms });
    std.debug.print("  recv:        {d} resp\n", .{recv});
    std.debug.print("  throughput:  {d} req/s\n", .{per_sec});
    std.debug.print("\n", .{});
}
