const std = @import("std");
const linux = std.os.linux;

const AsyncServer = @import("async_server.zig").AsyncServer;
const Connection = @import("connection.zig").Connection;
const Context = @import("context.zig").Context;
const packUserData = @import("../stack_pool.zig").packUserData;
const sticker = @import("../stack_pool_sticker.zig");
const helpers = @import("http_helpers.zig");
const getPathFromRequestWithLimit = helpers.getPathFromRequestWithLimit;
const getMethodFromRequest = helpers.getMethodFromRequest;
const isKeepAliveConnection = helpers.isKeepAliveConnection;
const logErr = helpers.logErr;
const ws_upgrade = @import("../ws/upgrade.zig");
const parser = @import("http_parser.zig");
const http_fiber = @import("http_fiber.zig");
const Fiber = @import("../next/fiber.zig").Fiber;
const milliTimestamp = @import("event_loop.zig").milliTimestamp;
const StackSlot = @import("../stack_pool.zig").StackSlot;
const HttpWork = @import("../stack_pool.zig").HttpWork;
const OVERSIZED_THRESHOLD = @import("../stack_pool.zig").OVERSIZED_THRESHOLD;
const BUFFER_SIZE = @import("../constants.zig").BUFFER_SIZE;
const NO_READ_BUFFER_BID = @import("../constants.zig").NO_READ_BUFFER_BID;
const HTTP_TASK_TAG = @import("../constants.zig").HTTP_TASK_TAG;
const TlsStream = @import("../tls/tls.zig").TlsStream;
const READ_BUF_GROUP_ID = @import("../constants.zig").READ_BUF_GROUP_ID;
const MAX_BUFFERED_BODY_SIZE: u64 = 1024 * 1024;
const MAX_REASSEMBLED_HEADER_SIZE: usize = BUFFER_SIZE * 2;
const build_options = @import("build_options");

const HttpTaskCtx = http_fiber.HttpTaskCtx;
const httpTaskExec = http_fiber.httpTaskExec;
const httpTaskExecWrapperWithOwnership = http_fiber.httpTaskExecWrapperWithOwnership;
const httpTaskComplete = http_fiber.httpTaskComplete;

fn prepareReadSubmission(conn: *Connection) void {
    conn.read_buf_recycled = false;
}

fn resetHttpWorkForRequest(slot: *StackSlot) *HttpWork {
    const hw = sticker.httpWork(slot);
    // keep-alive reuses the same slot, so Content-Length/path metadata must be reset per request instead of inheriting the previous POST.
    hw.* = .{};
    slot.line1.oversized = false;
    return hw;
}

fn clearPendingHeaderCopy(allocator: std.mem.Allocator, slot: *StackSlot, hw: *HttpWork) void {
    if (slot.line3.pending_buffer_ptr == 0) return;
    const saved: []u8 = @as([*]u8, @ptrFromInt(slot.line3.pending_buffer_ptr))[0..hw.header_len];
    allocator.free(saved);
    slot.line3.pending_buffer_ptr = 0;
    hw.pending_bid = NO_READ_BUFFER_BID;
    hw.pending_len = 0;
    hw.header_len = 0;
}

fn savePendingHeaderCopy(allocator: std.mem.Allocator, slot: *StackSlot, hw: *HttpWork, data: []const u8) !void {
    clearPendingHeaderCopy(allocator, slot, hw);
    const saved = try allocator.dupe(u8, data);
    // After multiple TCP fragments the header no longer lives in a single read buffer, so the accumulated copy must be saved.
    slot.line3.pending_buffer_ptr = @intFromPtr(saved.ptr);
    hw.pending_bid = NO_READ_BUFFER_BID;
    hw.pending_len = @intCast(saved.len);
    hw.header_len = @intCast(saved.len);
}

pub fn submitRead(self: *AsyncServer, conn_id: u64, conn: *Connection) !void {
    _ = conn_id;
    // read_buf_recycled tracks a single read CQE, so it must be reset before re-submitting a buffer-selection read.
    prepareReadSubmission(conn);
    const user_data = packUserData(conn.gen_id, conn.pool_idx);
    const fd = conn.ioFd();
    const sqe = self.ring.read(user_data, fd, .{
        .buffer_selection = .{ .group_id = READ_BUF_GROUP_ID, .len = BUFFER_SIZE },
    }, 0) catch return error.RingFull;
    if (conn.hasFixedFile()) sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn onReadComplete(self: *AsyncServer, conn_id: u64, res: i32, user_data: u64, cqe_flags: u32) void {
    _ = user_data;
    if (res <= 0) {
        const conn = self.getConn(conn_id) orelse return;
        if (cqe_flags & linux.IORING_CQE_F_BUFFER != 0) {
            const err_bid = @as(u16, @truncate(cqe_flags >> 16));
            self.buffer_pool.markReplenish(err_bid);
        }
        self.closeConn(conn_id, conn.fd);
        return;
    }
    const conn = self.getConn(conn_id) orelse return;

    if (cqe_flags & linux.IORING_CQE_F_BUFFER == 0) {
        self.closeConn(conn_id, conn.fd);
        return;
    }
    var bid = @as(u16, @truncate(cqe_flags >> 16));
    const read_buf = self.buffer_pool.getReadBuf(bid);
    const nread = @as(usize, @intCast(res));

    var plaintext_buf: [BUFFER_SIZE]u8 = [_]u8{0} ** BUFFER_SIZE;
    const tls = tlsDecryptRead(self, conn_id, conn, bid, read_buf[0..nread], &plaintext_buf);
    if (!tls.proceed) return;
    const plaintext_len = tls.plaintext_len;
    const tls_decrypted = tls.decrypted;
    bid = tls.bid;

    var effective_buf: []const u8 = if (build_options.tls_enabled and tls_decrypted) plaintext_buf[0..plaintext_len] else read_buf[0..nread];
    var effective_nread = if (build_options.tls_enabled and tls_decrypted) plaintext_len else nread;
    var pending_to_free: u16 = NO_READ_BUFFER_BID;
    var reassembled_header = false;
    var combo: [MAX_REASSEMBLED_HEADER_SIZE]u8 = undefined;

    const reassembly = reassembleHeader(self, conn, effective_buf, effective_nread, &combo, tls_decrypted);
    effective_buf = reassembly.effective_buf;
    effective_nread = reassembly.effective_nread;
    reassembled_header = reassembly.reassembled_header;
    pending_to_free = reassembly.pending_to_free;

    if (!build_options.tls_enabled or !tls_decrypted) {
        if (conn.read_len > 0 and conn.read_bid != pending_to_free) {
            self.buffer_pool.markReplenish(conn.read_bid);
        }
        if (pending_to_free != NO_READ_BUFFER_BID) {
            self.buffer_pool.markReplenish(pending_to_free);
        }
        conn.read_bid = bid;
    } else {
        conn.read_bid = NO_READ_BUFFER_BID;
    }
    conn.read_len = effective_nread;

    const has_header_end = std.mem.indexOf(u8, effective_buf, "\r\n\r\n") != null or
        std.mem.indexOf(u8, effective_buf, "\n\n") != null;
    if (!has_header_end) {
        const header_limit = reassembledHeaderLimit(self.cfg.max_header_buffer_size);
        if (headerBufferFullWithoutTerminator(effective_nread, header_limit)) {
            // The reassembly buffer hit its limit with no header terminator, so the next read can no longer append bytes;
            // continuing to submitRead would leave the connection stuck in the 8192-byte reassembly loop, so return 431 immediately.
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            conn.keep_alive = false;
            self.respond(conn, 431, "Request Header Fields Too Large");
            return;
        }
        if (self.connSlot(conn)) |slot| {
            const hw = sticker.httpWork(slot);
            if (reassembled_header or (build_options.tls_enabled and tls_decrypted and bid == NO_READ_BUFFER_BID)) {
                savePendingHeaderCopy(self.allocator, slot, hw, effective_buf) catch {
                    if (bid != NO_READ_BUFFER_BID) {
                        self.buffer_pool.markReplenish(bid);
                    }
                    conn.read_bid = NO_READ_BUFFER_BID;
                    conn.read_len = 0;
                    conn.keep_alive = false;
                    self.respond(conn, 500, "Internal Server Error");
                    return;
                };
                if (!build_options.tls_enabled or !tls_decrypted) {
                    self.buffer_pool.markReplenish(bid);
                }
                conn.read_bid = NO_READ_BUFFER_BID;
            } else {
                hw.pending_bid = bid;
                hw.pending_len = @intCast(effective_nread);
                hw.header_len = 0;
            }
        }
        conn.read_len = 0;
        self.submitRead(conn_id, conn) catch |err| {
            logErr("submitRead failed during header reassembly: {s}", .{@errorName(err)});
            if (self.connSlot(conn)) |slot| {
                const hw = sticker.httpWork(slot);
                if (hw.pending_bid != NO_READ_BUFFER_BID) {
                    self.buffer_pool.markReplenish(hw.pending_bid);
                    hw.pending_bid = NO_READ_BUFFER_BID;
                    hw.pending_len = 0;
                }
            }
            self.closeConn(conn_id, conn.fd);
        };
        return;
    }
    conn.state = .processing;

    if (!parser.requestLineIsSupported(effective_buf)) {
        // The request line must contain method, target, and an HTTP/1.x version; a malformed request must not reach the business handler.
        self.buffer_pool.markReplenish(bid);
        conn.read_len = 0;
        conn.keep_alive = false;
        self.respond(conn, 400, "Bad Request");
        return;
    }

    if (!parser.requestHeadersAreWellFormed(effective_buf)) {
        // Malformed header lines must not be ignored and passed to the business layer, or HTTP boundaries would be relaxed and later header parsing affected.
        self.buffer_pool.markReplenish(bid);
        conn.read_len = 0;
        conn.keep_alive = false;
        self.respond(conn, 400, "Bad Request");
        return;
    }

    if (!parser.hostHeaderIsValidForRequest(effective_buf)) {
        // HTTP/1.1 requires exactly one Host header; a missing or duplicate Host must not be passed to the business handler.
        self.buffer_pool.markReplenish(bid);
        conn.read_len = 0;
        conn.keep_alive = false;
        self.respond(conn, 400, "Bad Request");
        return;
    }

    conn.keep_alive = isKeepAliveConnection(effective_buf);

    if (self.connSlot(conn)) |slot| {
        // Refresh activity timestamp for TTL scanner. slot.line2.last_active_ms
        // was only set at slot allocation; without this update, every connection
        // times out after idle_timeout_ms regardless of actual request activity.
        const now_ms = milliTimestamp(self.io);
        slot.line2.last_active_ms = now_ms;
        conn.last_active_ms = now_ms;

        const path_limit = @as(usize, @intCast(self.cfg.max_path_length));
        const hw = resetHttpWorkForRequest(slot);
        hw.header_len = @intCast(@min(effective_nread, 65535));
        hw.method = if (effective_nread > 0) effective_buf[0] else 'G';
        if (std.mem.indexOfScalar(u8, effective_buf, ' ')) |sp1| {
            const after_method = sp1 + 1;
            if (after_method < effective_nread) {
                const path_start = after_method;
                if (std.mem.indexOfScalar(u8, effective_buf[path_start..effective_nread], ' ')) |sp2| {
                    const raw_target = effective_buf[path_start..][0..sp2];
                    // Routing matches on path only; the query string must not be written into the fast-path cache.
                    const q_pos = std.mem.indexOfScalar(u8, raw_target, '?') orelse raw_target.len;
                    if (q_pos == 0 or q_pos > path_limit) {
                        // max_path_length was not enforced before the fast-path cache, so an overlong path would bypass the helper and reach routing.
                        self.buffer_pool.markReplenish(bid);
                        conn.read_len = 0;
                        conn.keep_alive = false;
                        self.respond(
                            conn,
                            if (q_pos == 0) 400 else 414,
                            if (q_pos == 0) "Bad Request" else "URI Too Long",
                        );
                        return;
                    }
                    hw.path_offset = @intCast(path_start);
                    hw.path_len = @intCast(q_pos);
                }
            }
        }
        if (std.mem.indexOf(u8, effective_buf, "\r\n\r\n")) |pos| {
            // The body start is computed next; CRLF and LF-only separators have different lengths.
            hw.headers_end = @intCast(pos + 4);
        } else if (std.mem.indexOf(u8, effective_buf, "\n\n")) |pos| {
            hw.headers_end = @intCast(pos + 2);
        }
        if (helpers.extractHeader(effective_buf, "Transfer-Encoding")) |_| {
            // Body reads currently support only Content-Length, not chunked; handing off would leave the chunked body in the connection and corrupt subsequent requests.
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            conn.keep_alive = false;
            self.respond(conn, 400, "Bad Request");
            return;
        }
        const content_length_value = parser.extractSingleContentLength(effective_buf) catch {
            // Duplicate Content-Length makes the body boundary ambiguous, so the first value alone cannot be used.
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            conn.keep_alive = false;
            self.respond(conn, 400, "Bad Request");
            return;
        };
        if (content_length_value) |val| {
            // HTTP header names are case-insensitive, so a lowercase content-length must also take effect.
            hw.content_length = parser.parseContentLength(val) catch {
                // An invalid Content-Length must not be treated as no body, or the bad request would reach the handler and corrupt the keep-alive connection.
                self.buffer_pool.markReplenish(bid);
                conn.read_len = 0;
                conn.keep_alive = false;
                self.respond(conn, 400, "Bad Request");
                return;
            };
        }
        if (hw.content_length > OVERSIZED_THRESHOLD) {
            slot.line1.oversized = true;
        }
    }

    if (startBodyRead(self, conn_id, conn, bid, effective_buf, effective_nread, reassembled_header, tls_decrypted)) return;

    var request_buf = effective_buf;
    if (self.connSlot(conn)) |slot| {
        const hw_req = sticker.httpWork(slot);
        if (completeRequestEnd(effective_nread, hw_req.headers_end, hw_req.content_length)) |request_end| {
            request_buf = effective_buf[0..request_end];
            if (request_end < effective_nread) {
                // The event loop currently schedules only one HTTP request at a time; a trailing request in the same read buffer would be silently dropped and time out the client if keep-alive continued.
                conn.keep_alive = false;
            }
        }
    }

    const path = if (self.connSlot(conn)) |slot| blk: {
        const hw2 = sticker.httpWork(slot);
        if (hw2.path_len > 0 and hw2.path_offset + hw2.path_len <= request_buf.len)
            break :blk request_buf[hw2.path_offset..][0..hw2.path_len];
        break :blk getPathFromRequestWithLimit(
            request_buf,
            @as(usize, @intCast(self.cfg.max_path_length)),
        ) orelse {
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            self.respond(conn, 400, "Bad Request");
            return;
        };
    } else getPathFromRequestWithLimit(
        request_buf,
        @as(usize, @intCast(self.cfg.max_path_length)),
    ) orelse {
        self.buffer_pool.markReplenish(bid);
        conn.read_len = 0;
        self.respond(conn, 400, "Bad Request");
        return;
    };

    if (self.ws_server.hasHandlers() and ws_upgrade.isUpgradeRequest(request_buf)) {
        self.tryWsUpgrade(conn_id, conn, path, request_buf, bid);
        return;
    }

    if (self.respond_middlewares.has_global or
        self.respond_middlewares.precise.count() > 0 or
        self.respond_middlewares.wildcard.items.len > 0)
    {
        var temp_ctx = Context{
            .request_data = request_buf,
            .path = path,
            .app_ctx = self.app_ctx,
            .allocator = self.allocator,
            .status = 200,
            .content_type = .plain,
            .body = null,
            .headers = null,
            .conn_id = conn_id,
            .server = @ptrCast(self),
        };
        defer temp_ctx.deinit();
        var matched_respond_middleware = false;

        if (self.respond_middlewares.has_global) {
            matched_respond_middleware = true;
            for (self.respond_middlewares.global.items) |mw| {
                _ = mw(self.allocator, &temp_ctx) catch |err| {
                    logErr("respond middleware error: {s}", .{@errorName(err)});
                    break;
                };
                if (temp_ctx.body != null) break;
            }
        }

        if (temp_ctx.body == null) {
            if (self.respond_middlewares.precise.get(path)) |list| {
                matched_respond_middleware = true;
                for (list.items) |mw| {
                    _ = mw(self.allocator, &temp_ctx) catch |err| {
                        logErr("respond middleware error: {s}", .{@errorName(err)});
                        break;
                    };
                    if (temp_ctx.body != null) break;
                }
            }
        }

        if (temp_ctx.body == null) {
            for (self.respond_middlewares.wildcard.items) |entry| {
                if (entry.rule.match(path)) {
                    matched_respond_middleware = true;
                    for (entry.list.items) |mw| {
                        _ = mw(self.allocator, &temp_ctx) catch |err| {
                            logErr("respond middleware error: {s}", .{@errorName(err)});
                            break;
                        };
                        if (temp_ctx.body != null) break;
                    }
                    if (temp_ctx.body != null) break;
                }
            }
        }

        // Fast middleware that did not match the current path must not return an empty 200, or it would bypass the normal handler.
        if (matched_respond_middleware) {
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;

            const extra_headers = if (temp_ctx.headers) |h| h.items else "";

            if (temp_ctx.body) |body| {
                if (!self.ensureWriteBuf(conn, 512 + body.len + extra_headers.len)) {
                    self.allocator.free(body);
                    temp_ctx.body = null;
                    self.closeConn(conn_id, conn.fd);
                    return;
                }
                const buf = conn.response_buf.?;
                const mime = switch (temp_ctx.content_type) {
                    .plain => "text/plain",
                    .json => "application/json",
                    .html => "text/html",
                };
                const reason = statusText(temp_ctx.status);
                const conn_hdr = if (conn.keep_alive) "keep-alive" else "close";
                const len = std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\n{s}Content-Length: {d}\r\nConnection: {s}\r\n\r\n{s}", .{ temp_ctx.status, reason, mime, extra_headers, body.len, conn_hdr, body }) catch {
                    self.respondError(conn);
                    return;
                };
                conn.write_headers_len = len.len;
                conn.write_offset = 0;
                conn.write_body = null;
                conn.state = .writing;
                self.submitWrite(conn_id, conn) catch {
                    self.closeConn(conn_id, conn.fd);
                };
            } else if (extra_headers.len > 0) {
                if (!self.ensureWriteBuf(conn, headerOnlyCapacity(extra_headers.len))) {
                    self.closeConn(conn_id, conn.fd);
                    return;
                }
                const buf = conn.response_buf.?;
                const conn_hdr = if (conn.keep_alive) "keep-alive" else "close";
                const len = std.fmt.bufPrint(buf, "HTTP/1.1 200 OK\r\n{s}Content-Length: 0\r\nConnection: {s}\r\n\r\n", .{ extra_headers, conn_hdr }) catch {
                    self.respondError(conn);
                    return;
                };
                conn.write_headers_len = len.len;
                conn.write_offset = 0;
                conn.state = .writing;
                self.submitWrite(conn_id, conn) catch {
                    self.closeConn(conn_id, conn.fd);
                };
            } else {
                self.respond(conn, 200, "OK");
            }
            return;
        }
    }

    dispatchToHandler(self, conn_id, conn, path, request_buf, reassembled_header);
}

fn dispatchToHandler(self: *AsyncServer, conn_id: u64, conn: *Connection, path: []const u8, request_buf: []const u8, reassembled_header: bool) void {
    const has_async = self.middlewares.has_global or
        self.middlewares.precise.count() > 0 or
        self.middlewares.wildcard.items.len > 0 or
        self.handlers.count() > 0;
    if (!has_async) {
        self.buffer_pool.markReplenish(conn.read_bid);
        conn.read_len = 0;
        self.respond(conn, 404, "Not Found");
        return;
    }

    var selected_buf = request_buf;
    var request_data_owned = false;
    if (reassembled_header) {
        selected_buf = self.allocator.dupe(u8, request_buf) catch {
            self.buffer_pool.markReplenish(conn.read_bid);
            conn.read_len = 0;
            self.respond(conn, 500, "Internal Server Error");
            return;
        };
        // Across TCP fragments effective_buf points at the stack combo buffer, so fibers/queues must not hold a stack pointer.
        request_data_owned = true;
    }
    const method_str = getMethodFromRequest(selected_buf) orelse "GET";

    const t = self.http_ctx_pool.create(self.allocator) catch {
        if (request_data_owned) self.allocator.free(selected_buf);
        self.buffer_pool.markReplenish(conn.read_bid);
        conn.read_len = 0;
        self.respond(conn, 500, "Internal Server Error");
        return;
    };
    const method_cap: u4 = @intCast(@min(method_str.len, 15));
    const path_cap: u8 = @intCast(@min(path.len, 255));
    t.* = .{
        .tag = HTTP_TASK_TAG,
        .server = self,
        .conn_id = conn_id,
        .read_bid = conn.read_bid,
        .method_len = method_cap,
        .path_len = path_cap,
        .request_data = @constCast(selected_buf),
        .request_data_owned = request_data_owned,
    };
    @memcpy(t.method_buf[0..method_cap], method_str[0..method_cap]);
    @memcpy(t.path_buf[0..path_cap], path[0..path_cap]);

    if (self.shared_fiber_active) {
        if (self.next) |*n| {
            if (n.push(HttpTaskCtx, t.*, httpTaskExecWrapperWithOwnership, self.cfg.fiber_stack_size_kb * 1024)) {
                self.http_ctx_pool.destroy(t);
            } else {
                http_fiber.httpTaskCleanup(t);
                self.respond(conn, 503, "Service Unavailable");
            }
        } else {
            http_fiber.httpTaskCleanup(t);
            self.respond(conn, 503, "Service Unavailable");
        }
    } else {
        var fiber = Fiber.init(self.shared_fiber_stack);
        self.shared_fiber_active = true;
        fiber.exec(.{
            .userCtx = t,
            .complete = httpTaskComplete,
            .execFn = httpTaskExec,
        });
    }

    conn.read_len = 0;
}

fn startBodyRead(self: *AsyncServer, conn_id: u64, conn: *Connection, bid: u16, effective_buf: []const u8, effective_nread: usize, reassembled_header: bool, tls_decrypted: bool) bool {
    const body_incomplete = brk: {
        const slot = self.connSlot(conn) orelse break :brk false;
        const hw3 = sticker.httpWork(slot);
        if (hw3.content_length == 0) break :brk false;
        const headers_end = if (hw3.headers_end > 0) hw3.headers_end else effective_nread;
        const body_avail: usize = if (effective_nread > headers_end) effective_nread - headers_end else 0;
        break :brk body_avail < hw3.content_length;
    };
    if (!body_incomplete) return false;

    const slot = self.connSlot(conn).?;
    const hw4 = sticker.httpWork(slot);
    const headers_end = if (hw4.headers_end > 0) hw4.headers_end else effective_nread;
    if (!fitsLargeBodyBuffer(hw4.content_length)) {
        // LargeBufferPool blocks are only 1MB each; using min(content_length, large_buf.len)
        // would truncate an oversized body before the business layer sees it and leave the remaining bytes to corrupt subsequent requests.
        self.buffer_pool.markReplenish(bid);
        conn.read_len = 0;
        conn.keep_alive = false;
        self.respond(conn, 413, "Content Too Large");
        return true;
    }
    if (reassembled_header or (build_options.tls_enabled and tls_decrypted)) {
        // With reassembled_header, effective_buf points at the stack combo copy; with TLS decryption it points at the stack plaintext_buf copy.
        // Once async body reading begins the stack is unwound, so the header must be saved to the heap or processBodyRequest will read garbage.
        const header_copy = self.allocator.dupe(u8, effective_buf[0..headers_end]) catch {
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            conn.keep_alive = false;
            self.respond(conn, 500, "Internal Server Error");
            return true;
        };
        slot.line3.pending_buffer_ptr = @intFromPtr(header_copy.ptr);
        hw4.header_len = @intCast(header_copy.len);
    }
    if (headers_end >= effective_nread) {
        const large_buf = self.large_pool.acquire() orelse {
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            conn.keep_alive = false;
            self.respond(conn, 413, "Content Too Large");
            return true;
        };
        slot.line3.large_buf_ptr = @intFromPtr(large_buf.ptr);
        slot.line3.large_buf_len = @intCast(hw4.content_length);
        slot.line3.large_buf_offset = 0;

        conn.read_len = 0;
        conn.state = .receiving_body;
        self.submitBodyRead(conn, large_buf, slot) catch {
            // A failed body-read SQE submission never reaches processBodyRequest, so the retained header read buffer must be returned.
            self.buffer_pool.markReplenish(bid);
            conn.read_bid = NO_READ_BUFFER_BID;
            conn.read_len = 0;
            self.large_pool.release(large_buf);
            slot.line3.large_buf_ptr = 0;
            self.closeConn(conn_id, conn.fd);
        };
        return true;
    }

    const body_fragment = effective_buf[headers_end..effective_nread];
    const large_buf = self.large_pool.acquire() orelse {
        self.buffer_pool.markReplenish(bid);
        conn.read_len = 0;
        conn.keep_alive = false;
        self.respond(conn, 413, "Content Too Large");
        return true;
    };
    slot.line3.large_buf_ptr = @intFromPtr(large_buf.ptr);
    slot.line3.large_buf_len = @intCast(hw4.content_length);
    slot.line3.large_buf_offset = 0;

    @memcpy(large_buf[0..body_fragment.len], body_fragment);
    slot.line3.large_buf_offset = @intCast(body_fragment.len);

    conn.read_len = 0;
    conn.state = .receiving_body;
    self.submitBodyRead(conn, large_buf, slot) catch {
        // A failed body-read SQE submission never reaches processBodyRequest, so the retained header read buffer must be returned.
        self.buffer_pool.markReplenish(bid);
        conn.read_bid = NO_READ_BUFFER_BID;
        conn.read_len = 0;
        self.large_pool.release(large_buf);
        slot.line3.large_buf_ptr = 0;
        self.closeConn(conn_id, conn.fd);
    };
    return true;
}

const TlsReadResult = struct {
    proceed: bool,
    decrypted: bool,
    plaintext_len: usize,
    bid: u16,
};

fn tlsDecryptRead(self: *AsyncServer, conn_id: u64, conn: *Connection, bid: u16, ciphertext: []const u8, plaintext_buf: *[BUFFER_SIZE]u8) TlsReadResult {
    if (!build_options.tls_enabled) {
        return .{ .proceed = true, .decrypted = false, .plaintext_len = 0, .bid = bid };
    }
    const tls_stream = conn.tls orelse return .{ .proceed = true, .decrypted = false, .plaintext_len = 0, .bid = bid };

    const decrypted = tls_stream.read(ciphertext, plaintext_buf) catch {
        self.buffer_pool.markReplenish(bid);
        conn.read_len = 0;
        self.closeConn(conn_id, conn.fd);
        return .{ .proceed = false, .decrypted = false, .plaintext_len = 0, .bid = bid };
    };
    if (decrypted == 0) {
        self.buffer_pool.markReplenish(bid);
        conn.read_bid = NO_READ_BUFFER_BID;
        conn.read_len = 0;
        self.submitRead(conn_id, conn) catch |err_sub| {
            logErr("submitRead after TLS WANT_READ: {s}", .{@errorName(err_sub)});
            self.closeConn(conn_id, conn.fd);
        };
        return .{ .proceed = false, .decrypted = false, .plaintext_len = 0, .bid = bid };
    }
    self.buffer_pool.markReplenish(bid);
    return .{ .proceed = true, .decrypted = true, .plaintext_len = decrypted, .bid = NO_READ_BUFFER_BID };
}

const ReassembleResult = struct {
    effective_buf: []const u8,
    effective_nread: usize,
    reassembled_header: bool,
    pending_to_free: u16,
};

fn reassembleHeader(self: *AsyncServer, conn: *Connection, effective_buf: []const u8, effective_nread: usize, combo: *[MAX_REASSEMBLED_HEADER_SIZE]u8, tls_decrypted: bool) ReassembleResult {
    var pending_to_free: u16 = NO_READ_BUFFER_BID;
    var reassembled_header = false;
    var result_buf = effective_buf;
    var result_nread = effective_nread;

    const slot = self.connSlot(conn) orelse return .{
        .effective_buf = result_buf,
        .effective_nread = result_nread,
        .reassembled_header = false,
        .pending_to_free = pending_to_free,
    };

    // TLS decrypt reuses plaintext buffer for effective_buf, but if header
    // spans reads, the plaintext is on the stack and will be overwritten.
    // Use heap save (slice to slot.line3.pending_buffer_ptr) for TLS path.
    // For plaintext path, use io_uring bid as before.
    if (!build_options.tls_enabled or !tls_decrypted or blk: {
        const hw = sticker.httpWork(slot);
        break :blk hw.pending_len > 0 and hw.pending_bid == NO_READ_BUFFER_BID and slot.line3.pending_buffer_ptr != 0;
    }) {
        const hw = sticker.httpWork(slot);
        if (hw.pending_len > 0 and (hw.pending_bid != NO_READ_BUFFER_BID or slot.line3.pending_buffer_ptr != 0)) {
            const prev_len: usize = @intCast(hw.pending_len);
            var saved_heap: ?[]u8 = null;
            const prev_buf: []const u8 = if (slot.line3.pending_buffer_ptr != 0) blk: {
                const saved: []u8 = @as([*]u8, @ptrFromInt(slot.line3.pending_buffer_ptr))[0..prev_len];
                // Reassembling a header split across more than two reads cannot rely on the previous buffer id alone; accumulated fragments must be restored from the heap copy.
                saved_heap = saved;
                slot.line3.pending_buffer_ptr = 0;
                hw.header_len = 0;
                break :blk saved;
            } else blk: {
                pending_to_free = hw.pending_bid;
                break :blk self.buffer_pool.getReadBuf(hw.pending_bid)[0..prev_len];
            };
            const copy_prev_len = @min(prev_buf.len, combo.len);
            const cur_len = @min(effective_nread, combo.len - copy_prev_len);
            @memcpy(combo[0..copy_prev_len], prev_buf[0..copy_prev_len]);
            @memcpy(combo[copy_prev_len..][0..cur_len], effective_buf[0..cur_len]);
            result_buf = combo[0 .. copy_prev_len + cur_len];
            result_nread = copy_prev_len + cur_len;
            reassembled_header = true;
            if (saved_heap) |saved| self.allocator.free(saved);
            hw.pending_bid = NO_READ_BUFFER_BID;
            hw.pending_len = 0;
        }
    }

    return .{
        .effective_buf = result_buf,
        .effective_nread = result_nread,
        .reassembled_header = reassembled_header,
        .pending_to_free = pending_to_free,
    };
}

const statusText = @import("http_response.zig").statusText;
const headerOnlyCapacity = @import("http_response.zig").headerOnlyCapacity;

fn fitsLargeBodyBuffer(content_length: u64) bool {
    return content_length <= MAX_BUFFERED_BODY_SIZE;
}

fn reassembledHeaderLimit(configured_limit: u32) usize {
    return @min(@as(usize, configured_limit), MAX_REASSEMBLED_HEADER_SIZE);
}

fn headerBufferFullWithoutTerminator(effective_nread: usize, header_limit: usize) bool {
    return effective_nread >= header_limit;
}

fn completeRequestEnd(buffer_len: usize, headers_end: u16, content_length: u64) ?usize {
    if (headers_end == 0) return null;
    const header_bytes: usize = headers_end;
    if (header_bytes > buffer_len) return null;
    if (content_length > std.math.maxInt(usize) - header_bytes) return null;
    const end = header_bytes + @as(usize, @intCast(content_length));
    if (end > buffer_len) return null;
    return end;
}

test "large body buffer limit rejects truncation" {
    try std.testing.expect(fitsLargeBodyBuffer(MAX_BUFFERED_BODY_SIZE));
    try std.testing.expect(!fitsLargeBodyBuffer(MAX_BUFFERED_BODY_SIZE + 1));
}

test "header reassembly rejects at full buffer without terminator" {
    try std.testing.expect(headerBufferFullWithoutTerminator(MAX_REASSEMBLED_HEADER_SIZE, reassembledHeaderLimit(8192)));
    try std.testing.expect(!headerBufferFullWithoutTerminator(MAX_REASSEMBLED_HEADER_SIZE - 1, reassembledHeaderLimit(8192)));
    try std.testing.expectEqual(@as(usize, MAX_REASSEMBLED_HEADER_SIZE), reassembledHeaderLimit(16 * 1024));
}

test "pending header copy preserves reassembled fragments" {
    var slot = StackSlot{
        .line1 = .{},
        .line2 = .{},
        .line3 = .{},
        .line4 = .{},
        .line5 = .{},
    };
    const hw = sticker.httpWork(&slot);
    const data = "GET /split HTTP/1.1\r\nHost: example.test\r\nX-Long: partial";

    try savePendingHeaderCopy(std.testing.allocator, &slot, hw, data);
    defer clearPendingHeaderCopy(std.testing.allocator, &slot, hw);

    try std.testing.expectEqual(NO_READ_BUFFER_BID, hw.pending_bid);
    try std.testing.expectEqual(@as(u16, data.len), hw.pending_len);
    try std.testing.expectEqual(@as(u16, data.len), hw.header_len);
    const saved = @as([*]u8, @ptrFromInt(slot.line3.pending_buffer_ptr))[0..data.len];
    try std.testing.expectEqualStrings(data, saved);
}

test "submitRead preparation resets recycled marker for next CQE" {
    var conn = Connection{ .id = 0, .fd = 0, .read_buf_recycled = true };
    prepareReadSubmission(&conn);
    try std.testing.expect(!conn.read_buf_recycled);
}

test "HTTP work metadata resets between keep-alive requests" {
    var slot = StackSlot{
        .line1 = .{},
        .line2 = .{},
        .line3 = .{},
        .line4 = .{},
        .line5 = .{},
    };
    var hw = sticker.httpWork(&slot);
    hw.content_length = 7;
    hw.path_offset = 5;
    hw.path_len = 12;
    hw.headers_end = 42;
    slot.line1.oversized = true;

    hw = resetHttpWorkForRequest(&slot);
    try std.testing.expectEqual(@as(u64, 0), hw.content_length);
    try std.testing.expectEqual(@as(u16, 0), hw.path_len);
    try std.testing.expectEqual(@as(u16, 0), hw.headers_end);
    try std.testing.expect(!slot.line1.oversized);
}

test "completeRequestEnd detects pipelined trailing bytes boundary" {
    try std.testing.expectEqual(@as(?usize, 12), completeRequestEnd(20, 5, 7));
    try std.testing.expectEqual(@as(?usize, 5), completeRequestEnd(20, 5, 0));
    try std.testing.expect(completeRequestEnd(10, 5, 7) == null);
    try std.testing.expect(completeRequestEnd(10, 0, 0) == null);
}
