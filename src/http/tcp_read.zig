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
    // 修改原因：keep-alive 复用同一 slot，Content-Length/path 等元数据必须按请求重置，不能继承上一轮 POST。
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
    // 修改原因：多次 TCP 分片后的 header 不再完整存在于某一个 read buffer，必须保存累计副本。
    slot.line3.pending_buffer_ptr = @intFromPtr(saved.ptr);
    hw.pending_bid = NO_READ_BUFFER_BID;
    hw.pending_len = @intCast(saved.len);
    hw.header_len = @intCast(saved.len);
}

pub fn submitRead(self: *AsyncServer, conn_id: u64, conn: *Connection) !void {
    _ = conn_id;
    // 修改原因：read_buf_recycled 针对单次 read CQE，重新提交 buffer-selection read 前必须重置。
    prepareReadSubmission(conn);
    const user_data = packUserData(conn.gen_id, conn.pool_idx);
    const fd = if (conn.fixed_index != 0xFFFF) @as(i32, @intCast(conn.fixed_index)) else conn.fd;
    const sqe = self.ring.read(user_data, fd, .{
        .buffer_selection = .{ .group_id = READ_BUF_GROUP_ID, .len = BUFFER_SIZE },
    }, 0) catch return error.RingFull;
    if (conn.fixed_index != 0xFFFF) sqe.flags |= linux.IOSQE_FIXED_FILE;
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
    var plaintext_len: usize = 0;
    var tls_decrypted = false;
    if (build_options.tls_enabled) {

        if (conn.tls) |tls_stream| {
            const decrypted = tls_stream.read(read_buf[0..nread], &plaintext_buf) catch |err| {
                if (err == error.TlsConnectionClosed) {
                    self.buffer_pool.markReplenish(bid);
                    conn.read_len = 0;
                    self.closeConn(conn_id, conn.fd);
                    return;
                }
                self.buffer_pool.markReplenish(bid);
                conn.read_len = 0;
                self.closeConn(conn_id, conn.fd);
                return;
            };
            plaintext_len = decrypted;
            if (decrypted == 0) {
                self.buffer_pool.markReplenish(bid);
                conn.read_bid = NO_READ_BUFFER_BID;
                conn.read_len = 0;
                self.submitRead(conn_id, conn) catch |err_sub| {
                    logErr("submitRead after TLS WANT_READ: {s}", .{@errorName(err_sub)});
                    self.closeConn(conn_id, conn.fd);
                };
                return;
            }
            self.buffer_pool.markReplenish(bid);
            tls_decrypted = true;
            bid = NO_READ_BUFFER_BID;
        }
    }

    var effective_buf: []const u8 = if (build_options.tls_enabled and tls_decrypted) plaintext_buf[0..plaintext_len] else read_buf[0..nread];
    var effective_nread = if (build_options.tls_enabled and tls_decrypted) plaintext_len else nread;
    var pending_to_free: u16 = NO_READ_BUFFER_BID;
    var reassembled_header = false;
    var combo: [MAX_REASSEMBLED_HEADER_SIZE]u8 = undefined;

    if (conn.pool_idx != 0xFFFFFFFF) {
        // TLS decrypt reuses plaintext buffer for effective_buf, but if header
        // spans reads, the plaintext is on the stack and will be overwritten.
        // Use heap save (slice to slot.line3.pending_buffer_ptr) for TLS path.
        // For plaintext path, use io_uring bid as before.
        if (!build_options.tls_enabled or !tls_decrypted or blk: {
            const hw = sticker.httpWork(&self.pool.slots[conn.pool_idx]);
            break :blk hw.pending_len > 0 and hw.pending_bid == NO_READ_BUFFER_BID and self.pool.slots[conn.pool_idx].line3.pending_buffer_ptr != 0;
        }) {
        const slot = &self.pool.slots[conn.pool_idx];
        const hw = sticker.httpWork(slot);
        if (hw.pending_len > 0 and (hw.pending_bid != NO_READ_BUFFER_BID or slot.line3.pending_buffer_ptr != 0)) {
            const prev_len: usize = @intCast(hw.pending_len);
            var saved_heap: ?[]u8 = null;
            const prev_buf: []const u8 = if (slot.line3.pending_buffer_ptr != 0) blk: {
                const saved: []u8 = @as([*]u8, @ptrFromInt(slot.line3.pending_buffer_ptr))[0..prev_len];
                // 修改原因：超过两段的 header 重组不能只依赖上一个 buffer id，累计片段必须从堆副本恢复。
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
            effective_buf = combo[0 .. copy_prev_len + cur_len];
            effective_nread = copy_prev_len + cur_len;
            reassembled_header = true;
            if (saved_heap) |saved| self.allocator.free(saved);
            hw.pending_bid = NO_READ_BUFFER_BID;
            hw.pending_len = 0;
        }
    }
    } // conn.pool_idx guard for header reassembly

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
            // 修改原因：重组缓冲到达上限且仍无 header 结束符时，下一次读取已无法继续追加字节；
            // 继续 submitRead 会让连接卡在 8192 字节重组循环里，应立即返回 431。
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            conn.keep_alive = false;
            self.respond(conn, 431, "Request Header Fields Too Large");
            return;
        }
        if (conn.pool_idx != 0xFFFFFFFF) {
            const slot = &self.pool.slots[conn.pool_idx];
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
            if (conn.pool_idx != 0xFFFFFFFF) {
                const hw = sticker.httpWork(&self.pool.slots[conn.pool_idx]);
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
        // 修改原因：请求行必须包含 method、target 和 HTTP/1.x 版本；畸形请求不能继续进入业务 handler。
        self.buffer_pool.markReplenish(bid);
        conn.read_len = 0;
        conn.keep_alive = false;
        self.respond(conn, 400, "Bad Request");
        return;
    }

    if (!parser.requestHeadersAreWellFormed(effective_buf)) {
        // 修改原因：畸形 header 行不能被业务层忽略后继续处理，否则会放宽 HTTP 边界并影响后续头解析。
        self.buffer_pool.markReplenish(bid);
        conn.read_len = 0;
        conn.keep_alive = false;
        self.respond(conn, 400, "Bad Request");
        return;
    }

    if (!parser.hostHeaderIsValidForRequest(effective_buf)) {
        // 修改原因：HTTP/1.1 要求且只允许一个 Host；缺失或重复 Host 不能继续交给业务 handler。
        self.buffer_pool.markReplenish(bid);
        conn.read_len = 0;
        conn.keep_alive = false;
        self.respond(conn, 400, "Bad Request");
        return;
    }

    conn.keep_alive = isKeepAliveConnection(effective_buf);

    if (conn.pool_idx != 0xFFFFFFFF) {
        // Refresh activity timestamp for TTL scanner. slot.line2.last_active_ms
        // was only set at slot allocation; without this update, every connection
        // times out after idle_timeout_ms regardless of actual request activity.
        const now_ms = milliTimestamp(self.io);
        self.pool.slots[conn.pool_idx].line2.last_active_ms = now_ms;
        conn.last_active_ms = now_ms;

        const slot = &self.pool.slots[conn.pool_idx];
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
                    // 修改原因：路由匹配只使用 path，不能把 query string 一起写入 fast-path cache。
                    const q_pos = std.mem.indexOfScalar(u8, raw_target, '?') orelse raw_target.len;
                    if (q_pos == 0 or q_pos > path_limit) {
                        // 修改原因：fast-path cache 之前没有执行 max_path_length，超长路径会绕过 helper 进入路由层。
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
            // 修改原因：后续要计算 body 起点，CRLF 和 LF-only 分隔符长度不同。
            hw.headers_end = @intCast(pos + 4);
        } else if (std.mem.indexOf(u8, effective_buf, "\n\n")) |pos| {
            hw.headers_end = @intCast(pos + 2);
        }
        if (helpers.extractHeader(effective_buf, "Transfer-Encoding")) |_| {
            // 修改原因：当前请求体读取只支持 Content-Length，不支持 chunked；继续交给 handler 会把分块 body 留在连接里污染后续请求。
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            conn.keep_alive = false;
            self.respond(conn, 400, "Bad Request");
            return;
        }
        const content_length_value = parser.extractSingleContentLength(effective_buf) catch {
            // 修改原因：重复 Content-Length 会让请求体边界产生歧义，不能只取第一个值继续处理。
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            conn.keep_alive = false;
            self.respond(conn, 400, "Bad Request");
            return;
        };
        if (content_length_value) |val| {
            // 修改原因：HTTP header 名大小写不敏感，lowercase content-length 也必须生效。
            hw.content_length = parser.parseContentLength(val) catch {
                // 修改原因：非法 Content-Length 不能按无 body 继续处理，否则坏请求会进入 handler 并污染 keep-alive 连接。
                self.buffer_pool.markReplenish(bid);
                conn.read_len = 0;
                conn.keep_alive = false;
                self.respond(conn, 400, "Bad Request");
                return;
            };
        }
        if (hw.content_length > OVERSIZED_THRESHOLD) {
            self.pool.slots[conn.pool_idx].line1.oversized = true;
        }
    }

    const body_incomplete = brk: {
        if (conn.pool_idx == 0xFFFFFFFF) break :brk false;
        const hw3 = sticker.httpWork(&self.pool.slots[conn.pool_idx]);
        if (hw3.content_length == 0) break :brk false;
        const headers_end = if (hw3.headers_end > 0) hw3.headers_end else effective_nread;
        const body_avail: usize = if (effective_nread > headers_end) effective_nread - headers_end else 0;
        break :brk body_avail < hw3.content_length;
    };

    if (body_incomplete) {
        const slot = &self.pool.slots[conn.pool_idx];
        const hw4 = sticker.httpWork(slot);
        const headers_end = if (hw4.headers_end > 0) hw4.headers_end else effective_nread;
        if (!fitsLargeBodyBuffer(hw4.content_length)) {
            // 修改原因：LargeBufferPool 每块只有 1MB；继续用 min(content_length, large_buf.len)
            // 会把超大请求体截断后交给业务层，并把剩余字节留在连接里污染后续请求。
            self.buffer_pool.markReplenish(bid);
            conn.read_len = 0;
            conn.keep_alive = false;
            self.respond(conn, 413, "Content Too Large");
            return;
        }
        if (reassembled_header or (build_options.tls_enabled and tls_decrypted)) {
            // 修改原因：reassembled_header 时 effective_buf 指�?combo 栈上副本；TLS 解密时 effective_buf 指�?plaintext_buf 栈上副本。
            // 进入异步 body 读取后栈已展开，必须�?header 保存�?heap，否则 processBodyRequest 会读到脏数据�?
            const header_copy = self.allocator.dupe(u8, effective_buf[0..headers_end]) catch {
                self.buffer_pool.markReplenish(bid);
                conn.read_len = 0;
                conn.keep_alive = false;
                self.respond(conn, 500, "Internal Server Error");
                return;
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
                return;
            };
            slot.line3.large_buf_ptr = @intFromPtr(large_buf.ptr);
            slot.line3.large_buf_len = @intCast(hw4.content_length);
            slot.line3.large_buf_offset = 0;

            conn.read_len = 0;
            conn.state = .receiving_body;
            self.submitBodyRead(conn, large_buf, slot) catch {
                // 修改原因：body read SQE 提交失败后不会再进入 processBodyRequest，必须归还之前保留的 header read buffer。
                self.buffer_pool.markReplenish(bid);
                conn.read_bid = NO_READ_BUFFER_BID;
                conn.read_len = 0;
                self.large_pool.release(large_buf);
                slot.line3.large_buf_ptr = 0;
                self.closeConn(conn_id, conn.fd);
            };
            return;
        } else {
            const body_fragment = effective_buf[headers_end..effective_nread];
            const large_buf = self.large_pool.acquire() orelse {
                self.buffer_pool.markReplenish(bid);
                conn.read_len = 0;
                conn.keep_alive = false;
                self.respond(conn, 413, "Content Too Large");
                return;
            };
            slot.line3.large_buf_ptr = @intFromPtr(large_buf.ptr);
            slot.line3.large_buf_len = @intCast(hw4.content_length);
            slot.line3.large_buf_offset = 0;

            @memcpy(large_buf[0..body_fragment.len], body_fragment);
            slot.line3.large_buf_offset = @intCast(body_fragment.len);

            conn.read_len = 0;
            conn.state = .receiving_body;
            self.submitBodyRead(conn, large_buf, slot) catch {
                // 修改原因：body read SQE 提交失败后不会再进入 processBodyRequest，必须归还之前保留的 header read buffer。
                self.buffer_pool.markReplenish(bid);
                conn.read_bid = NO_READ_BUFFER_BID;
                conn.read_len = 0;
                self.large_pool.release(large_buf);
                slot.line3.large_buf_ptr = 0;
                self.closeConn(conn_id, conn.fd);
            };
            return;
        }
    }

    var request_buf = effective_buf;
    if (conn.pool_idx != 0xFFFFFFFF) {
        const hw_req = sticker.httpWork(&self.pool.slots[conn.pool_idx]);
        if (completeRequestEnd(effective_nread, hw_req.headers_end, hw_req.content_length)) |request_end| {
            request_buf = effective_buf[0..request_end];
            if (request_end < effective_nread) {
                // 修改原因：当前事件循环一次只调度一个 HTTP 请求；同一 read buffer 中的尾随请求若继续 keep-alive 会被静默丢弃并让客户端超时。
                conn.keep_alive = false;
            }
        }
    }

    const path = if (conn.pool_idx != 0xFFFFFFFF) blk: {
        const hw2 = sticker.httpWork(&self.pool.slots[conn.pool_idx]);
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

        // 修改原因：未匹配当前 path 的快速中间件不能直接返回空 200，否则会绕过正常 handler。
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

    const has_async = self.middlewares.has_global or
        self.middlewares.precise.count() > 0 or
        self.middlewares.wildcard.items.len > 0 or
        self.handlers.count() > 0;
    if (has_async) {
        var selected_buf = request_buf;
        var request_data_owned = false;
        if (reassembled_header) {
            selected_buf = self.allocator.dupe(u8, request_buf) catch {
                self.buffer_pool.markReplenish(conn.read_bid);
                conn.read_len = 0;
                self.respond(conn, 500, "Internal Server Error");
                return;
            };
            // 修改原因：跨 TCP 分片时 effective_buf 指向栈上 combo，fiber/队列不能持有栈指针。
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
            .tag = 0x48540001,
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
        return;
    }

    self.buffer_pool.markReplenish(conn.read_bid);
    conn.read_len = 0;
    self.respond(conn, 404, "Not Found");
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
    var conn = Connection{ .read_buf_recycled = true };
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
