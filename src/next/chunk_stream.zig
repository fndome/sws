const std = @import("std");
const Allocator = std.mem.Allocator;
const DeferredResponse = @import("../deferred.zig").DeferredResponse;

pub const ProcessFn = *const fn (ctx: ?*anyopaque, chunk: []const u8, resp: *DeferredResponse) void;

pub const StreamHandle = struct {
    const Self = @This();

    large_buf: []u8, // IO write target: LargeBufferPool 1MB
    offset: usize, // bytes accumulated in large_buf
    threshold: usize, // dispatch trigger byte count
    eof: bool, // stream finished
    dropped: bool, // set when a chunk dispatch is rejected by the worker pool
    job_id: u64,
    slot_idx: u32,
    resp: *DeferredResponse,
    process_fn: ProcessFn,
    process_ctx: ?*anyopaque,

    const CHUNK_DEFAULT: usize = 65536;

    pub fn init(large_buf: []u8, threshold: usize, slot_idx: u32, resp: *DeferredResponse, process_fn: ProcessFn, process_ctx: ?*anyopaque) Self {
        const thresh = if (threshold == 0) CHUNK_DEFAULT else threshold;
        return .{
            .large_buf = large_buf,
            .offset = 0,
            .threshold = thresh,
            .eof = false,
            .dropped = false,
            .job_id = 0,
            .slot_idx = slot_idx,
            .resp = resp,
            .process_fn = process_fn,
            .process_ctx = process_ctx,
        };
    }

    pub fn feed(self: *Self, data: []const u8) bool {
        if (self.eof) return false;
        var remaining = data;
        var dispatched = false;
        while (remaining.len > 0) {
            if (self.offset >= self.threshold) {
                self.dispatch();
                dispatched = true;
            }
            const space = self.large_buf.len -| self.offset;
            if (space == 0) {
                self.dispatch();
                dispatched = true;
                continue;
            }
            // Cap copy to threshold boundary to prevent exceeding worker_buf
            const to_threshold = self.threshold -| self.offset;
            const n = @min(@min(remaining.len, space), to_threshold);
            @memcpy(self.large_buf[self.offset..][0..n], remaining[0..n]);
            self.offset += n;
            remaining = remaining[n..];
        }
        // Trigger dispatch if we hit the threshold on the last chunk
        if (self.offset >= self.threshold) {
            self.dispatch();
            dispatched = true;
        }
        return dispatched;
    }

    pub fn finish(self: *Self) bool {
        self.eof = true;
        if (self.offset > 0) {
            self.dispatch();
            return true;
        }
        return false;
    }

    fn dispatch(self: *Self) void {
        if (self.offset == 0) return;
        std.debug.assert(self.offset <= self.large_buf.len);
        // Allocate a dedicated buffer for the worker so the next dispatch
        // does not overwrite data the worker is still reading. The worker
        // pool runs asynchronously; reusing worker_buf is a data race.
        const chunk_copy = self.resp.allocator.alloc(u8, self.offset) catch {
            self.offset = 0;
            self.dropped = true;
            return;
        };
        @memcpy(chunk_copy[0..self.offset], self.large_buf[0..self.offset]);
        const chunk_len = self.offset;
        self.offset = 0;

        const ctx = ChunkDispatchCtx{
            .chunk = chunk_copy.ptr,
            .chunk_len = chunk_len,
            .chunk_alloc = chunk_copy,
            .process_fn = self.process_fn,
            .process_ctx = self.process_ctx,
            .resp = self.resp,
            .job_id = self.job_id,
            .slot_idx = self.slot_idx,
        };
        const scheduler = self.resp.server.scheduler() catch {
            self.resp.allocator.free(chunk_copy);
            self.dropped = true;
            return;
        };
        if (!scheduler.trySubmit(ChunkDispatchCtx, ctx, runChunkWorker)) {
            self.resp.allocator.free(chunk_copy);
            self.dropped = true;
        }
    }
};

fn runChunkWorker(c: *ChunkDispatchCtx, complete: *const fn (?*anyopaque, []const u8) void) void {
    _ = complete;
    const chunk = c.chunk[0..c.chunk_len];
    c.process_fn(c.process_ctx, chunk, c.resp);
    // Free the per-chunk buffer allocated by dispatch() to prevent
    // overwrite races when the next chunk arrives before this worker
    // finishes processing.
    c.resp.allocator.free(c.chunk_alloc);
}

const ChunkDispatchCtx = struct {
    chunk: [*]u8,
    chunk_len: usize,
    chunk_alloc: []u8,
    process_fn: ProcessFn,
    process_ctx: ?*anyopaque,
    resp: *DeferredResponse,
    job_id: u64,
    slot_idx: u32,
};
