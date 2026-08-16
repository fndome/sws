const std = @import("std");
const Allocator = std.mem.Allocator;

/// Sends an HTTP response to the client at the end of chained async I/O.
/// The handler sets ctx.deferred = true; at the end of the chained call, resp.json/text sends the data back.
/// Worker thread → invokeOnIoThread(SPSC) → IO thread writes the response.
pub const DeferredResponse = struct {
    server: *@import("./http/async_server.zig").AsyncServer,
    conn_id: u64,
    allocator: Allocator,

    pub fn json(self: *const DeferredResponse, status: u16, body: []const u8) void {
        const duped = self.allocator.dupe(u8, body) catch {
            // OOM: send a best-effort error response so the client does not
            // hang indefinitely waiting for a deferred response that will
            // never arrive.
            const fallback = self.allocator.dupe(u8, "{\"error\":\"OOM\"}") catch {
                // persistent OOM: even the fallback allocation failed.
                // response will time out, but the slot is not leaked —
                // the close chain will free it when the connection closes
                return;
            };
            self.server.sendDeferredResponse(self.conn_id, 500, .json, fallback);
            return;
        };
        self.server.sendDeferredResponse(self.conn_id, status, .json, duped);
    }

    pub fn text(self: *const DeferredResponse, status: u16, body: []const u8) void {
        const duped = self.allocator.dupe(u8, body) catch {
            const fallback = self.allocator.dupe(u8, "OOM") catch {
                return;
            };
            self.server.sendDeferredResponse(self.conn_id, 500, .plain, fallback);
            return;
        };
        self.server.sendDeferredResponse(self.conn_id, status, .plain, duped);
    }
};
