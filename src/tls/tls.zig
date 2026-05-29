const std = @import("std");
const tls_lib = @import("tls");

pub const HandshakeStep = enum {
    want_read,
    want_write,
    done,
    error,
};

pub const TlsConfig = struct {
    allocator: std.mem.Allocator,
    is_server: bool,
    cert_key_pair: ?tls_lib.config.CertKeyPair = null,
    root_ca: ?tls_lib.config.cert.Bundle = null,
    init_now: std.Io.Timestamp,

    pub fn init(allocator: std.mem.Allocator, cert_path: ?[:0]const u8, key_path: ?[:0]const u8, is_server: bool) !TlsConfig {
        const io = std.Io{};
        const now = std.Io.Clock.real.now(io);

        if (is_server) {
            if (cert_path == null or key_path == null) return error.MissingCertificate;
            const ckp = try tls_lib.config.CertKeyPair.fromFilePathAbsolute(allocator, io, cert_path.?, key_path.?);
            return TlsConfig{
                .allocator = allocator,
                .is_server = true,
                .cert_key_pair = ckp,
                .init_now = now,
            };
        } else {
            return TlsConfig{
                .allocator = allocator,
                .is_server = false,
                .init_now = now,
            };
        }
    }

    pub fn deinit(self: *TlsConfig) void {
        if (self.cert_key_pair) |*ckp| {
            ckp.deinit(self.allocator);
        }
        if (self.root_ca) |*ca| {
            ca.deinit(self.allocator);
        }
    }

    fn serverOptions(self: *const TlsConfig) tls_lib.config.Server {
        return .{
            .rng = std.crypto.random,
            .auth = if (self.cert_key_pair) |*ckp| @constCast(ckp) else null,
            .now = self.init_now,
        };
    }

    fn clientOptions(self: *const TlsConfig) tls_lib.config.Client {
        return .{
            .rng = std.crypto.random,
            .now = self.init_now,
            .host = "localhost",
            .insecure_skip_verify = true,
        };
    }
};

pub const TlsStream = struct {
    state: State,
    ready_cipher: ?tls_lib.Cipher = null,
    handshake_out_buf: [tls_lib.max_ciphertext_record_len]u8 = [_]u8{0} ** tls_lib.max_ciphertext_record_len,
    handshake_out_len: usize = 0,
    pending_handshake_write: bool = false,
    saved_ciphertext: [tls_lib.max_ciphertext_record_len]u8 = [_]u8{0} ** tls_lib.max_ciphertext_record_len,
    saved_ciphertext_len: usize = 0,

    const State = union(enum) {
        server: tls_lib.nonblock.Server,
        client: tls_lib.nonblock.Client,
        connected: tls_lib.nonblock.Connection,
    };

    pub fn new(config: *const TlsConfig) !TlsStream {
        if (config.is_server) {
            return TlsStream{
                .state = .{ .server = tls_lib.nonblock.Server.init(config.serverOptions()) },
            };
        } else {
            return TlsStream{
                .state = .{ .client = tls_lib.nonblock.Client.init(config.clientOptions()) },
            };
        }
    }

    pub fn free(self: *TlsStream) void {
        self.* = undefined;
    }

    pub fn handshakeAdvance(self: *TlsStream, in_data: ?[]const u8) !HandshakeStep {
        if (self.ready_cipher) |cipher| {
            if (in_data) |data| {
                if (data.len > 0 and self.saved_ciphertext_len == 0) {
                    const n = @min(data.len, self.saved_ciphertext.len);
                    @memcpy(self.saved_ciphertext[0..n], data[0..n]);
                    self.saved_ciphertext_len = n;
                }
            }
            self.state = .{ .connected = tls_lib.nonblock.Connection.init(cipher) };
            self.ready_cipher = null;
            return .done;
        }

        const in = in_data orelse &.{};

        switch (self.state) {
            .server => |*s| {
                if (s.done()) {
                    return finalizeHandshake(self, s.cipher().?, 0);
                }
                const res = s.run(in, &self.handshake_out_buf) catch return .error;
                if (s.done()) {
                    return finalizeHandshake(self, s.cipher().?, res.send.len);
                }
                self.handshake_out_len = res.send.len;
                if (res.send.len > 0) return .want_write;
                return .want_read;
            },
            .client => |*c| {
                if (c.done()) {
                    return finalizeHandshake(self, c.cipher().?, 0);
                }
                const res = c.run(in, &self.handshake_out_buf) catch return .error;
                if (c.done()) {
                    return finalizeHandshake(self, c.cipher().?, res.send.len);
                }
                self.handshake_out_len = res.send.len;
                if (res.send.len > 0) return .want_write;
                return .want_read;
            },
            .connected => return .done,
        }
    }

    fn finalizeHandshake(self: *TlsStream, cipher: tls_lib.Cipher, send_len: usize) HandshakeStep {
        if (send_len > 0) {
            self.handshake_out_len = send_len;
            self.ready_cipher = cipher;
            return .want_write;
        }
        self.state = .{ .connected = tls_lib.nonblock.Connection.init(cipher) };
        return .done;
    }

    pub fn handshakeOutput(self: *TlsStream) []const u8 {
        return self.handshake_out_buf[0..self.handshake_out_len];
    }

    pub fn read(self: *TlsStream, ciphertext: []const u8, plaintext: []u8) !usize {
        switch (self.state) {
            .connected => |*conn| {
                if (self.saved_ciphertext_len > 0) {
                    const res = conn.decrypt(self.saved_ciphertext[0..self.saved_ciphertext_len], plaintext) catch |err| {
                        return tlsErrorToReadError(err);
                    };
                    if (res.closed) return error.TlsConnectionClosed;
                    self.saved_ciphertext_len = saveUnused(self.saved_ciphertext[0..], res.unused_ciphertext);
                    if (res.cleartext.len > 0) return res.cleartext.len;
                }

                const res = conn.decrypt(ciphertext, plaintext) catch |err| {
                    return tlsErrorToReadError(err);
                };
                if (res.closed) return error.TlsConnectionClosed;
                self.saved_ciphertext_len = saveUnused(self.saved_ciphertext[0..], res.unused_ciphertext);
                return res.cleartext.len;
            },
            else => return 0,
        }
    }

    pub fn write(self: *TlsStream, plaintext: []const u8, ciphertext: []u8) !usize {
        switch (self.state) {
            .connected => |*conn| {
                const res = conn.encrypt(plaintext, ciphertext) catch return error.TlsWriteFailed;
                return res.ciphertext.len;
            },
            else => return 0,
        }
    }
};

fn saveUnused(buf: []u8, unused: []const u8) usize {
    if (unused.len == 0) return 0;
    const n = @min(unused.len, buf.len);
    @memcpy(buf[0..n], unused[0..n]);
    return n;
}

fn tlsErrorToReadError(err: anyerror) anyerror {
    if (err == error.TlsAlertCloseNotify) return error.TlsConnectionClosed;
    return error.TlsReadFailed;
}
