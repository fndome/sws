const std = @import("std");
const boring = @import("boring.zig");

pub const HandshakeStep = enum {
    want_read,
    want_write,
    done,
    error,
};

pub const TlsConfig = struct {
    ctx: *boring.SSL_CTX,
    is_server: bool,

    pub fn init(cert_path: ?[:0]const u8, key_path: ?[:0]const u8, is_server: bool) !TlsConfig {
        const method = if (is_server)
            boring.TLS_server_method()
        else
            boring.TLS_client_method();
        const ctx = boring.SSL_CTX_new(method) orelse return error.TlsInitFailed;
        errdefer boring.SSL_CTX_free(ctx);

        _ = boring.SSL_CTX_set_min_proto_version(ctx, boring.TLS1_2_VERSION);
        _ = boring.SSL_CTX_set_max_proto_version(ctx, boring.TLS1_3_VERSION);
        _ = boring.SSL_CTX_set_options(ctx, boring.SSL_OP_NO_SSLv3 | boring.SSL_OP_NO_TLSv1 | boring.SSL_OP_NO_TLSv1_1);

        if (is_server) {
            if (cert_path) |cert| {
                if (boring.SSL_CTX_use_certificate_file(ctx, cert, boring.SSL_FILETYPE_PEM) != 1) {
                    return error.CertificateLoadFailed;
                }
            }
            if (key_path) |key| {
                if (boring.SSL_CTX_use_PrivateKey_file(ctx, key, boring.SSL_FILETYPE_PEM) != 1) {
                    return error.PrivateKeyLoadFailed;
                }
            }
        }

        return TlsConfig{ .ctx = ctx, .is_server = is_server };
    }

    pub fn deinit(self: *TlsConfig) void {
        boring.SSL_CTX_free(self.ctx);
        self.ctx = undefined;
    }
};

pub const TlsStream = struct {
    ssl: *boring.SSL,
    in_bio: *boring.BIO,
    out_bio: *boring.BIO,
    handshake_out_buf: [16384]u8 = [_]u8{0} ** 16384,
    handshake_out_len: usize = 0,
    pending_handshake_write: bool = false,

    pub fn new(config: *const TlsConfig) !TlsStream {
        const ssl = boring.SSL_new(config.ctx) orelse return error.TlsStreamNewFailed;
        errdefer boring.SSL_free(ssl);

        _ = boring.SSL_set_options(ssl, boring.SSL_OP_NO_RENEGOTIATION);

        if (config.is_server) {
            boring.SSL_set_accept_state(ssl);
        } else {
            boring.SSL_set_connect_state(ssl);
        }

        const in_bio = boring.BIO_new(boring.BIO_s_mem().?) orelse {
            boring.SSL_free(ssl);
            return error.BioNewFailed;
        };
        const out_bio = boring.BIO_new(boring.BIO_s_mem().?) orelse {
            boring.BIO_free(in_bio);
            boring.SSL_free(ssl);
            return error.BioNewFailed;
        };

        boring.SSL_set_bio(ssl, in_bio, out_bio);

        return TlsStream{
            .ssl = ssl,
            .in_bio = in_bio,
            .out_bio = out_bio,
        };
    }

    pub fn free(self: *TlsStream) void {
        boring.SSL_free(self.ssl);
        self.ssl = undefined;
        self.in_bio = undefined;
        self.out_bio = undefined;
    }

    pub fn handshakeAdvance(self: *TlsStream, in_data: ?[]const u8) !HandshakeStep {
        if (in_data) |data| {
            if (data.len > 0) {
                const write_len: i32 = @intCast(data.len);
                const written = boring.BIO_write(self.in_bio, data.ptr, write_len);
                if (written != write_len) return error.TlsBioError;
            }
        }

        self.handshake_out_len = 0;
        self.pending_handshake_write = false;

        while (true) {
            const ret = boring.SSL_do_handshake(self.ssl);
            if (ret == 1) return .done;

            const err = boring.SSL_get_error(self.ssl, ret);
            switch (err) {
                boring.SSL_ERROR_WANT_READ => {
                    const pending = boring.BIO_ctrl_pending(self.out_bio);
                    if (pending > 0) {
                        self.handshake_out_len = pending;
                        return .want_write;
                    }
                    return .want_read;
                },
                boring.SSL_ERROR_WANT_WRITE => {
                    const pending = boring.BIO_ctrl_pending(self.out_bio);
                    self.handshake_out_len = if (pending <= self.handshake_out_buf.len) pending else self.handshake_out_buf.len;
                    self.pending_handshake_write = true;
                    return .want_write;
                },
                else => return error.TlsHandshakeFailed,
            }
        }
    }

    pub fn handshakeOutput(self: *TlsStream) []const u8 {
        if (self.handshake_out_len == 0) return &.{};
        const read_len: i32 = @intCast(@min(self.handshake_out_len, self.handshake_out_buf.len));
        const n = boring.BIO_read(self.out_bio, &self.handshake_out_buf, read_len);
        if (n <= 0) {
            self.handshake_out_len = 0;
            return &.{};
        }
        self.handshake_out_len = @intCast(n);
        return self.handshake_out_buf[0..@intCast(n)];
    }

    pub fn read(self: *TlsStream, ciphertext: []const u8, plaintext: []u8) !usize {
        if (ciphertext.len > 0) {
            const write_len: i32 = @intCast(ciphertext.len);
            const written = boring.BIO_write(self.in_bio, ciphertext.ptr, write_len);
            if (written != write_len) return error.TlsBioError;
        }

        const read_len: i32 = @intCast(plaintext.len);
        const ret = boring.SSL_read(self.ssl, plaintext.ptr, read_len);
        if (ret <= 0) {
            const err = boring.SSL_get_error(self.ssl, ret);
            switch (err) {
                boring.SSL_ERROR_WANT_READ => return 0,
                boring.SSL_ERROR_WANT_WRITE => return 0,
                boring.SSL_ERROR_ZERO_RETURN => return error.TlsConnectionClosed,
                else => return error.TlsReadFailed,
            }
        }
        return @intCast(ret);
    }

    pub fn write(self: *TlsStream, plaintext: []const u8, ciphertext: []u8) !usize {
        const write_len: i32 = @intCast(plaintext.len);
        const ret = boring.SSL_write(self.ssl, plaintext.ptr, write_len);
        if (ret <= 0) {
            const err = boring.SSL_get_error(self.ssl, ret);
            switch (err) {
                boring.SSL_ERROR_WANT_READ => return 0,
                boring.SSL_ERROR_WANT_WRITE => return 0,
                boring.SSL_ERROR_ZERO_RETURN => return error.TlsConnectionClosed,
                else => return error.TlsWriteFailed,
            }
        }

        const pending = boring.BIO_ctrl_pending(self.out_bio);
        const to_read: i32 = @intCast(@min(pending, ciphertext.len));
        const n = boring.BIO_read(self.out_bio, ciphertext.ptr, to_read);
        if (n <= 0) {
            return 0;
        }
        return @intCast(n);
    }
};
