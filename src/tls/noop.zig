const std = @import("std");

pub const TlsTimestamp = std.Io.Timestamp;
pub const TlsRandom = std.Random;

pub const max_ciphertext_record_len = 16645;
pub const input_buffer_len = 16645;
pub const output_buffer_len = 16469;

pub const Cipher = struct {};

const CertKeyPairType = struct {
    pub fn fromFilePathAbsolute(_: anytype, _: anytype, _: []const u8, _: []const u8) !@This() {
        return .{};
    }
    pub fn deinit(_: *@This(), _: anytype) void {}
};
pub const CertKeyPair = CertKeyPairType;

pub const config = struct {
    pub const CertKeyPair = CertKeyPairType;

    pub const cert = struct {
        pub const Bundle = struct {
            pub const empty: @This() = .{};
            pub fn deinit(_: *@This(), _: anytype) void {}
        };
    };

    pub const Server = struct {
        rng: TlsRandom,
        auth: ?*CertKeyPair = null,
        now: TlsTimestamp = .{ .seconds = 0, .nanos = 0 },
    };

    pub const Client = struct {
        rng: TlsRandom,
        now: TlsTimestamp = .{ .seconds = 0, .nanos = 0 },
        host: []const u8 = "localhost",
        root_ca: config.cert.Bundle = .empty,
        insecure_skip_verify: bool = true,
    };
};

pub const nonblock = struct {
    pub const Server = struct {
        pub fn init(_: config.Server) !@This() {
            return .{};
        }
        pub fn run(_: *@This(), _: []const u8, _: []u8) !struct {
            recv_pos: usize = 0,
            send_pos: usize = 0,
            unused_recv: []const u8 = &.{},
            send: []const u8 = &.{},
        } {
            return .{};
        }
        pub fn done(_: *const @This()) bool {
            return true;
        }
        pub fn cipher(_: *@This()) ?Cipher {
            return Cipher{};
        }
    };

    pub const Client = struct {
        pub fn init(_: config.Client) !@This() {
            return .{};
        }
        pub fn run(_: *@This(), _: []const u8, _: []u8) !struct {
            recv_pos: usize = 0,
            send_pos: usize = 0,
            unused_recv: []const u8 = &.{},
            send: []const u8 = &.{},
        } {
            return .{};
        }
        pub fn done(_: *const @This()) bool {
            return true;
        }
        pub fn cipher(_: *@This()) ?Cipher {
            return Cipher{};
        }
    };

    pub const Connection = struct {
        pub fn init(_: Cipher) @This() {
            return .{};
        }
        pub fn encrypt(_: *@This(), _: []const u8, _: []u8) !struct {
            cleartext_pos: usize = 0,
            unused_cleartext: []const u8 = &.{},
            ciphertext: []const u8 = &.{},
        } {
            return .{};
        }
        pub fn decrypt(_: *@This(), _: []const u8, _: []u8) !struct {
            ciphertext_pos: usize = 0,
            unused_ciphertext: []const u8 = &.{},
            cleartext: []const u8 = &.{},
            closed: bool = false,
        } {
            return .{};
        }
    };
};
