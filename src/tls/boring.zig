const std = @import("std");

pub const SSL_CTX = opaque {};
pub const SSL = opaque {};
pub const BIO = opaque {};
pub const BIO_METHOD = opaque {};
pub const X509 = opaque {};
pub const EVP_PKEY = opaque {};

pub const SSL_VERIFY_NONE: i32 = 0;
pub const SSL_VERIFY_PEER: i32 = 1;

pub const SSL_ERROR_NONE: i32 = 0;
pub const SSL_ERROR_SSL: i32 = 1;
pub const SSL_ERROR_WANT_READ: i32 = 2;
pub const SSL_ERROR_WANT_WRITE: i32 = 3;
pub const SSL_ERROR_SYSCALL: i32 = 5;
pub const SSL_ERROR_ZERO_RETURN: i32 = 6;

pub const SSL_OP_NO_RENEGOTIATION: u64 = 0x40000000;
pub const SSL_OP_NO_SSLv3: u64 = 0x02000000;
pub const SSL_OP_NO_TLSv1: u64 = 0x04000000;
pub const SSL_OP_NO_TLSv1_1: u64 = 0x10000000;

pub const TLS1_2_VERSION: i32 = 0x0303;
pub const TLS1_3_VERSION: i32 = 0x0304;

pub const SSL_FILETYPE_PEM: i32 = 1;

pub extern fn SSL_CTX_new(method: ?*const SSL_METHOD) callconv(.c) ?*SSL_CTX;
pub extern fn SSL_CTX_free(ctx: *SSL_CTX) callconv(.c) void;
pub extern fn SSL_CTX_set_min_proto_version(ctx: *SSL_CTX, version: i32) callconv(.c) i32;
pub extern fn SSL_CTX_set_max_proto_version(ctx: *SSL_CTX, version: i32) callconv(.c) i32;
pub extern fn SSL_CTX_set_options(ctx: *SSL_CTX, options: u64) callconv(.c) u64;
pub extern fn SSL_CTX_use_certificate_file(ctx: *SSL_CTX, file: [*:0]const u8, type_: i32) callconv(.c) i32;
pub extern fn SSL_CTX_use_PrivateKey_file(ctx: *SSL_CTX, file: [*:0]const u8, type_: i32) callconv(.c) i32;

pub extern fn SSL_new(ctx: *SSL_CTX) callconv(.c) ?*SSL;
pub extern fn SSL_free(ssl: *SSL) callconv(.c) void;
pub extern fn SSL_set_accept_state(ssl: *SSL) callconv(.c) void;
pub extern fn SSL_set_connect_state(ssl: *SSL) callconv(.c) void;
pub extern fn SSL_set_bio(ssl: *SSL, rbio: ?*BIO, wbio: ?*BIO) callconv(.c) void;
pub extern fn SSL_do_handshake(ssl: *SSL) callconv(.c) i32;
pub extern fn SSL_read(ssl: *SSL, buf: [*]u8, num: i32) callconv(.c) i32;
pub extern fn SSL_write(ssl: *SSL, buf: [*]const u8, num: i32) callconv(.c) i32;
pub extern fn SSL_get_error(ssl: *SSL, ret: i32) callconv(.c) i32;
pub extern fn SSL_set_options(ssl: *SSL, options: u64) callconv(.c) u64;

pub extern fn BIO_s_mem() callconv(.c) ?*const BIO_METHOD;
pub extern fn BIO_new(method: *const BIO_METHOD) callconv(.c) ?*BIO;
pub extern fn BIO_free(bio: *BIO) callconv(.c) i32;
pub extern fn BIO_read(bio: *BIO, buf: [*]u8, len: i32) callconv(.c) i32;
pub extern fn BIO_write(bio: *BIO, buf: [*]const u8, len: i32) callconv(.c) i32;
pub extern fn BIO_ctrl_pending(bio: *BIO) callconv(.c) usize;

pub extern fn TLS_method() callconv(.c) ?*const SSL_METHOD;
pub extern fn TLS_server_method() callconv(.c) ?*const SSL_METHOD;
pub extern fn TLS_client_method() callconv(.c) ?*const SSL_METHOD;

pub const SSL_METHOD = opaque {};
