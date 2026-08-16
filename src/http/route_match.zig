//! Pure route-pattern matching (no io_uring/AsyncServer/context dependency),
//! so it is unit-testable on the host via `zig test`.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Segment = union(enum) {
    literal: []const u8,
    param: []const u8,
    wildcard: void,
};

/// A captured path parameter. Owned by the caller; `name` points into the
/// route's segment storage, `value` into the request path.
pub const RouteParam = struct {
    name: []const u8,
    value: []const u8,
};

/// Maximum path parameters captured per route match.
pub const MAX_PARAMS: usize = 16;

pub fn parseParamPattern(allocator: Allocator, pattern: []const u8) ![]const Segment {
    var segments = std.ArrayList(Segment).empty;
    errdefer {
        for (segments.items) |seg| {
            if (seg == .literal or seg == .param) {
                allocator.free(@as([]const u8, switch (seg) {
                    .literal => |lit| lit,
                    .param => |p| p,
                    .wildcard => unreachable,
                }));
            }
        }
        segments.deinit(allocator);
    }

    var iter = std.mem.splitScalar(u8, pattern, '/');
    while (iter.next()) |part| {
        if (part.len == 0) continue;
        if (std.mem.eql(u8, part, "*")) {
            try segments.append(allocator, .wildcard);
        } else if (part[0] == ':') {
            const name = try allocator.dupe(u8, part[1..]);
            try segments.append(allocator, .{ .param = name });
        } else {
            const lit = try allocator.dupe(u8, part);
            try segments.append(allocator, .{ .literal = lit });
        }
    }
    return segments.toOwnedSlice(allocator);
}

pub fn freeSegments(allocator: Allocator, segments: []const Segment) void {
    for (segments) |seg| {
        if (seg == .literal) allocator.free(seg.literal);
        if (seg == .param) allocator.free(seg.param);
    }
    allocator.free(segments);
}

pub fn matchParamRoute(segments: []const Segment, path: []const u8, params: *[MAX_PARAMS]RouteParam) ?usize {
    var path_iter = std.mem.splitScalar(u8, path, '/');
    var param_idx: usize = 0;
    var seg_idx: usize = 0;

    while (path_iter.next()) |part| {
        if (part.len == 0) continue;
        if (seg_idx >= segments.len) return null;

        const segment = segments[seg_idx];
        switch (segment) {
            .literal => |lit| {
                if (!std.mem.eql(u8, lit, part)) return null;
            },
            .param => |name| {
                if (param_idx < params.len) {
                    params[param_idx] = .{ .name = name, .value = part };
                    param_idx += 1;
                } else {
                    return null;
                }
            },
            .wildcard => {
                return param_idx;
            },
        }
        seg_idx += 1;
    }

    return if (seg_idx == segments.len) param_idx else null;
}

test "parseParamPattern handles mixed literal and param segments" {
    const allocator = std.testing.allocator;
    const segments = try parseParamPattern(allocator, "/users/:id/posts/:postId");
    defer freeSegments(allocator, segments);

    try std.testing.expectEqual(@as(usize, 4), segments.len);
    try std.testing.expect(segments[0] == .literal);
    try std.testing.expectEqualStrings("users", segments[0].literal);
    try std.testing.expect(segments[1] == .param);
    try std.testing.expectEqualStrings("id", segments[1].param);
    try std.testing.expect(segments[2] == .literal);
    try std.testing.expectEqualStrings("posts", segments[2].literal);
    try std.testing.expect(segments[3] == .param);
    try std.testing.expectEqualStrings("postId", segments[3].param);
}

test "parseParamPattern handles wildcard" {
    const allocator = std.testing.allocator;
    const segments = try parseParamPattern(allocator, "/static/*");
    defer freeSegments(allocator, segments);

    try std.testing.expectEqual(@as(usize, 2), segments.len);
    try std.testing.expect(segments[0] == .literal);
    try std.testing.expectEqualStrings("static", segments[0].literal);
    try std.testing.expect(segments[1] == .wildcard);
}

test "matchParamRoute extracts single and multiple params" {
    const allocator = std.testing.allocator;
    const segments = try parseParamPattern(allocator, "/users/:userId/posts/:postId");
    defer freeSegments(allocator, segments);

    var params_buf: [MAX_PARAMS]RouteParam = undefined;

    const count = matchParamRoute(segments, "/users/42/posts/99", &params_buf);
    try std.testing.expect(count != null);
    try std.testing.expectEqual(@as(usize, 2), count.?);
    try std.testing.expectEqualStrings("userId", params_buf[0].name);
    try std.testing.expectEqualStrings("42", params_buf[0].value);
    try std.testing.expectEqualStrings("postId", params_buf[1].name);
    try std.testing.expectEqualStrings("99", params_buf[1].value);
}

test "matchParamRoute returns null on mismatch" {
    const allocator = std.testing.allocator;
    const segments = try parseParamPattern(allocator, "/users/:id");
    defer freeSegments(allocator, segments);

    var params_buf: [MAX_PARAMS]RouteParam = undefined;

    try std.testing.expect(matchParamRoute(segments, "/posts/42", &params_buf) == null);
    try std.testing.expect(matchParamRoute(segments, "/users/42/extra", &params_buf) == null);
    try std.testing.expect(matchParamRoute(segments, "/users", &params_buf) == null);
}
