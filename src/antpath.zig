const std = @import("std");
const Allocator = std.mem.Allocator;

// ==========================================
// 2. AntPath path matching
// ==========================================

pub const PathRule = struct {
    pattern: []const u8,
    allocator: Allocator,
    segments: [][]const u8,

    pub fn init(allocator: Allocator, pattern: []const u8) !PathRule {
        const pattern_dupe = try allocator.dupe(u8, pattern);
        errdefer allocator.free(pattern_dupe);

        const ArrayListM = std.array_list.Managed([]const u8);
        var seg_list = ArrayListM.init(allocator);
        defer seg_list.deinit();
        var it = std.mem.splitScalar(u8, pattern_dupe, '/');
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            try seg_list.append(seg);
        }
        const segments = try seg_list.toOwnedSlice();
        return .{
            .pattern = pattern_dupe,
            .allocator = allocator,
            .segments = segments,
        };
    }

    pub fn deinit(self: *PathRule) void {
        self.allocator.free(self.segments);
        self.allocator.free(@constCast(self.pattern));
    }

    pub fn match(self: *const PathRule, path: []const u8) bool {
        var segments_buf: [64][]const u8 = undefined;
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, path, '/');
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            if (count >= segments_buf.len) return false;
            segments_buf[count] = seg;
            count += 1;
        }
        return matchSegments(self.segments, segments_buf[0..count], 0, 0, 0);
    }

    fn matchSegments(pattern: []const []const u8, path: []const []const u8, pi: usize, si: usize, depth: u8) bool {
        if (depth > 16) return false;
        var p_idx = pi;
        var s_idx = si;
        while (p_idx < pattern.len and s_idx < path.len) {
            const p = pattern[p_idx];
            if (std.mem.eql(u8, p, "**")) {
                var next_s = s_idx;
                while (next_s <= path.len) : (next_s += 1) {
                    if (matchSegments(pattern, path, p_idx + 1, next_s, depth + 1)) return true;
                    if (next_s >= path.len) break;
                }
                return false;
            }
            if (std.mem.eql(u8, p, "*")) {
                s_idx += 1;
                p_idx += 1;
                continue;
            }
            if (!std.mem.eql(u8, p, path[s_idx])) return false;
            p_idx += 1;
            s_idx += 1;
        }
        while (p_idx < pattern.len and std.mem.eql(u8, pattern[p_idx], "**")) {
            p_idx += 1;
        }
        return p_idx == pattern.len and s_idx == path.len;
    }
};
