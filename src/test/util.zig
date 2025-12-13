//! Test utilities shared across test files.

const std = @import("std");

/// Get project root from a source file path at comptime.
/// Handles both absolute paths (with /src/) and relative paths (from build.zig).
///
/// Usage: `const project_root = comptime getProjectRoot(@src().file);`
pub fn getProjectRoot(comptime src_path: []const u8) []const u8 {
    // Try to find "/src/" for absolute paths
    const marker = "/src/";
    if (src_path.len >= marker.len) {
        for (0..src_path.len - marker.len + 1) |i| {
            if (std.mem.eql(u8, src_path[i..][0..marker.len], marker)) {
                return src_path[0..i];
            }
        }
    }
    // Relative path from build.zig (e.g., "test/util.zig", "parser/evtx/worker.zig")
    // Tests run from project root, so just use "."
    return ".";
}

test "getProjectRoot with absolute path" {
    const abs = "/Users/foo/zig-evtx/src/test/util.zig";
    const root = comptime getProjectRoot(abs);
    try std.testing.expectEqualStrings("/Users/foo/zig-evtx", root);
}

test "getProjectRoot with relative path" {
    const rel = "test/util.zig";
    const root = comptime getProjectRoot(rel);
    try std.testing.expectEqualStrings(".", root);
}
