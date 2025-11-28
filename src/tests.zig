const std = @import("std");

// Aggregate tests from submodules. Using imports inside a test block ensures
// Zig resolves those modules (and their test declarations) in 0.14.
test "aggregate module tests" {
    _ = @import("parser/util.zig");
    _ = @import("parser/util_simd_test.zig");
    _ = @import("parser/render_json.zig");
    _ = @import("parser/render_xml.zig");
    _ = @import("parser/reader.zig");
    _ = @import("parser/evtx/mod.zig");
    _ = @import("parser/value_format.zig");
    _ = @import("parser/binxml/value_reader.zig");
    try std.testing.expect(true);
}
