const std = @import("std");

// Import all test modules
const binary_parser_tests = @import("binary_parser.zig");
const nodes_tests = @import("nodes.zig");
const evtx_tests = @import("evtx.zig");
const views_tests = @import("views.zig");

test {
    // Reference all test modules to include their tests
    std.testing.refAllDecls(binary_parser_tests);
    std.testing.refAllDecls(nodes_tests);
    std.testing.refAllDecls(evtx_tests);
    std.testing.refAllDecls(views_tests);
}
