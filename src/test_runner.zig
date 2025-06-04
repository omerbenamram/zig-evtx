const std = @import("std");

// Import all test modules
const binary_parser_tests = @import("binary_parser.zig");
const evtx_tests = @import("evtx.zig");
const views_tests = @import("views.zig");
const evtx_parsing_tests = @import("tests/test_evtx_parsing.zig");
const variant_type_tests = @import("tests/test_variant_types.zig");
const bxml_node_tests = @import("tests/test_bxml_nodes.zig");

test {
    // Reference all test modules to include their tests
    std.testing.refAllDecls(binary_parser_tests);
    std.testing.refAllDecls(evtx_tests);
    std.testing.refAllDecls(views_tests);
    std.testing.refAllDecls(evtx_parsing_tests);
    std.testing.refAllDecls(variant_type_tests);
    std.testing.refAllDecls(bxml_node_tests);
}
