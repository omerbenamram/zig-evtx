const std = @import("std");
const testing = std.testing;
const evtx = @import("../evtx.zig");

// Regression test documenting the template parsing progress.
// Template 3346188909 originally produced only five nodes. After
// fixing stream handling the parser should yield significantly more
// nodes, though still fewer than the Python implementation.

test "Template 3346188909 parses more than 5 nodes" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var parser = evtx.Evtx.init(allocator);
    defer parser.deinit();

    try parser.open("tests/data/security.evtx");

    var chunk_iter = parser.chunks();
    const chunk = chunk_iter.next() orelse return error.TestUnexpected;
    var chunk_mut = chunk;

    try chunk_mut.loadTemplates();
    const tmpl_opt = try chunk_mut.getTemplate(3346188909);
    try testing.expect(tmpl_opt != null);
    const tmpl = tmpl_opt.?;

    // Ensure we parse more than five nodes after fixing stream handling.
    try testing.expect(tmpl.structure.nodes.len > 5);
    std.log.debug("Node count: {d}", .{tmpl.structure.nodes.len});
}
