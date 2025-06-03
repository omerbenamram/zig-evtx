const std = @import("std");
const testing = std.testing;
const binary_parser = @import("../binary_parser.zig");
const variant_types = @import("../variant_types.zig");

// Tests for variant type parsing

test "VariantTypeNode BinXml parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const fragment = [_]u8{ 0x0F, 0x01, 0x01, 0x00, 0x00 };
    var block = binary_parser.Block.init(&fragment, 0);
    var pos: usize = 0;

    const node = try variant_types.VariantTypeNode.parseWithKnownSize(
        allocator,
        &block,
        &pos,
        0x21,
        fragment.len,
    );
    defer switch (node.data) {
        .BinXml => |data| allocator.free(data),
        else => {},
    };

    try testing.expect(node.tag == .BinXml);
    try testing.expect(node.data.BinXml.len == fragment.len);
    try testing.expect(std.mem.eql(u8, node.data.BinXml, &fragment));
    try testing.expect(pos == fragment.len);
}

test "VariantTypeNode WString parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const fragment = [_]u8{ 0x41, 0x00, 0x00, 0x00 };
    var block = binary_parser.Block.init(&fragment, 0);
    var pos: usize = 0;

    const node = try variant_types.VariantTypeNode.parseWithType(
        allocator,
        &block,
        &pos,
        0x01,
    );
    defer allocator.free(node.data.WString);

    try testing.expect(node.tag == .WString);
    try testing.expect(std.mem.eql(u8, node.data.WString, "A"));
    try testing.expect(pos == fragment.len);
}

test "VariantTypeNode String known size" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const fragment = [_]u8{ 'a', 'b', 'c' };
    var block = binary_parser.Block.init(&fragment, 0);
    var pos: usize = 0;

    const node = try variant_types.VariantTypeNode.parseWithKnownSize(
        allocator,
        &block,
        &pos,
        0x02,
        fragment.len,
    );
    defer allocator.free(node.data.String);

    try testing.expect(node.tag == .String);
    try testing.expect(std.mem.eql(u8, node.data.String, "abc"));
    try testing.expect(pos == fragment.len);
}
