const std = @import("std");
const testing = std.testing;
const binary_parser = @import("../binary_parser.zig");
const bxml_parser = @import("../bxml_parser.zig");

// Tests for BXmlNode parsing

test "BXmlNode simple fragment parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const fragment = [_]u8{ 0x0F, 0x01, 0x01, 0x00, 0x00 };
    var block = binary_parser.Block.init(&fragment, 0);
    var pos: usize = 0;

    const node1 = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node1) {
        .start_of_stream => {},
        else => try testing.expect(false),
    }

    const node2 = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node2) {
        .end_of_stream => {},
        else => try testing.expect(false),
    }

    try testing.expect(pos == fragment.len);
}

test "BXmlNode value node parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const fragment = [_]u8{ 0x05, 0x01, 0x41, 0x00, 0x00, 0x00 };
    var block = binary_parser.Block.init(&fragment, 0);
    var pos: usize = 0;

    const node = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node) {
        .value => |val| {
            defer allocator.free(val.value_data.data.WString);
            try testing.expect(val.value_type == 0x01);
            try testing.expect(std.mem.eql(u8, val.value_data.data.WString, "A"));
        },
        else => try testing.expect(false),
    }

    try testing.expect(pos == fragment.len);
}

test "BXmlNode open element with attribute" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const fragment = [_]u8{
        0x0F, 0x01, 0x01, 0x00,
        0x41,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x06,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x04,
        0x2A,
        0x02,
        0x04,
        0x00,
    };
    var block = binary_parser.Block.init(&fragment, 0);
    var pos: usize = 0;

    var node = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node) {
        .start_of_stream => {},
        else => try testing.expect(false),
    }

    node = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node) {
        .open_start_element => |ose| {
            try testing.expect(ose.has_more);
        },
        else => try testing.expect(false),
    }

    node = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node) {
        .attribute => |attr| {
            try testing.expect(attr.value_data.tag == .UnsignedByte);
            try testing.expect(attr.value_data.data.UnsignedByte == 0x2A);
        },
        else => try testing.expect(false),
    }

    node = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node) {
        .close_start_element => {},
        else => try testing.expect(false),
    }

    node = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node) {
        .close_element => {},
        else => try testing.expect(false),
    }

    node = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node) {
        .end_of_stream => {},
        else => try testing.expect(false),
    }

    try testing.expect(pos == fragment.len);
}

test "BXmlNode template instance parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const fragment = [_]u8{
        0x0C,
        0xAA,
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0,
    };
    var block = binary_parser.Block.init(&fragment, 0);
    var pos: usize = 0;

    const node = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node) {
        .template_instance => |ti| {
            try testing.expect(ti.unknown0 == 0xAA);
            try testing.expect(ti.template_id == 0x78563412);
            try testing.expect(ti.template_offset == 0xF0DEBC9A);
        },
        else => try testing.expect(false),
    }

    try testing.expect(pos == fragment.len);
}

test "BXmlNode normal substitution parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const fragment = [_]u8{ 0x0D, 0x34, 0x12, 0x04, 0x00 };
    var block = binary_parser.Block.init(&fragment, 0);
    var pos: usize = 0;

    const node = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node) {
        .normal_substitution => |sub| {
            try testing.expect(sub.index == 0x1234);
            try testing.expect(sub.value_type == 0x04);
            try testing.expect(!sub.is_conditional);
        },
        else => try testing.expect(false),
    }

    try testing.expect(pos == fragment.len);
}
