const std = @import("std");
const testing = std.testing;
const binary_parser = @import("../binary_parser.zig");
const bxml_parser = @import("../bxml_parser.zig");
const evtx = @import("../evtx.zig");
const views = @import("../views.zig");
const variant_types = @import("../variant_types.zig");

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

test "Open element with attribute list size" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const fragment = [_]u8{
        0x0F, 0x01, 0x01, 0x00,
        0x41,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x06,
        0x00, 0x00, 0x00, 0x00,
        0x04, 0x2A,
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
        .attribute => {},
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

test "BXmlNode value node parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const fragment = [_]u8{ 0x05, 0x01, 0x01, 0x00, 0x41, 0x00 };
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
        // StartOfStream token and data
        0x0F, 0x01, 0x01, 0x00,
        // OpenStartElement token with has_more flag
        0x41,
        // unknown0
        0x00, 0x00,
        // size
        0x00, 0x00, 0x00, 0x00,
        // string_offset (0 -> unresolved)
        0x00, 0x00, 0x00, 0x00,
        // dependency id when has_more flag present
        0x00, 0x00, 0x00, 0x00,
        // Attribute token
        0x06,
        // attribute string_offset
        0x00, 0x00, 0x00, 0x00,
        // value: UnsignedByte 0x2A
        0x05, 0x04, 0x2A,
        // CloseStartElement, CloseElement, EndOfStream
        0x02, 0x04,
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
            switch (attr.value_node.*) {
                .value => |val| {
                    try testing.expect(val.value_type == 0x04);
                    try testing.expect(val.value_data.data.UnsignedByte == 0x2A);
                },
                else => try testing.expect(false),
            }
            allocator.destroy(attr.value_node);
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
        0x12,
        0x34,
        0x56,
        0x78,
        0x9A,
        0xBC,
        0xDE,
        0xF0,
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

test "NameNode resolves table and inline strings" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Build minimal chunk with one string in table and one inline string
    var chunk_buf = [_]u8{0} ** 0x400;
    const magic = "ElfChnk\x00";
    @memcpy(chunk_buf[0..8], magic);
    std.mem.writeInt(u32, chunk_buf[0x28..0x2C], 0x80, .little); // header_size
    std.mem.writeInt(u32, chunk_buf[0x2C..0x30], 0x350, .little); // last_record_offset
    std.mem.writeInt(u32, chunk_buf[0x30..0x34], 0x350, .little); // next_record_offset

    // String table entry at bucket 0
    const table_offset: u32 = 0x250;
    std.mem.writeInt(u32, chunk_buf[0x80..0x84], table_offset, .little);
    const table_str = "Elem";
    std.mem.writeInt(u32, chunk_buf[table_offset .. table_offset + 4], 0, .little); // next
    std.mem.writeInt(u16, chunk_buf[table_offset + 4 .. table_offset + 6], 0, .little); // hash
    std.mem.writeInt(u16, chunk_buf[table_offset + 6 .. table_offset + 8], table_str.len, .little);
    for (table_str, 0..) |ch, i| {
        const slice = chunk_buf[table_offset + 8 + i * 2 .. table_offset + 8 + i * 2 + 2];
        std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(slice.ptr)), ch, .little);
    }

    // Inline string not referenced by table
    const inline_offset: u32 = 0x300;
    const inline_str = "Inl";
    std.mem.writeInt(u32, chunk_buf[inline_offset .. inline_offset + 4], 0, .little);
    std.mem.writeInt(u16, chunk_buf[inline_offset + 4 .. inline_offset + 6], 0, .little);
    std.mem.writeInt(u16, chunk_buf[inline_offset + 6 .. inline_offset + 8], inline_str.len, .little);
    for (inline_str, 0..) |ch, i| {
        const slice = chunk_buf[inline_offset + 8 + i * 2 .. inline_offset + 8 + i * 2 + 2];
        std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(slice.ptr)), ch, .little);
    }

    var chunk = try evtx.ChunkHeader.init(allocator, &chunk_buf, 0);
    defer chunk.deinit();

    // Fragment referencing table string
    const frag_table = [_]u8{
        0x0F, 0x01, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x50,
        0x02, 0x00, 0x00, 0x02,
        0x04, 0x00,
    };
    var block = binary_parser.Block.init(&frag_table, 0);
    var pos: usize = 0;
    _ = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null); // StartOfStream
    const node_table = try bxml_parser.BXmlNode.parse(allocator, &block, &pos, null);
    switch (node_table) {
        .open_start_element => |ose| {
            const str_opt = try chunk.getStringAtOffset(ose.name.string_offset.?);
            var actual: []const u8 = undefined;
            var must_free = false;
            if (str_opt) |s| {
                actual = s;
            } else {
                const len = try chunk.block.unpackWord(ose.name.string_offset.? + 6);
                actual = try chunk.block.unpackWstring(allocator, ose.name.string_offset.? + 8, len);
                must_free = true;
            }
            defer if (must_free) allocator.free(actual);
            try testing.expect(std.mem.eql(u8, actual, table_str));
        },
        else => try testing.expect(false),
    }

    // Fragment referencing inline string
    const frag_inline = [_]u8{
        0x0F, 0x01, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x02,
        0x04, 0x00,
    };
    var block2 = binary_parser.Block.init(&frag_inline, 0);
    var pos2: usize = 0;
    _ = try bxml_parser.BXmlNode.parse(allocator, &block2, &pos2, null);
    const node_inline = try bxml_parser.BXmlNode.parse(allocator, &block2, &pos2, null);
    switch (node_inline) {
        .open_start_element => |ose| {
            const str_opt = try chunk.getStringAtOffset(ose.name.string_offset.?);
            var actual2: []const u8 = undefined;
            var must_free2 = false;
            if (str_opt) |s| {
                actual2 = s;
            } else {
                const len = try chunk.block.unpackWord(ose.name.string_offset.? + 6);
                actual2 = try chunk.block.unpackWstring(allocator, ose.name.string_offset.? + 8, len);
                must_free2 = true;
            }
            defer if (must_free2) allocator.free(actual2);
            try testing.expect(std.mem.eql(u8, actual2, inline_str));
        },
        else => try testing.expect(false),
    }
}

test "ValueNode toXml escaping" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const val_node = bxml_parser.ValueNode{
        .value_type = 0x01,
        .value_data = variant_types.VariantTypeNode{
            .tag = .WString,
            .data = .{ .WString = try allocator.dupe(u8, "<foo>&\"") },
        },
    };
    defer allocator.free(val_node.value_data.data.WString);

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    try val_node.toXml(allocator, buf.writer());

    try testing.expectEqualStrings("&lt;foo&gt;&amp;&quot;", buf.items);
}

test "AttributeNode toXml output" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const value_node = try allocator.create(bxml_parser.BXmlNode);
    value_node.* = .{ .value = bxml_parser.ValueNode{
        .value_type = 0x01,
        .value_data = variant_types.VariantTypeNode{
            .tag = .WString,
            .data = .{ .WString = try allocator.dupe(u8, "bar") },
        },
    } };
    const str_ptr = value_node.value.value_data.data.WString;
    defer allocator.destroy(value_node);
    defer allocator.free(str_ptr);

    var attr = bxml_parser.AttributeNode{
        .name = .{ .string_offset = null, .string = "test" },
        .value_node = value_node,
    };

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    try attr.toXml(allocator, buf.writer());

    try testing.expectEqualStrings(" test=\"bar\"", buf.items);
}

test "CharRefNode toXml" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const node = bxml_parser.CharRefNode{ .value = 0x41 };

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try node.toXml(allocator, buf.writer());

    try testing.expectEqualStrings("&#x0041;", buf.items);
}

test "EntityReferenceNode toXml" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const node = bxml_parser.EntityReferenceNode{ .name = "nbsp" };

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try node.toXml(allocator, buf.writer());

    try testing.expectEqualStrings("&nbsp;", buf.items);
}

test "CDataSectionNode toXml" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const node = bxml_parser.CDataSectionNode{ .text = "some" };

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try node.toXml(allocator, buf.writer());

    try testing.expectEqualStrings("<![CDATA[some]]>", buf.items);
}
