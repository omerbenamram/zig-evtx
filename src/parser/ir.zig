const std = @import("std");

const TemplateValue = @import("binxml/types.zig").TemplateValue;
const utf16EqualsAscii = @import("util.zig").utf16EqualsAscii;

pub const IR = struct {
    pub const Name = union(enum) {
        NameOffset: u32,
        InlineUtf16: struct { bytes: []const u8, num_chars: usize },
    };

    pub const NodeTag = enum { Element, Text, Value, Subst, CharRef, EntityRef, CData, Pad, PITarget, PIData };

    pub const Node = struct {
        tag: NodeTag,
        elem: ?*Element = null,
        text_utf16: []const u8 = &[_]u8{},
        text_num_chars: usize = 0,
        vtype: u8 = 0,
        vbytes: []const u8 = &[_]u8{},
        subst_id: u16 = 0,
        subst_vtype: u8 = 0,
        subst_optional: bool = false,
        charref_value: u16 = 0,
        entity_name: Name = Name{ .NameOffset = 0 },
        pad_width: usize = 0,
        // PI
        pi_target: Name = Name{ .NameOffset = 0 },
    };

    pub const Attr = struct {
        name: Name,
        // Flat token list allowed in attribute contexts
        value: std.ArrayList(Node),
    };

    pub const Element = struct {
        name: Name,
        attrs: std.ArrayList(Attr),
        children: std.ArrayList(Node),
        // Optional nested template instance values that apply to this element subtree
        local_values: []const TemplateValue = &[_]TemplateValue{},
        // Render hints computed during IR build
        has_element_child: bool = false,
        has_evtxml_value_in_tree: bool = false,
        has_evtxml_subst_in_tree: bool = false,
        has_attr_evtxml_value: bool = false,
        has_attr_evtxml_subst: bool = false,
    };
};

pub fn irNewElement(allocator: std.mem.Allocator, name: IR.Name) !*IR.Element {
    const el = try allocator.create(IR.Element);
    el.* = .{ .name = name, .attrs = std.ArrayList(IR.Attr).init(allocator), .children = std.ArrayList(IR.Node).init(allocator), .local_values = &[_]TemplateValue{} };
    return el;
}

pub fn irPushText(list: *std.ArrayList(IR.Node), utf16: []const u8, num_chars: usize) !void {
    try list.append(.{ .tag = .Text, .text_utf16 = utf16, .text_num_chars = num_chars });
}

pub fn irPushPad2(list: *std.ArrayList(IR.Node)) !void {
    try list.append(.{ .tag = .Pad, .pad_width = 2 });
}

pub fn nameEqualsAscii(chunk: []const u8, name: IR.Name, ascii: []const u8) bool {
    switch (name) {
        .NameOffset => |off| {
            const o: usize = @intCast(off);
            if (o + 8 > chunk.len) return false;
            const num_chars = std.mem.readInt(u16, chunk[o + 6 .. o + 8][0..2], .little);
            const str_start = o + 8;
            const byte_len = @as(usize, num_chars) * 2;
            if (str_start + byte_len > chunk.len) return false;
            return utf16EqualsAscii(chunk[str_start .. str_start + byte_len], num_chars, ascii);
        },
        .InlineUtf16 => |inl| return utf16EqualsAscii(inl.bytes, inl.num_chars, ascii),
    }
}
