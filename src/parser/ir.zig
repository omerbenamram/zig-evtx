const std = @import("std");

const TemplateValue = @import("binxml/types.zig").TemplateValue;
const utf16EqualsAscii = @import("util.zig").utf16EqualsAscii;

pub const IR = struct {
    pub const Name = struct { bytes: []const u8, num_chars: usize };

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
        entity_name: Name = Name{ .bytes = &[_]u8{}, .num_chars = 0 },
        // PI
        pi_target: Name = Name{ .bytes = &[_]u8{}, .num_chars = 0 },
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
        has_element_child: bool = false,
    };
};

pub fn irNewElement(allocator: std.mem.Allocator, name: IR.Name) !*IR.Element {
    const el = try allocator.create(IR.Element);
    el.* = .{ .name = name, .attrs = std.ArrayList(IR.Attr).initCapacity(allocator, 0) catch unreachable, .children = std.ArrayList(IR.Node).initCapacity(allocator, 0) catch unreachable };
    return el;
}

pub fn nameEqualsAscii(chunk: []const u8, name: IR.Name, ascii: []const u8) bool {
    _ = chunk;
    return utf16EqualsAscii(name.bytes, name.num_chars, ascii);
}
