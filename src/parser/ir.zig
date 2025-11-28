const std = @import("std");

const TemplateValue = @import("binxml/types.zig").TemplateValue;
const utf16EqualsAscii = @import("util.zig").utf16EqualsAscii;

pub const IR = struct {
    pub const Name = struct { bytes: []const u8, num_chars: usize };

    pub const NodeTag = enum { Element, Text, Value, Subst, CharRef, EntityRef, CData, Pad, PITarget, PIData };

    /// Payload types for each node variant
    pub const TextPayload = struct { utf16: []const u8, num_chars: usize };
    pub const ValuePayload = struct { vtype: u8, bytes: []const u8 };
    pub const SubstPayload = struct { id: u16, vtype: u8, optional: bool };

    /// Tagged union for IR nodes - replaces struct with tag pattern
    pub const Node = union(NodeTag) {
        Element: *Element,
        Text: TextPayload,
        Value: ValuePayload,
        Subst: SubstPayload,
        CharRef: u16,
        EntityRef: Name,
        CData: TextPayload,
        Pad: void,
        PITarget: Name,
        PIData: TextPayload,
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
    el.* = .{ .name = name, .attrs = .empty, .children = .empty };
    return el;
}

pub fn nameEqualsAscii(chunk: []const u8, name: IR.Name, ascii: []const u8) bool {
    _ = chunk;
    return utf16EqualsAscii(name.bytes, name.num_chars, ascii);
}
