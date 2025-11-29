//! JSON rendering for BinXML IR structures.
//! Converts the intermediate representation into JSON output.
//!
//! This module produces JSON output compatible with Rust evtx_dump:
//! - Attributes grouped into `#attributes` object (only if non-empty)
//! - EventData/UserData `Data` elements flattened to key-value pairs
//! - Numeric values output as JSON numbers where appropriate
//! - Empty elements rendered as `null`
//! - GUIDs formatted as uppercase without braces

const std = @import("std");
const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const util = @import("util.zig");
const vf = @import("value_format.zig");
const ValueType = @import("binxml/types.zig").ValueType;
const reader = @import("reader.zig");

/// Writer error type for all rendering functions.
pub const WriterError = std.Io.Writer.Error;

/// Key for grouping elements by name.
const NameKey = struct {
    bytes: []const u8,
    num_chars: usize,

    fn fromName(name: IR.Name) NameKey {
        return .{ .bytes = name.bytes, .num_chars = name.num_chars };
    }

    fn eql(self: NameKey, other: NameKey) bool {
        if (self.num_chars != other.num_chars) return false;
        if (self.bytes.ptr == other.bytes.ptr) return true;
        return std.mem.eql(u8, self.bytes, other.bytes);
    }
};

/// Entry for counting unique element names during two-pass rendering.
const NameCount = struct {
    key: NameKey,
    count: u16,
    emitted: bool,
};

const MAX_UNIQUE_NAMES: usize = 64;

// ============================================================================
// Name Comparison Helpers
// ============================================================================

fn nameEqualsAscii(name: IR.Name, ascii: []const u8) bool {
    return util.utf16EqualsAscii(name.bytes, name.num_chars, ascii);
}

fn isDataContainer(name: IR.Name) bool {
    return nameEqualsAscii(name, "EventData") or nameEqualsAscii(name, "UserData");
}

fn isDataElement(name: IR.Name) bool {
    return nameEqualsAscii(name, "Data");
}

// ============================================================================
// Content Helpers
// ============================================================================

/// Check if nodes contain any non-empty text content
fn hasNonEmptyTextContent(nodes: []const IR.Node) bool {
    for (nodes) |node| {
        switch (node) {
            .Text => |text| if (text.num_chars > 0) return true,
            .Value => |val| if (val.bytes.len > 0) return true,
            .CData => |cdata| if (cdata.num_chars > 0) return true,
            .CharRef, .EntityRef => return true,
            else => {},
        }
    }
    return false;
}

/// Check if element has any non-empty attributes
fn hasNonEmptyAttributes(element: *const IR.Element) bool {
    for (element.attrs.items) |attr| {
        if (hasNonEmptyTextContent(attr.value.items)) return true;
    }
    return false;
}

/// Get the Name attribute value from a Data element for flattening
fn getNameAttrValue(element: *const IR.Element) ?[]const u8 {
    for (element.attrs.items) |attr| {
        if (nameEqualsAscii(attr.name, "Name")) {
            for (attr.value.items) |node| {
                switch (node) {
                    .Text => |text| return text.utf16[0 .. text.num_chars * 2],
                    .Value => |val| return val.bytes,
                    else => {},
                }
            }
        }
    }
    return null;
}

fn getNameAttrNumChars(element: *const IR.Element) ?usize {
    for (element.attrs.items) |attr| {
        if (nameEqualsAscii(attr.name, "Name")) {
            for (attr.value.items) |node| {
                switch (node) {
                    .Text => |text| return text.num_chars,
                    .Value => return null,
                    else => {},
                }
            }
        }
    }
    return null;
}

// ============================================================================
// JSON Value Formatting
// ============================================================================

/// Try to render content as a JSON number (only for Value nodes with numeric types).
/// Text content is never converted to numbers to match Rust evtx_dump behavior.
fn tryWriteAsNumber(nodes: []const IR.Node, writer: *std.Io.Writer) WriterError!bool {
    if (nodes.len != 1) return false;

    switch (nodes[0]) {
        .Value => |val| {
            const base = ValueType.baseType(val.vtype);
            const vtype = std.meta.intToEnum(ValueType, base) catch return false;

            switch (vtype) {
                .int8, .uint8, .int16, .uint16, .int32, .uint32, .int64, .uint64 => {
                    try vf.formatValueXml(writer, vtype, val.bytes);
                    return true;
                },
                .bool => {
                    if (reader.readValue(bool, val.bytes)) |b| {
                        try writer.writeAll(if (b) "true" else "false");
                        return true;
                    }
                    return false;
                },
                else => return false,
            }
        },
        // Text content stays as strings - don't try to convert to numbers
        else => return false,
    }
}

fn renderJsonTextContent(nodes: []const IR.Node, writer: *std.Io.Writer) WriterError!void {
    for (nodes) |node| {
        switch (node) {
            .Text => |text| try util.writeUtf16LeJsonEscaped(writer, text.utf16, text.num_chars),
            .Value => |val| try formatValueJson(writer, val.vtype, val.bytes),
            .CharRef => |charref| try writer.print("&#{d};", .{charref}),
            .EntityRef => try writer.writeByte('&'),
            .CData => |cdata| try util.writeUtf16LeJsonEscaped(writer, cdata.utf16, cdata.num_chars),
            .PITarget, .PIData, .Element => {},
            .Placeholder => unreachable,
        }
    }
}

fn formatValueJson(w: *std.Io.Writer, raw_type: u8, data: []const u8) WriterError!void {
    const base = ValueType.baseType(raw_type);
    const vtype = std.meta.intToEnum(ValueType, base) catch return;

    if (vtype == .guid) {
        if (reader.readGuid(data)) |guid| {
            try formatGuidJson(w, guid);
            return;
        }
    }

    try vf.formatValueXmlFromRaw(w, raw_type, data);
}

fn formatGuidJson(w: *std.Io.Writer, guid: reader.Guid) WriterError!void {
    try w.print("{X:0>8}-{X:0>4}-{X:0>4}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    });
}

fn renderTextToJsonString(nodes: []const IR.Node, writer: *std.Io.Writer) WriterError!void {
    try writer.writeByte('"');
    try renderJsonTextContent(nodes, writer);
    try writer.writeByte('"');
}

fn renderContentAsJsonValue(nodes: []const IR.Node, writer: *std.Io.Writer) WriterError!void {
    if (try tryWriteAsNumber(nodes, writer)) return;
    try renderTextToJsonString(nodes, writer);
}

// ============================================================================
// Attribute Rendering
// ============================================================================

/// Render non-empty attributes as #attributes object
fn renderAttributesObject(attrs: []const IR.Attr, writer: *std.Io.Writer) WriterError!bool {
    // Check if any attribute has non-empty value
    var has_any = false;
    for (attrs) |attr| {
        if (hasNonEmptyTextContent(attr.value.items)) {
            has_any = true;
            break;
        }
    }
    if (!has_any) return false;

    try writer.writeAll("\"#attributes\":{");
    var first = true;
    for (attrs) |attr| {
        // Skip empty attributes
        if (!hasNonEmptyTextContent(attr.value.items)) continue;

        if (!first) try writer.writeByte(',');
        first = false;

        try writer.writeByte('"');
        try util.writeUtf16LeJsonEscaped(writer, attr.name.bytes, attr.name.num_chars);
        try writer.writeAll("\":");

        if (try tryWriteAsNumber(attr.value.items, writer)) continue;
        try renderTextToJsonString(attr.value.items, writer);
    }
    try writer.writeByte('}');
    return true;
}

// ============================================================================
// Element Rendering
// ============================================================================

fn isLeafString(element: *const IR.Element) bool {
    return element.attrs.items.len == 0 and !element.has_element_child;
}

/// Check if element can be rendered as just its value (no non-empty attrs)
fn canRenderAsSimpleValue(element: *const IR.Element) bool {
    // Has child elements - needs object form
    if (element.has_element_child) return false;

    // Has non-empty attributes - needs object form
    if (hasNonEmptyAttributes(element)) return false;

    // Has text content - can be simple
    return hasNonEmptyTextContent(element.children.items);
}

/// Check if element should be rendered as null
fn shouldRenderAsNull(element: *const IR.Element) bool {
    if (element.has_element_child) return false;
    if (hasNonEmptyTextContent(element.children.items)) return false;
    if (hasNonEmptyAttributes(element)) return false;
    return true;
}

fn renderDataElementValue(element: *const IR.Element, allocator: std.mem.Allocator, writer: *std.Io.Writer) anyerror!void {
    if (!hasNonEmptyTextContent(element.children.items) and !element.has_element_child) {
        try writer.writeAll("\"\"");
        return;
    }

    if (element.has_element_child) {
        try writeElementBodyJson(element, allocator, writer, false);
        return;
    }

    try renderContentAsJsonValue(element.children.items, writer);
}

/// Write an element's value - handles both simple values and objects
fn writeElementValue(element: *const IR.Element, allocator: std.mem.Allocator, writer: *std.Io.Writer, child_is_container: bool) anyerror!void {
    if (shouldRenderAsNull(element)) {
        try writer.writeAll("null");
    } else if (canRenderAsSimpleValue(element)) {
        // Element with no non-empty attrs and text content - render as simple value
        try renderContentAsJsonValue(element.children.items, writer);
    } else if (isLeafString(element)) {
        try renderContentAsJsonValue(element.children.items, writer);
    } else {
        try writeElementBodyJson(element, allocator, writer, child_is_container);
    }
}

fn writeElementBodyJson(element: *const IR.Element, allocator: std.mem.Allocator, writer: *std.Io.Writer, in_data_container: bool) anyerror!void {
    // Count unique element names
    var name_counts: [MAX_UNIQUE_NAMES]NameCount = undefined;
    var num_unique: usize = 0;

    for (element.children.items) |node| {
        switch (node) {
            .Element => |child| {
                const key = NameKey.fromName(child.name);
                var found = false;
                for (name_counts[0..num_unique]) |*nc| {
                    if (nc.key.eql(key)) {
                        nc.count += 1;
                        found = true;
                        break;
                    }
                }
                if (!found and num_unique < MAX_UNIQUE_NAMES) {
                    name_counts[num_unique] = .{ .key = key, .count = 1, .emitted = false };
                    num_unique += 1;
                }
            },
            else => {},
        }
    }

    try writer.writeByte('{');
    var wrote_any = false;

    // Render non-empty attributes as #attributes object
    if (element.attrs.items.len > 0) {
        if (try renderAttributesObject(element.attrs.items, writer)) {
            wrote_any = true;
        }
    }

    const should_flatten = in_data_container;

    // Render child elements
    for (element.children.items) |node| {
        if (node != .Element) continue;
        const child = node.Element;
        const key = NameKey.fromName(child.name);

        var count: u16 = 1;
        var nc_ptr: ?*NameCount = null;
        for (name_counts[0..num_unique]) |*nc| {
            if (nc.key.eql(key)) {
                if (nc.emitted) break;
                nc.emitted = true;
                count = nc.count;
                nc_ptr = nc;
                break;
            }
        }
        if (nc_ptr == null) continue;

        // Handle Data flattening for EventData/UserData
        if (should_flatten and isDataElement(child.name)) {
            for (element.children.items) |node2| {
                if (node2 != .Element) continue;
                const c = node2.Element;
                if (!isDataElement(c.name)) continue;

                if (getNameAttrValue(c)) |name_utf16| {
                    if (wrote_any) try writer.writeByte(',');
                    wrote_any = true;

                    try writer.writeByte('"');
                    const num_chars = getNameAttrNumChars(c) orelse name_utf16.len / 2;
                    try util.writeUtf16LeJsonEscaped(writer, name_utf16, num_chars);
                    try writer.writeAll("\":");
                    try renderDataElementValue(c, allocator, writer);
                }
            }
            continue;
        }

        if (wrote_any) try writer.writeByte(',');

        try writer.writeByte('"');
        try util.writeUtf16LeJsonEscaped(writer, child.name.bytes, child.name.num_chars);
        try writer.writeAll("\":");

        const child_is_container = isDataContainer(child.name);

        if (count == 1) {
            try writeElementValue(child, allocator, writer, child_is_container);
        } else {
            try writer.writeByte('[');
            var first = true;
            for (element.children.items) |node2| {
                if (node2 != .Element) continue;
                const c = node2.Element;
                if (!NameKey.fromName(c.name).eql(key)) continue;

                if (!first) try writer.writeByte(',');
                first = false;
                try writeElementValue(c, allocator, writer, child_is_container);
            }
            try writer.writeByte(']');
        }
        wrote_any = true;
    }

    try writer.writeByte('}');
}

// ============================================================================
// Public API
// ============================================================================

pub fn renderElementJson(root: *const IR.Element, allocator: std.mem.Allocator, writer: *std.Io.Writer) anyerror!void {
    try writeElementBodyJson(root, allocator, writer, false);
}
