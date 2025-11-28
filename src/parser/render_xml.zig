//! XML rendering for BinXML IR structures.
//! Converts the intermediate representation into properly formatted XML output.

const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const TemplateValue = @import("binxml/types.zig").TemplateValue;
const ValueType = @import("binxml/types.zig").ValueType;
const logger = @import("../logger.zig");
const log = logger.scoped("render_xml");
const std = @import("std");
const BinXmlError = @import("err.zig").BinXmlError;
const util = @import("util.zig");
const writeAnsiCp1252Escaped = util.writeAnsiCp1252Escaped;
const normalizeAndWriteSystemTimeAscii = util.normalizeAndWriteSystemTimeAscii;
const writePaddedInt = util.writePaddedInt;
const writeUtf16LeRawToUtf8 = util.writeUtf16LeRawToUtf8;
const binxml = @import("binxml/mod.zig");
const Context = binxml.Context;
const logNameTrace = @import("binxml/name.zig").logNameTrace;
const valueTypeFixedSize = @import("binxml/types.zig").valueTypeFixedSize;
const attrNameIsSystemTime = @import("binxml/name.zig").attrNameIsSystemTime;
const vr = @import("binxml/value_reader.zig");
const vf = @import("value_format.zig");

// ============================================================================
// Low-Level Writing Helpers
// ============================================================================

/// Write N spaces for indentation
inline fn writeSpaces(writer: anytype, count: usize) !void {
    if (count == 0) return;
    const SPACES = "                                                                "; // 64 spaces
    var remaining: usize = count;
    while (remaining > 0) {
        const take = @min(remaining, SPACES.len);
        try writer.writeAll(SPACES[0..take]);
        remaining -= take;
    }
}

/// Write an element name from UTF-16LE
fn writeNameXml(chunk: []const u8, name: IR.Name, writer: anytype) !void {
    _ = chunk;
    try util.writeUtf16LeXmlEscaped(writer, name.bytes, name.num_chars);
}

// ============================================================================
// Attribute and Element State Helpers
// ============================================================================

/// Check if an attribute should be dropped (single optional substitution resolving to NULL)
fn shouldDropAttribute(attr: *const IR.Attr, template_values: []const TemplateValue) bool {
    if (attr.value.items.len != 1) return false;
    if (attr.value.items[0] != .Subst) return false;

    const subst = attr.value.items[0].Subst;
    if (!subst.optional) return false;
    if (subst.id >= template_values.len) return false;

    const value = template_values[subst.id];
    return value.t == 0x00 or value.data.len == 0;
}

/// Check if an element should be dropped (only child is optional substitution resolving to NULL)
fn shouldDropElement(element: *const IR.Element, template_values: []const TemplateValue) bool {
    if (element.has_element_child) return false;
    if (element.children.items.len != 1) return false;
    if (element.children.items[0] != .Subst) return false;

    const subst = element.children.items[0].Subst;
    if (!subst.optional) return false;
    if (subst.id >= template_values.len) return false;

    const value = template_values[subst.id];
    return value.t == 0x00 or value.data.len == 0;
}

/// Check if element has an array substitution as its sole child
fn getArraySubstitution(element: *const IR.Element, chunk: []const u8, template_values: []const TemplateValue) ?struct { subst: IR.SubstPayload, value: TemplateValue } {
    if (element.has_element_child) return null;
    if (element.children.items.len != 1) return null;
    if (IRModule.nameEqualsAscii(chunk, element.name, "Data")) return null;
    if (element.children.items[0] != .Subst) return null;

    const subst = element.children.items[0].Subst;
    const is_array = (subst.vtype & ValueType.ARRAY_FLAG) != 0;
    if (!is_array) return null;
    if (subst.id >= template_values.len) return null;

    return .{ .subst = subst, .value = template_values[subst.id] };
}

// ============================================================================
// Tag Rendering Helpers
// ============================================================================

/// Write the closing tag for an element: </Name>\n
fn writeCloseTag(chunk: []const u8, element: *const IR.Element, writer: anytype) !void {
    try writer.writeAll("</");
    try writeNameXml(chunk, element.name, writer);
    try writer.writeByte('>');
    try writer.writeByte('\n');
}

/// Render a single attribute: name="value"
fn renderAttribute(chunk: []const u8, attr: *const IR.Attr, template_values: []const TemplateValue, writer: anytype) !void {
    try writer.writeByte(' ');
    try writeNameXml(chunk, attr.name, writer);
    try writer.writeAll("=\"");

    if (attrNameIsSystemTime(attr.name)) {
        // SystemTime attributes need normalization
        var buffer: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);
        try renderAttrValueFromIR(chunk, attr.value.items, template_values, fbs.writer());
        try normalizeAndWriteSystemTimeAscii(writer, fbs.getWritten());
    } else {
        try renderAttrValueFromIRStream(chunk, attr.value.items, template_values, writer);
    }

    try writer.writeByte('"');
}

/// Render the opening tag start with all attributes (without closing >)
fn renderOpenTagStart(chunk: []const u8, element: *const IR.Element, template_values: []const TemplateValue, writer: anytype, indent: usize) !void {
    try writeSpaces(writer, indent);
    try writer.writeByte('<');
    try writeNameXml(chunk, element.name, writer);

    for (element.attrs.items) |*attr| {
        if (!shouldDropAttribute(attr, template_values)) {
            try renderAttribute(chunk, attr, template_values, writer);
        }
    }
}

// ============================================================================
// Array Substitution Rendering
// ============================================================================

/// Render array of Unicode strings (NUL-terminated)
fn renderUnicodeStringArray(
    chunk: []const u8,
    element: *const IR.Element,
    data: []const u8,
    writer: anytype,
    indent: usize,
    any_rendered: *bool,
) !void {
    var offset: usize = 0;
    while (offset <= data.len) {
        const start = offset;
        var end = offset;

        // Find NUL terminator (2-byte aligned)
        while (end + 1 < data.len) : (end += 2) {
            if (std.mem.readInt(u16, data[end..][0..2], .little) == 0) break;
        }

        try renderOpenTagStart(chunk, element, &[_]TemplateValue{}, writer, indent);
        try writer.writeByte('>');
        if (end > start) {
            try util.writeUtf16LeXmlEscaped(writer, data[start..end], (end - start) / 2);
        }
        try writeCloseTag(chunk, element, writer);
        any_rendered.* = true;

        if (end + 1 < data.len) {
            offset = end + 2;
        } else {
            break;
        }
    }
}

/// Render array of ANSI strings (NUL-separated)
fn renderAnsiStringArray(
    chunk: []const u8,
    element: *const IR.Element,
    data: []const u8,
    writer: anytype,
    indent: usize,
    any_rendered: *bool,
) !void {
    var offset: usize = 0;
    while (offset <= data.len) {
        const start = offset;
        var end = offset;

        // Find NUL terminator
        while (end < data.len and data[end] != 0) : (end += 1) {}

        try renderOpenTagStart(chunk, element, &[_]TemplateValue{}, writer, indent);
        try writer.writeByte('>');
        if (end > start) {
            try writeAnsiCp1252Escaped(writer, data[start..end]);
        }
        try writeCloseTag(chunk, element, writer);
        any_rendered.* = true;

        if (end < data.len and data[end] == 0) {
            offset = end + 1;
        } else {
            break;
        }
    }
}

/// Render array of fixed-size elements
fn renderFixedSizeArray(
    chunk: []const u8,
    element: *const IR.Element,
    data: []const u8,
    base_type: u8,
    element_size: usize,
    writer: anytype,
    indent: usize,
    any_rendered: *bool,
) !void {
    var offset: usize = 0;
    while (offset + element_size <= data.len) : (offset += element_size) {
        try renderOpenTagStart(chunk, element, &[_]TemplateValue{}, writer, indent);
        try writer.writeByte('>');
        try writeValueXml(writer, base_type, data[offset .. offset + element_size]);
        try writeCloseTag(chunk, element, writer);
        any_rendered.* = true;
    }
}

/// Render array of SIDs (variable length)
fn renderSidArray(
    chunk: []const u8,
    element: *const IR.Element,
    data: []const u8,
    writer: anytype,
    indent: usize,
    any_rendered: *bool,
) !void {
    var offset: usize = 0;
    while (offset + 8 <= data.len) {
        // Use shared SID size calculation
        const sid_size = vr.sidSize(data[offset..]) orelse break;
        if (offset + sid_size > data.len) break;

        try renderOpenTagStart(chunk, element, &[_]TemplateValue{}, writer, indent);
        try writer.writeByte('>');
        try writeValueXml(writer, 0x13, data[offset .. offset + sid_size]);
        try writeCloseTag(chunk, element, writer);
        any_rendered.* = true;

        offset += sid_size;
    }
}

/// Render array substitution - emits repeated elements for each array item
/// Returns true if array was rendered, false if caller should continue with normal rendering
fn renderArraySubstitution(
    chunk: []const u8,
    element: *const IR.Element,
    subst: IR.SubstPayload,
    template_value: TemplateValue,
    writer: anytype,
    indent: usize,
) !bool {
    const base_type: u8 = subst.vtype & 0x7F;

    // Handle unsupported types
    if (base_type == 0x21) {
        log.warn("array of BinXML (0x21) not supported; skipping repetition", .{});
        return false;
    }
    if (base_type == 0x10 and !(template_value.t == 0x94 or template_value.t == 0x95)) {
        log.warn("size array backing mismatch: expected hex_int32/64_array, got 0x{x}", .{template_value.t});
        return true; // Skip element entirely
    }

    const data = template_value.data;
    var any_item_rendered = false;

    // Iterate and render based on base type
    if (base_type == 0x01) {
        // Unicode string array: NUL-terminated items
        try renderUnicodeStringArray(chunk, element, data, writer, indent, &any_item_rendered);
    } else if (base_type == 0x02) {
        // ANSI string array: NUL-separated items
        try renderAnsiStringArray(chunk, element, data, writer, indent, &any_item_rendered);
    } else if (valueTypeFixedSize(base_type)) |element_size| {
        // Fixed-size type array
        try renderFixedSizeArray(chunk, element, data, base_type, element_size, writer, indent, &any_item_rendered);
    } else if (base_type == 0x13) {
        // SID array (variable length)
        try renderSidArray(chunk, element, data, writer, indent, &any_item_rendered);
    }

    // Empty arrays produce one empty element
    if (!any_item_rendered) {
        try renderOpenTagStart(chunk, element, &[_]TemplateValue{}, writer, indent);
        try writer.writeByte('>');
        try writeCloseTag(chunk, element, writer);
    }

    return true;
}

// ============================================================================
// Content Rendering
// ============================================================================

/// Stream attribute value tokens directly to destination (no buffering)
fn renderAttrValueFromIRStream(chunk: []const u8, nodes: []const IR.Node, template_values: []const TemplateValue, writer: anytype) !void {
    _ = template_values;
    for (nodes) |node| switch (node) {
        .Text => |text| try util.writeUtf16LeXmlEscaped(writer, text.utf16, text.num_chars),
        .Pad => {},
        .Value => |val| try writeValueXml(writer, val.vtype, val.bytes),
        .Subst => {},
        .CharRef => |charref| try writer.print("&#{d};", .{charref}),
        .EntityRef => |name| {
            try writer.writeByte('&');
            try writeNameXml(chunk, name, writer);
            try writer.writeByte(';');
        },
        .CData => |cdata| try util.writeUtf16LeXmlEscaped(writer, cdata.utf16, cdata.num_chars),
        .PITarget => |name| {
            try writer.writeAll("<?");
            try writeNameXml(chunk, name, writer);
        },
        .PIData => |pidata| {
            try writer.writeByte(' ');
            try writeUtf16LeRawToUtf8(writer, pidata.utf16, pidata.num_chars);
            try writer.writeAll("?>");
        },
        .Element => {},
    };
}

/// Render attribute value with buffering (for normalization)
fn renderAttrValueFromIR(chunk: []const u8, nodes: []const IR.Node, template_values: []const TemplateValue, writer: anytype) !void {
    var buffer: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const buf_writer = fbs.writer();

    for (nodes) |node| switch (node) {
        .Text => |text| try util.writeUtf16LeXmlEscaped(buf_writer, text.utf16, text.num_chars),
        .Pad => {},
        .Value => |val| try writeValueXml(buf_writer, val.vtype, val.bytes),
        .Subst => {},
        .CharRef => |charref| try buf_writer.print("&#{d};", .{charref}),
        .EntityRef => |name| {
            try buf_writer.writeByte('&');
            try writeNameXml(chunk, name, buf_writer);
            try buf_writer.writeByte(';');
        },
        .CData => |cdata| try util.writeUtf16LeXmlEscaped(buf_writer, cdata.utf16, cdata.num_chars),
        .PITarget => |name| {
            try buf_writer.writeAll("<?");
            try writeNameXml(chunk, name, buf_writer);
        },
        .PIData => |pidata| {
            try buf_writer.writeByte(' ');
            try writeUtf16LeRawToUtf8(buf_writer, pidata.utf16, pidata.num_chars);
            try buf_writer.writeAll("?>");
        },
        .Element => {},
    };

    _ = template_values;
    const written = fbs.getWritten();
    if (written.len > 0) try writer.writeAll(written);
}

/// Render text content from IR nodes
fn renderTextContentFromIR(chunk: []const u8, nodes: []const IR.Node, template_values: []const TemplateValue, writer: anytype) !void {
    _ = template_values;
    for (nodes) |node| {
        switch (node) {
            .Text => |text| try util.writeUtf16LeXmlEscaped(writer, text.utf16, text.num_chars),
            .Pad => {},
            .Value => |val| try writeValueXml(writer, val.vtype, val.bytes),
            .Subst => {},
            .CharRef => |charref| try writer.print("&#{d};", .{charref}),
            .EntityRef => |name| {
                try writer.writeByte('&');
                try writeNameXml(chunk, name, writer);
                try writer.writeByte(';');
            },
            .CData => |cdata| {
                try writer.writeAll("<![CDATA[");
                try writeUtf16LeRawToUtf8(writer, cdata.utf16, cdata.num_chars);
                try writer.writeAll("]]>");
            },
            .PITarget => |name| {
                try writer.writeAll("<?");
                try writeNameXml(chunk, name, writer);
            },
            .PIData => |pidata| {
                try writer.writeByte(' ');
                try writeUtf16LeRawToUtf8(writer, pidata.utf16, pidata.num_chars);
                try writer.writeAll("?>");
            },
            .Element => {},
        }
    }
}

// ============================================================================
// Main Element Renderer
// ============================================================================

/// Recursively render an IR element to XML
fn renderElementIRXml(chunk: []const u8, element: *const IR.Element, template_values: []const TemplateValue, writer: anytype, indent: usize) anyerror!void {
    // Early exit: drop element if it's an optional NULL substitution
    if (shouldDropElement(element, template_values)) return;

    // Handle array substitution (repeated elements for each array item)
    if (getArraySubstitution(element, chunk, template_values)) |array_info| {
        if (try renderArraySubstitution(chunk, element, array_info.subst, array_info.value, writer, indent)) {
            return;
        }
    }

    // Render opening tag with attributes
    try renderOpenTagStart(chunk, element, template_values, writer, indent);

    // Handle empty elements: <Name></Name>
    if (element.children.items.len == 0) {
        try writer.writeByte('>');
        try writeCloseTag(chunk, element, writer);
        return;
    }

    // Handle leaf elements (no child elements): <Name>content</Name>
    if (!element.has_element_child) {
        try writer.writeByte('>');
        try renderTextContentFromIR(chunk, element.children.items, template_values, writer);
        try writeCloseTag(chunk, element, writer);
        return;
    }

    // Handle elements with child elements: block form with newlines
    try writer.writeByte('>');
    try writer.writeByte('\n');

    for (element.children.items) |node| {
        switch (node) {
            .Element => |child_element| {
                try renderElementIRXml(chunk, child_element, template_values, writer, indent + 2);
            },
            .Subst => {},
            else => {
                try writeSpaces(writer, indent + 2);
                try renderTextContentFromIR(chunk, &[_]IR.Node{node}, template_values, writer);
                try writer.writeByte('\n');
            },
        }
    }

    try writeSpaces(writer, indent);
    try writeCloseTag(chunk, element, writer);
}

// ============================================================================
// Public API
// ============================================================================

/// Render XML from BinXML with context
pub fn renderXmlWithContext(ctx: *Context, chunk: []const u8, bin: []const u8, writer: anytype) anyerror!void {
    if (ctx.verbose) logger.setModuleLevel("binxml", .trace);

    var builder = binxml.Builder.init(ctx, ctx.allocator);
    const root = try builder.build(chunk, bin);

    if (ctx.verbose) {
        try logNameTrace(root.name, "root");
    }

    try renderElementIRXml(chunk, root, &[_]TemplateValue{}, writer, 0);
}

/// Write name from chunk offset
pub fn writeNameFromOffset(chunk: []const u8, name_offset: u32, writer: anytype) !void {
    const off = @as(usize, name_offset);
    if (off + 8 > chunk.len) return BinXmlError.OutOfBounds;

    // Name structure: u32 next_offset, u16 hash, u16 num_chars, then UTF-16LE chars
    const num_chars = std.mem.readInt(u16, chunk[off + 6 .. off + 8][0..2], .little);
    const str_start = off + 8;
    const byte_len = @as(usize, num_chars) * 2;

    if (str_start + byte_len > chunk.len) return BinXmlError.OutOfBounds;

    // Trim trailing NUL if present
    var actual_chars = num_chars;
    if (byte_len >= 2) {
        const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
        if (last == 0 and actual_chars > 0) actual_chars -= 1;
    }

    try util.writeUtf16LeXmlEscaped(writer, chunk[str_start .. str_start + actual_chars * 2], actual_chars);
}

/// Write name from UTF-16LE bytes
pub fn writeNameFromUtf16(writer: anytype, utf16le: []const u8, num_chars: usize) !void {
    try util.writeUtf16LeXmlEscaped(writer, utf16le, num_chars);
}

/// Write a value with optional padding for integers
fn writeSingleWithPad(writer: anytype, raw_type: u8, bytes: []const u8, pad: usize) !void {
    if (pad > 0) {
        switch (raw_type) {
            0x07 => if (vr.readInt(i32, bytes)) |v| return try writePaddedInt(writer, i32, v, pad),
            0x08 => if (vr.readInt(u32, bytes)) |v| return try writePaddedInt(writer, u32, v, pad),
            0x09 => if (vr.readInt(i64, bytes)) |v| return try writePaddedInt(writer, i64, v, pad),
            0x0a => if (vr.readInt(u64, bytes)) |v| return try writePaddedInt(writer, u64, v, pad),
            else => {},
        }
    }
    try writeValueXml(writer, raw_type, bytes);
}

/// Render a single value payload to XML text according to its Binary XML type.
/// Uses the typed value_format module for clean, well-structured formatting.
pub fn writeValueXml(writer: anytype, raw_type: u8, data: []const u8) !void {
    try vf.formatValueXmlFromRaw(writer, raw_type, data);
}
