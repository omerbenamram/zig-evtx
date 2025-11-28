//! XML rendering for BinXML IR structures.
//! Converts the intermediate representation into properly formatted XML output.

const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const logger = @import("../logger.zig");
const std = @import("std");
const util = @import("util.zig");
const normalizeAndWriteSystemTimeAscii = util.normalizeAndWriteSystemTimeAscii;
const writeUtf16LeRawToUtf8 = util.writeUtf16LeRawToUtf8;
const binxml = @import("binxml/mod.zig");
const Context = binxml.Context;
const logNameTrace = @import("binxml/name.zig").logNameTrace;
const attrNameIsSystemTime = @import("binxml/name.zig").attrNameIsSystemTime;
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
fn renderAttribute(chunk: []const u8, attr: *const IR.Attr, writer: anytype) !void {
    try writer.writeByte(' ');
    try writeNameXml(chunk, attr.name, writer);
    try writer.writeAll("=\"");

    if (attrNameIsSystemTime(attr.name)) {
        // SystemTime attributes need normalization - buffer first, then normalize
        var buffer: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);
        try renderAttrValueNodes(chunk, attr.value.items, fbs.writer());
        try normalizeAndWriteSystemTimeAscii(writer, fbs.getWritten());
    } else {
        try renderAttrValueNodes(chunk, attr.value.items, writer);
    }

    try writer.writeByte('"');
}

/// Render the opening tag start with all attributes (without closing >)
fn renderOpenTagStart(chunk: []const u8, element: *const IR.Element, writer: anytype, indent: usize) !void {
    try writeSpaces(writer, indent);
    try writer.writeByte('<');
    try writeNameXml(chunk, element.name, writer);

    for (element.attrs.items) |*attr| {
        try renderAttribute(chunk, attr, writer);
    }
}

// ============================================================================
// Content Rendering
// ============================================================================

/// Render attribute value tokens to any writer
fn renderAttrValueNodes(chunk: []const u8, nodes: []const IR.Node, writer: anytype) !void {
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

/// Render text content from IR nodes
fn renderTextContentFromIR(chunk: []const u8, nodes: []const IR.Node, writer: anytype) !void {
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
fn renderElementIRXml(chunk: []const u8, element: *const IR.Element, writer: anytype, indent: usize) anyerror!void {
    // Render opening tag with attributes
    try renderOpenTagStart(chunk, element, writer, indent);

    // Handle empty elements: <Name></Name>
    if (element.children.items.len == 0) {
        try writer.writeByte('>');
        try writeCloseTag(chunk, element, writer);
        return;
    }

    // Handle leaf elements (no child elements): <Name>content</Name>
    if (!element.has_element_child) {
        try writer.writeByte('>');
        try renderTextContentFromIR(chunk, element.children.items, writer);
        try writeCloseTag(chunk, element, writer);
        return;
    }

    // Handle elements with child elements: block form with newlines
    try writer.writeByte('>');
    try writer.writeByte('\n');

    for (element.children.items) |node| {
        switch (node) {
            .Element => |child_element| {
                try renderElementIRXml(chunk, child_element, writer, indent + 2);
            },
            .Subst => {},
            else => {
                try writeSpaces(writer, indent + 2);
                try renderTextContentFromIR(chunk, &[_]IR.Node{node}, writer);
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

    var builder = binxml.Builder.init(ctx);
    const root = try builder.build(chunk, bin);

    if (ctx.verbose) {
        try logNameTrace(root.name, "root");
    }

    try renderElementIRXml(chunk, root, writer, 0);
}

/// Render a single value payload to XML text according to its Binary XML type.
/// Uses the typed value_format module for clean, well-structured formatting.
pub fn writeValueXml(writer: anytype, raw_type: u8, data: []const u8) !void {
    try vf.formatValueXmlFromRaw(writer, raw_type, data);
}
