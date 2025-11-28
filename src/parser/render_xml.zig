//! XML rendering for BinXML IR structures.
//! Converts the intermediate representation into properly formatted XML output.
//!
//! This module uses Zig 0.15's concrete std.Io.Writer interface for all output,
//! enabling better debug-mode performance and eliminating generic code bloat.

const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const logger = @import("../logger.zig");
const std = @import("std");
const util = @import("util.zig");
const normalizeAndWriteSystemTimeAscii = util.normalizeAndWriteSystemTimeAscii;
const binxml = @import("binxml/mod.zig");
const Context = binxml.Context;
const logNameTrace = @import("binxml/name.zig").logNameTrace;
const attrNameIsSystemTime = @import("binxml/name.zig").attrNameIsSystemTime;
const vf = @import("value_format.zig");

/// Writer error type for all rendering functions.
pub const WriterError = std.Io.Writer.Error;

// ============================================================================
// Low-Level Writing Helpers
// ============================================================================

/// Write N spaces for indentation using efficient splatting.
inline fn writeSpaces(writer: *std.Io.Writer, count: usize) WriterError!void {
    if (count == 0) return;
    try writer.splatByteAll(' ', count);
}

/// Write an element name from UTF-16LE
fn writeNameXml(name: IR.Name, writer: *std.Io.Writer) WriterError!void {
    try util.writeUtf16LeXmlEscaped(writer, name.bytes, name.num_chars);
}

// ============================================================================
// Tag Rendering Helpers
// ============================================================================

/// Write the closing tag for an element: </Name>\n
fn writeCloseTag(element: *const IR.Element, writer: *std.Io.Writer) WriterError!void {
    try writer.writeAll("</");
    try writeNameXml(element.name, writer);
    try writer.writeByte('>');
    try writer.writeByte('\n');
}

/// Render a single attribute: name="value"
fn renderAttribute(attr: *const IR.Attr, writer: *std.Io.Writer) WriterError!void {
    try writer.writeByte(' ');
    try writeNameXml(attr.name, writer);
    try writer.writeAll("=\"");

    if (attrNameIsSystemTime(attr.name)) {
        // SystemTime attributes need normalization - buffer first, then normalize
        var buffer: [512]u8 = undefined;
        var fixed_writer = std.Io.Writer.fixed(&buffer);
        renderAttrValueNodes(attr.value.items, &fixed_writer) catch {};
        const written = fixed_writer.buffer[0..fixed_writer.end];
        try normalizeAndWriteSystemTimeAscii(writer, written);
    } else {
        try renderAttrValueNodes(attr.value.items, writer);
    }

    try writer.writeByte('"');
}

/// Render the opening tag start with all attributes (without closing >)
fn renderOpenTagStart(element: *const IR.Element, writer: *std.Io.Writer, indent: usize) WriterError!void {
    try writeSpaces(writer, indent);
    try writer.writeByte('<');
    try writeNameXml(element.name, writer);

    for (element.attrs.items) |*attr| {
        try renderAttribute(attr, writer);
    }
}

// ============================================================================
// Content Rendering
// ============================================================================

/// Render attribute value tokens to writer
fn renderAttrValueNodes(nodes: []const IR.Node, writer: *std.Io.Writer) WriterError!void {
    for (nodes) |node| switch (node) {
        .Text => |text| try util.writeUtf16LeXmlEscaped(writer, text.utf16, text.num_chars),
        .Pad => {},
        .Value => |val| try writeValueXml(writer, val.vtype, val.bytes),
        .Subst => {},
        .CharRef => |charref| try writer.print("&#{d};", .{charref}),
        .EntityRef => |name| {
            try writer.writeByte('&');
            try writeNameXml(name, writer);
            try writer.writeByte(';');
        },
        .CData => |cdata| try util.writeUtf16LeXmlEscaped(writer, cdata.utf16, cdata.num_chars),
        .PITarget => |name| {
            try writer.writeAll("<?");
            try writeNameXml(name, writer);
        },
        .PIData => |pidata| {
            try writer.writeByte(' ');
            try util.writeUtf16LeRawToUtf8(writer, pidata.utf16, pidata.num_chars);
            try writer.writeAll("?>");
        },
        .Element => {},
    };
}

/// Render text content from IR nodes
fn renderTextContentFromIR(nodes: []const IR.Node, writer: *std.Io.Writer) WriterError!void {
    for (nodes) |node| {
        switch (node) {
            .Text => |text| try util.writeUtf16LeXmlEscaped(writer, text.utf16, text.num_chars),
            .Pad => {},
            .Value => |val| try writeValueXml(writer, val.vtype, val.bytes),
            .Subst => {},
            .CharRef => |charref| try writer.print("&#{d};", .{charref}),
            .EntityRef => |name| {
                try writer.writeByte('&');
                try writeNameXml(name, writer);
                try writer.writeByte(';');
            },
            .CData => |cdata| {
                try writer.writeAll("<![CDATA[");
                try util.writeUtf16LeRawToUtf8(writer, cdata.utf16, cdata.num_chars);
                try writer.writeAll("]]>");
            },
            .PITarget => |name| {
                try writer.writeAll("<?");
                try writeNameXml(name, writer);
            },
            .PIData => |pidata| {
                try writer.writeByte(' ');
                try util.writeUtf16LeRawToUtf8(writer, pidata.utf16, pidata.num_chars);
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
fn renderElementIRXml(element: *const IR.Element, writer: *std.Io.Writer, indent: usize) WriterError!void {
    // Render opening tag with attributes
    try renderOpenTagStart(element, writer, indent);

    // Handle empty elements: <Name></Name>
    if (element.children.items.len == 0) {
        try writer.writeByte('>');
        try writeCloseTag(element, writer);
        return;
    }

    // Handle leaf elements (no child elements): <Name>content</Name>
    if (!element.has_element_child) {
        try writer.writeByte('>');
        try renderTextContentFromIR(element.children.items, writer);
        try writeCloseTag(element, writer);
        return;
    }

    // Handle elements with child elements: block form with newlines
    try writer.writeByte('>');
    try writer.writeByte('\n');

    for (element.children.items) |node| {
        switch (node) {
            .Element => |child_element| {
                try renderElementIRXml(child_element, writer, indent + 2);
            },
            .Subst => {},
            else => {
                try writeSpaces(writer, indent + 2);
                try renderTextContentFromIR(&[_]IR.Node{node}, writer);
                try writer.writeByte('\n');
            },
        }
    }

    try writeSpaces(writer, indent);
    try writeCloseTag(element, writer);
}

// ============================================================================
// Public API
// ============================================================================

/// Render XML from BinXML with context using concrete std.Io.Writer.
pub fn renderXmlWithContext(ctx: *Context, chunk: []const u8, bin: []const u8, writer: *std.Io.Writer) anyerror!void {
    if (ctx.verbose) logger.setModuleLevel("binxml", .trace);

    var builder = binxml.Builder.init(ctx);
    const root = try builder.build(chunk, bin);

    if (ctx.verbose) {
        try logNameTrace(root.name, "root");
    }

    try renderElementIRXml(root, writer, 0);
}

/// Render a single value payload to XML text according to its Binary XML type.
/// Uses the typed value_format module for clean, well-structured formatting.
pub fn writeValueXml(writer: *std.Io.Writer, raw_type: u8, data: []const u8) WriterError!void {
    try vf.formatValueXmlFromRaw(writer, raw_type, data);
}
