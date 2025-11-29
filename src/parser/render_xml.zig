//! XML rendering for BinXML IR structures.
//! Converts the intermediate representation into properly formatted XML output.
//!
//! This module uses Zig 0.15's concrete std.Io.Writer interface for all output,
//! enabling better debug-mode performance and eliminating generic code bloat.

const std = @import("std");
const binxml = @import("binxml/mod.zig");
const Context = binxml.Context;
const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const util = @import("util.zig");
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

/// Write an element/attribute name (pre-converted UTF-8).
///
/// No escaping needed: XML NCName rules guarantee names contain only safe
/// characters ([a-zA-Z_][a-zA-Z0-9_.-]*). See IR.Name documentation.
fn writeNameXml(name: IR.Name, writer: *std.Io.Writer) WriterError!void {
    try writer.writeAll(name.utf8);
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
    try renderNodes(attr.value.items, writer, true);
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

/// Render IR nodes to XML. CData handling differs by context:
/// - In attributes: CData is XML-escaped (no CDATA wrapper allowed in attributes)
/// - In element content: CData uses <![CDATA[...]]> wrapper
fn renderNodes(nodes: []const IR.Node, writer: *std.Io.Writer, comptime in_attribute: bool) WriterError!void {
    for (nodes) |node| {
        switch (node) {
            .Text => |text| try util.writeUtf16LeXmlEscaped(writer, text.utf16, text.num_chars),
            .Value => |val| try vf.formatValueXmlFromRaw(writer, val.vtype, val.bytes),
            .CharRef => |charref| try writer.print("&#{d};", .{charref}),
            .EntityRef => |name| {
                try writer.writeByte('&');
                try writeNameXml(name, writer);
                try writer.writeByte(';');
            },
            .CData => |cdata| {
                if (in_attribute) {
                    // Attributes cannot contain CDATA sections - escape instead
                    try util.writeUtf16LeXmlEscaped(writer, cdata.utf16, cdata.num_chars);
                } else {
                    try writer.writeAll("<![CDATA[");
                    try util.writeUtf16LeRawToUtf8(writer, cdata.utf16, cdata.num_chars);
                    try writer.writeAll("]]>");
                }
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
            .Placeholder => unreachable, // ElementTree guarantees no placeholders
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
        try renderNodes(element.children.items, writer, false);
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
            else => {
                try writeSpaces(writer, indent + 2);
                try renderNodes(&[_]IR.Node{node}, writer, false);
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
/// Note: Callers should set logger level before calling if verbose output is needed.
pub fn renderXmlWithContext(ctx: *Context, chunk: []const u8, bin: []const u8, writer: *std.Io.Writer) anyerror!void {
    const tree = try binxml.parseRecord(ctx, chunk, bin);
    try renderElementIRXml(tree.element, writer, 0);
}
