//! JSON rendering for BinXML IR structures.
//! Converts the intermediate representation into JSON output.
//!
//! This module uses Zig 0.15's concrete std.Io.Writer interface for all output,
//! enabling better debug-mode performance and eliminating generic code bloat.

const std = @import("std");
const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const util = @import("util.zig");
const attrNameIsSystemTime = @import("binxml/name.zig").attrNameIsSystemTime;
const vf = @import("value_format.zig");

/// Writer error type for all rendering functions.
pub const WriterError = std.Io.Writer.Error;

// ============================================================================
// Name and Value Writing
// ============================================================================

/// Write a value inline within a JSON string (no surrounding quotes).
/// This is used when a value appears as part of text content within a string.
fn writeValueInlineJson(writer: *std.Io.Writer, raw_type: u8, data: []const u8) WriterError!void {
    // For inline values in strings, we want the XML-style formatting (no quotes)
    try vf.formatValueXmlFromRaw(writer, raw_type, data);
}

// ============================================================================
// Content Rendering
// ============================================================================

/// Render IR nodes as a JSON string value
fn renderTextToJsonString(nodes: []const IR.Node, writer: *std.Io.Writer) WriterError!void {
    try writer.writeByte('"');
    for (nodes) |node| {
        switch (node) {
            .Text => |text| try util.writeUtf16LeJsonEscaped(writer, text.utf16, text.num_chars),
            .Pad => {},
            .Value => |val| try writeValueInlineJson(writer, val.vtype, val.bytes),
            .CharRef => |charref| try writer.print("&#{d};", .{charref}),
            .EntityRef => try writer.writeByte('&'),
            .CData => |cdata| try util.writeUtf16LeJsonEscaped(writer, cdata.utf16, cdata.num_chars),
            .PITarget, .PIData, .Element, .Subst => {},
        }
    }
    try writer.writeByte('"');
}

// ============================================================================
// Element Rendering
// ============================================================================

/// Check if an element is a simple leaf with string content
fn isLeafString(element: *const IR.Element) bool {
    return element.attrs.items.len == 0 and !element.has_element_child;
}

/// Write the body of an element as a JSON object
fn writeElementBodyJson(element: *const IR.Element, allocator: std.mem.Allocator, writer: *std.Io.Writer) anyerror!void {
    // Group child elements by name for proper JSON array handling
    var groups = std.StringHashMap(std.ArrayList(*IR.Element)).init(allocator);
    defer groups.deinit();

    var has_textual_content: bool = false;
    var textual_nodes: std.ArrayList(IR.Node) = .empty;
    defer textual_nodes.deinit(allocator);

    // Pre-allocate capacity for textual nodes
    if (element.children.items.len > 0) {
        try textual_nodes.ensureTotalCapacityPrecise(allocator, element.children.items.len);
    }

    // Categorize children into element groups and textual content
    for (element.children.items) |node| {
        switch (node) {
            .Element => |child| {
                // Convert name to UTF-8 key for grouping
                var key_alloc = std.Io.Writer.Allocating.init(allocator);
                defer key_alloc.deinit();
                try util.writeUtf16LeJsonEscaped(&key_alloc.writer, child.name.bytes, child.name.num_chars);
                const key = try key_alloc.toOwnedSlice();

                const entry = try groups.getOrPut(key);
                if (!entry.found_existing) {
                    entry.value_ptr.* = .empty;
                    try entry.value_ptr.ensureTotalCapacityPrecise(allocator, 2);
                }
                try entry.value_ptr.append(allocator, child);
            },
            else => {
                has_textual_content = true;
                try textual_nodes.append(allocator, node);
            },
        }
    }

    try writer.writeByte('{');
    var wrote_any = false;

    // Render attributes with @ prefix
    for (element.attrs.items) |attr| {
        if (wrote_any) try writer.writeByte(',');
        try writer.writeByte('"');
        try writer.writeByte('@');
        try util.writeUtf16LeJsonEscaped(writer, attr.name.bytes, attr.name.num_chars);
        try writer.writeAll("\":");

        // Special-case SystemTime normalization
        if (attrNameIsSystemTime(attr.name)) {
            var buffer: [256]u8 = undefined;
            var fixed_writer = std.Io.Writer.fixed(&buffer);
            for (attr.value.items) |node| {
                if (node == .Text) {
                    util.writeUtf16LeRawToUtf8(&fixed_writer, node.Text.utf16, node.Text.num_chars) catch {};
                }
            }
            try writer.writeByte('"');
            const written = fixed_writer.buffer[0..fixed_writer.end];
            try util.normalizeAndWriteSystemTimeAscii(writer, written);
            try writer.writeByte('"');
        } else {
            try renderTextToJsonString(attr.value.items, writer);
        }
        wrote_any = true;
    }

    // Render textual content as #text
    if (has_textual_content) {
        if (wrote_any) try writer.writeByte(',');
        try writer.writeAll("\"#text\":");
        try renderTextToJsonString(textual_nodes.items, writer);
        wrote_any = true;
    }

    // Render child element groups
    var iterator = groups.iterator();
    while (iterator.next()) |entry| {
        const key = entry.key_ptr.*;
        const children = entry.value_ptr.*;

        if (wrote_any) try writer.writeByte(',');
        try writer.writeByte('"');
        try util.jsonEscapeUtf8(writer, key);
        try writer.writeAll("\":");

        if (children.items.len == 1) {
            const child = children.items[0];
            if (isLeafString(child)) {
                // Render leaf element as string value
                var text_nodes: std.ArrayList(IR.Node) = .empty;
                defer text_nodes.deinit(allocator);
                for (child.children.items) |node| {
                    if (node != .Element) try text_nodes.append(allocator, node);
                }
                try renderTextToJsonString(text_nodes.items, writer);
            } else {
                try writeElementBodyJson(child, allocator, writer);
            }
        } else {
            // Multiple children with same name -> array
            try writer.writeByte('[');
            for (children.items, 0..) |child, i| {
                if (i > 0) try writer.writeByte(',');
                if (isLeafString(child)) {
                    var text_nodes: std.ArrayList(IR.Node) = .empty;
                    defer text_nodes.deinit(allocator);
                    for (child.children.items) |node| {
                        if (node != .Element) try text_nodes.append(allocator, node);
                    }
                    try renderTextToJsonString(text_nodes.items, writer);
                } else {
                    try writeElementBodyJson(child, allocator, writer);
                }
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

/// Render an IR element tree as JSON using concrete std.Io.Writer.
pub fn renderElementJson(root: *const IR.Element, allocator: std.mem.Allocator, writer: *std.Io.Writer) anyerror!void {
    try writeElementBodyJson(root, allocator, writer);
}
