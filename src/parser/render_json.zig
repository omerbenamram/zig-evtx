//! JSON rendering for BinXML IR structures.
//! Converts the intermediate representation into JSON output.
//!
//! This module uses Zig 0.15's concrete std.Io.Writer interface for all output,
//! enabling better debug-mode performance and eliminating generic code bloat.

const std = @import("std");
const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const util = @import("util.zig");
const vf = @import("value_format.zig");

/// Check if attribute name is "SystemTime" for special normalization.
fn attrNameIsSystemTime(name: IR.Name) bool {
    return util.utf16EqualsAscii(name.bytes, name.num_chars, "SystemTime");
}

/// Writer error type for all rendering functions.
pub const WriterError = std.Io.Writer.Error;

/// Key for grouping elements by name.
/// Uses content comparison to handle cases where same logical name
/// might have different pointers (inline vs cached names).
const NameKey = struct {
    bytes: []const u8,
    num_chars: usize,

    fn fromName(name: IR.Name) NameKey {
        return .{ .bytes = name.bytes, .num_chars = name.num_chars };
    }

    fn eql(self: NameKey, other: NameKey) bool {
        // Fast path: if lengths differ, not equal
        if (self.num_chars != other.num_chars) return false;
        // Fast path: pointer equality means same buffer
        if (self.bytes.ptr == other.bytes.ptr) return true;
        // Slow path: compare actual content
        return std.mem.eql(u8, self.bytes, other.bytes);
    }
};

/// Entry for counting unique element names during two-pass rendering.
const NameCount = struct {
    key: NameKey,
    count: u16,
    emitted: bool,
};

/// Maximum unique child element names we track before falling back.
/// Most XML elements have < 32 distinct child tag names.
const MAX_UNIQUE_NAMES: usize = 64;

// ============================================================================
// Content Rendering
// ============================================================================

/// Render IR nodes as JSON-escaped text content (without surrounding quotes)
fn renderJsonTextContent(nodes: []const IR.Node, writer: *std.Io.Writer) WriterError!void {
    for (nodes) |node| {
        switch (node) {
            .Text => |text| try util.writeUtf16LeJsonEscaped(writer, text.utf16, text.num_chars),
            .Value => |val| try vf.formatValueXmlFromRaw(writer, val.vtype, val.bytes),
            .CharRef => |charref| try writer.print("&#{d};", .{charref}),
            .EntityRef => try writer.writeByte('&'),
            .CData => |cdata| try util.writeUtf16LeJsonEscaped(writer, cdata.utf16, cdata.num_chars),
            .PITarget, .PIData, .Element => {},
            .Placeholder => unreachable, // ElementTree guarantees no placeholders
        }
    }
}

/// Render IR nodes as a JSON string value (with surrounding quotes)
fn renderTextToJsonString(nodes: []const IR.Node, writer: *std.Io.Writer) WriterError!void {
    try writer.writeByte('"');
    try renderJsonTextContent(nodes, writer);
    try writer.writeByte('"');
}

// ============================================================================
// Element Rendering
// ============================================================================

/// Check if an element is a simple leaf with string content
fn isLeafString(element: *const IR.Element) bool {
    return element.attrs.items.len == 0 and !element.has_element_child;
}

/// Write the body of an element as a JSON object.
///
/// ## Two-Pass Counting Algorithm
///
/// JSON requires grouping same-named XML elements into arrays:
/// ```xml
/// <Data Name="A">1</Data><Data Name="B">2</Data>
/// ```
/// becomes: `{"Data": [{"@Name":"A",...}, {"@Name":"B",...}]}`
///
/// We use a two-pass approach with zero heap allocation:
/// - Pass 1: Count occurrences of each unique tag name using a fixed stack array
/// - Pass 2: Emit JSON, using counts to decide single object vs array
///
/// This is O(n²) but n is tiny (typically <10 unique child tags per element).
/// The stack-based linear scan is faster than a HashMap due to cache locality
/// and zero allocator overhead.
fn writeElementBodyJson(element: *const IR.Element, allocator: std.mem.Allocator, writer: *std.Io.Writer) anyerror!void {
    // allocator only used for recursive calls

    // =========================================================================
    // PASS 1: Count unique element names
    // =========================================================================
    // Scan all children once to build a frequency table of tag names.
    // Uses a fixed stack array - no heap allocation. Linear search is O(n²)
    // overall but faster than HashMap for small n due to cache locality and
    // zero allocator overhead.
    var name_counts: [MAX_UNIQUE_NAMES]NameCount = undefined;
    var num_unique: usize = 0;
    var has_textual_content: bool = false;

    for (element.children.items) |node| {
        switch (node) {
            .Element => |child| {
                const key = NameKey.fromName(child.name);
                // Linear search - fast for small n, cache-friendly, no allocation
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
            else => has_textual_content = true,
        }
    }

    // =========================================================================
    // PASS 2: Emit JSON using the counts from Pass 1
    // =========================================================================
    // Now we know how many times each tag name appears:
    // - count == 1: emit as single object  {"Tag": {...}}
    // - count > 1:  emit as array           {"Tag": [{...}, {...}]}
    //
    // We iterate children in document order, but only emit each unique tag name
    // once (on first occurrence). The `emitted` flag prevents duplicate keys.
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
        try renderTextToJsonString(element.children.items, writer);
        wrote_any = true;
    }

    // Render child elements grouped by name.
    // Process in document order, emitting each unique tag name only once.
    // When we encounter the first element with a given name, we look up its
    // count and emit either a single object or an array of all matching elements.
    for (element.children.items) |node| {
        if (node != .Element) continue;
        const child = node.Element;
        const key = NameKey.fromName(child.name);

        // Look up this name's count and check if we've already emitted it
        var count: u16 = 1;
        var nc_ptr: ?*NameCount = null;
        for (name_counts[0..num_unique]) |*nc| {
            if (nc.key.eql(key)) {
                if (nc.emitted) break; // Already output all elements with this name
                nc.emitted = true; // Mark as processed to prevent duplicate JSON keys
                count = nc.count;
                nc_ptr = nc;
                break;
            }
        }
        if (nc_ptr == null) continue; // Skip - already emitted or not in our tracking array

        if (wrote_any) try writer.writeByte(',');
        try writer.writeByte('"');
        try util.writeUtf16LeJsonEscaped(writer, child.name.bytes, child.name.num_chars);
        try writer.writeAll("\":");

        if (count == 1) {
            // Single element - emit directly
            if (isLeafString(child)) {
                try renderTextToJsonString(child.children.items, writer);
            } else {
                try writeElementBodyJson(child, allocator, writer);
            }
        } else {
            // Multiple elements with same name - emit as array
            try writer.writeByte('[');
            var first = true;
            // Re-scan children for all matching this name
            for (element.children.items) |node2| {
                if (node2 != .Element) continue;
                const c = node2.Element;
                if (!NameKey.fromName(c.name).eql(key)) continue;

                if (!first) try writer.writeByte(',');
                first = false;
                if (isLeafString(c)) {
                    try renderTextToJsonString(c.children.items, writer);
                } else {
                    try writeElementBodyJson(c, allocator, writer);
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
