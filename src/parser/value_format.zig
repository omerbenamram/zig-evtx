//! Value formatting utilities for BinXML types.
//! Provides typed formatters that write to any std.io.Writer.
//! Shared between XML and JSON renderers.

const std = @import("std");
const vr = @import("binxml/value_reader.zig");
const ValueType = @import("binxml/types.zig").ValueType;
const util = @import("util.zig");

// ============================================================================
// GUID Formatting
// ============================================================================

/// Format a GUID as XML: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
pub fn formatGuidXml(w: anytype, guid: vr.Guid) !void {
    try w.print("{{{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}}}", .{
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

/// Format a GUID as JSON string (with quotes): "{...}"
pub fn formatGuidJson(w: anytype, guid: vr.Guid) !void {
    try w.writeByte('"');
    try formatGuidXml(w, guid);
    try w.writeByte('"');
}

// ============================================================================
// SID Formatting
// ============================================================================

/// Format a SID as XML: S-1-5-21-...
pub fn formatSidXml(w: anytype, sid: vr.Sid) !void {
    try w.print("S-{d}-{d}", .{ sid.revision, sid.id_authority });
    var i: usize = 0;
    while (i < sid.sub_authority_count) : (i += 1) {
        if (sid.getSubAuthority(i)) |sub| {
            try w.print("-{d}", .{sub});
        }
    }
}

/// Format a SID as JSON string (with quotes): "S-1-5-..."
pub fn formatSidJson(w: anytype, sid: vr.Sid) !void {
    try w.writeByte('"');
    try formatSidXml(w, sid);
    try w.writeByte('"');
}

// ============================================================================
// Time Formatting
// ============================================================================

/// Format a FILETIME as ISO8601 UTC string
pub fn formatFileTimeXml(w: anytype, ft: vr.FileTime) !void {
    var buf: [40]u8 = undefined;
    const out = util.formatIso8601UtcFromFiletimeMicros(&buf, ft.raw) catch {
        // Fallback to raw numeric
        return try w.print("{d}", .{ft.raw});
    };
    try w.writeAll(out);
}

/// Format a FILETIME as JSON string (with quotes)
pub fn formatFileTimeJson(w: anytype, ft: vr.FileTime) !void {
    try w.writeByte('"');
    try formatFileTimeXml(w, ft);
    try w.writeByte('"');
}

/// Format a SYSTEMTIME as ISO8601 string
pub fn formatSystemTimeXml(w: anytype, st: vr.SystemTime) !void {
    var buf: [32]u8 = undefined;
    const slice = try std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        st.year,
        st.month,
        st.day,
        st.hour,
        st.minute,
        st.second,
        st.milliseconds,
    });
    try w.writeAll(slice);
}

/// Format a SYSTEMTIME as JSON string (with quotes)
pub fn formatSystemTimeJson(w: anytype, st: vr.SystemTime) !void {
    try w.writeByte('"');
    try formatSystemTimeXml(w, st);
    try w.writeByte('"');
}

// ============================================================================
// Numeric Formatting
// ============================================================================

/// Format a signed integer as decimal
pub fn formatSignedDecimal(w: anytype, comptime T: type, value: T) !void {
    var buf: [24]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{d}", .{value});
    try w.writeAll(s);
}

/// Format an unsigned integer as decimal
pub fn formatUnsignedDecimal(w: anytype, comptime T: type, value: T) !void {
    var buf: [24]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{d}", .{value});
    try w.writeAll(s);
}

/// Format a hex integer (uppercase, with 0x prefix)
pub fn formatHexUpper(w: anytype, comptime T: type, value: T) !void {
    try w.print("0x{X}", .{value});
}

/// Format a hex integer as JSON string
pub fn formatHexUpperJson(w: anytype, comptime T: type, value: T) !void {
    try w.print("\"0x{X}\"", .{value});
}

// ============================================================================
// Float Formatting
// ============================================================================

/// Format f32, handling NaN and Inf specially
pub fn formatFloat32Xml(w: anytype, f: f32) !void {
    if (std.math.isNan(f)) return try w.writeAll("-1.#IND");
    if (std.math.isInf(f)) return try w.writeAll(if (f > 0) "1.#INF" else "-1.#INF");
    try w.print("{d}", .{f});
}

/// Format f64, handling NaN and Inf specially
pub fn formatFloat64Xml(w: anytype, f: f64) !void {
    if (std.math.isNan(f)) return try w.writeAll("-1.#IND");
    if (std.math.isInf(f)) return try w.writeAll(if (f > 0) "1.#INF" else "-1.#INF");
    try w.print("{d}", .{f});
}

/// Format f32 for JSON (NaN/Inf as strings)
pub fn formatFloat32Json(w: anytype, f: f32) !void {
    if (std.math.isNan(f)) return try w.writeAll("\"-1.#IND\"");
    if (std.math.isInf(f)) return try w.writeAll(if (f > 0) "\"1.#INF\"" else "\"-1.#INF\"");
    try w.print("{d}", .{f});
}

/// Format f64 for JSON (NaN/Inf as strings)
pub fn formatFloat64Json(w: anytype, f: f64) !void {
    if (std.math.isNan(f)) return try w.writeAll("\"-1.#IND\"");
    if (std.math.isInf(f)) return try w.writeAll(if (f > 0) "\"1.#INF\"" else "\"-1.#INF\"");
    try w.print("{d}", .{f});
}

// ============================================================================
// Boolean Formatting
// ============================================================================

pub fn formatBoolXml(w: anytype, value: bool) !void {
    try w.writeAll(if (value) "true" else "false");
}

pub fn formatBoolJson(w: anytype, value: bool) !void {
    try w.writeAll(if (value) "true" else "false");
}

// ============================================================================
// Binary/Hex Formatting
// ============================================================================

/// Write bytes as lowercase hex string
pub fn formatHexBytesLower(w: anytype, bytes: []const u8) !void {
    const hex_chars = "0123456789abcdef";
    for (bytes) |b| {
        try w.writeByte(hex_chars[b >> 4]);
        try w.writeByte(hex_chars[b & 0x0F]);
    }
}

/// Write bytes as lowercase hex string with quotes for JSON
pub fn formatHexBytesLowerJson(w: anytype, bytes: []const u8) !void {
    try w.writeByte('"');
    try formatHexBytesLower(w, bytes);
    try w.writeByte('"');
}

// ============================================================================
// String Formatting
// ============================================================================

/// Format UTF-16LE string for XML (with escaping)
pub fn formatUtf16StringXml(w: anytype, data: []const u8) !void {
    if (data.len == 0) return;
    if ((data.len & 1) != 0) return; // Invalid: odd byte count
    var num = data.len / 2;
    // Strip trailing NUL if present
    if (num > 0) {
        const last = std.mem.readInt(u16, data[data.len - 2 .. data.len][0..2], .little);
        if (last == 0) num -= 1;
    }
    if (num == 0) return;
    try util.writeUtf16LeXmlEscaped(w, data[0 .. num * 2], num);
}

/// Format UTF-16LE string for JSON (with quotes and escaping)
pub fn formatUtf16StringJson(w: anytype, data: []const u8) !void {
    try w.writeByte('"');
    if (data.len == 0) {
        try w.writeByte('"');
        return;
    }
    if ((data.len & 1) != 0) {
        try w.writeByte('"');
        return;
    }
    var num = data.len / 2;
    if (num > 0) {
        const last = std.mem.readInt(u16, data[data.len - 2 .. data.len][0..2], .little);
        if (last == 0) num -= 1;
    }
    if (num > 0) try util.writeUtf16LeJsonEscaped(w, data[0 .. num * 2], num);
    try w.writeByte('"');
}

/// Format ANSI (CP-1252) string for XML (with escaping)
pub fn formatAnsiStringXml(w: anytype, data: []const u8) !void {
    try util.writeAnsiCp1252Escaped(w, data);
}

/// Format ANSI (CP-1252) string for JSON (with quotes and escaping)
pub fn formatAnsiStringJson(w: anytype, data: []const u8) !void {
    try w.writeByte('"');
    try util.writeAnsiCp1252JsonEscaped(w, data);
    try w.writeByte('"');
}

// ============================================================================
// Main Entry Point: Format by ValueType
// ============================================================================

/// Format a binary value to XML based on its ValueType.
/// Returns without writing anything if data is insufficient.
pub fn formatValueXml(w: anytype, vtype: ValueType, data: []const u8) !void {
    switch (vtype) {
        .null => {},
        .string => try formatUtf16StringXml(w, data),
        .ansi_string => try formatAnsiStringXml(w, data),
        .int8 => if (vr.readInt(i8, data)) |v| try formatSignedDecimal(w, i8, v),
        .uint8 => if (vr.readInt(u8, data)) |v| try formatUnsignedDecimal(w, u8, v),
        .int16 => if (vr.readInt(i16, data)) |v| try formatSignedDecimal(w, i16, v),
        .uint16 => if (vr.readInt(u16, data)) |v| try formatUnsignedDecimal(w, u16, v),
        .int32 => if (vr.readInt(i32, data)) |v| try formatSignedDecimal(w, i32, v),
        .uint32 => if (vr.readInt(u32, data)) |v| try formatUnsignedDecimal(w, u32, v),
        .int64 => if (vr.readInt(i64, data)) |v| try formatSignedDecimal(w, i64, v),
        .uint64 => if (vr.readInt(u64, data)) |v| try formatUnsignedDecimal(w, u64, v),
        .real32 => if (vr.readFloat32(data)) |f| try formatFloat32Xml(w, f),
        .real64 => if (vr.readFloat64(data)) |f| try formatFloat64Xml(w, f),
        .bool => if (vr.readBool(data)) |b| try formatBoolXml(w, b),
        .binary => try formatHexBytesLower(w, data),
        .guid => if (vr.readGuid(data)) |g| try formatGuidXml(w, g),
        .size_t => {
            // Variable size: 8 bytes preferred, 4 bytes fallback
            if (vr.readInt(u64, data)) |v| {
                try formatHexUpper(w, u64, v);
            } else if (vr.readInt(u32, data)) |v| {
                try formatHexUpper(w, u32, v);
            }
        },
        .filetime => if (vr.readFileTime(data)) |ft| try formatFileTimeXml(w, ft),
        .systime => if (vr.readSystemTime(data)) |st| try formatSystemTimeXml(w, st),
        .sid => if (vr.readSid(data)) |s| try formatSidXml(w, s),
        .hex_int32 => if (vr.readInt(u32, data)) |v| try formatHexUpper(w, u32, v),
        .hex_int64 => if (vr.readInt(u64, data)) |v| try formatHexUpper(w, u64, v),
        .evt_handle => {
            if (vr.readInt(u64, data)) |v| {
                try formatUnsignedDecimal(w, u64, v);
            } else if (vr.readInt(u32, data)) |v| {
                try formatUnsignedDecimal(w, u32, v);
            }
        },
        .bin_xml => {}, // Nested BinXML - handled specially by caller
        .evt_xml => try formatHexBytesLower(w, data),
        // Array types are handled by caller iterating elements
        else => {},
    }
}

/// Format a binary value to JSON based on its ValueType.
pub fn formatValueJson(w: anytype, vtype: ValueType, data: []const u8) !void {
    switch (vtype) {
        .null => try w.writeAll("null"),
        .string => try formatUtf16StringJson(w, data),
        .ansi_string => try formatAnsiStringJson(w, data),
        .int8 => if (vr.readInt(i8, data)) |v| try formatSignedDecimal(w, i8, v) else try w.writeAll("null"),
        .uint8 => if (vr.readInt(u8, data)) |v| try formatUnsignedDecimal(w, u8, v) else try w.writeAll("null"),
        .int16 => if (vr.readInt(i16, data)) |v| try formatSignedDecimal(w, i16, v) else try w.writeAll("null"),
        .uint16 => if (vr.readInt(u16, data)) |v| try formatUnsignedDecimal(w, u16, v) else try w.writeAll("null"),
        .int32 => if (vr.readInt(i32, data)) |v| try formatSignedDecimal(w, i32, v) else try w.writeAll("null"),
        .uint32 => if (vr.readInt(u32, data)) |v| try formatUnsignedDecimal(w, u32, v) else try w.writeAll("null"),
        .int64 => if (vr.readInt(i64, data)) |v| try formatSignedDecimal(w, i64, v) else try w.writeAll("null"),
        .uint64 => if (vr.readInt(u64, data)) |v| try formatUnsignedDecimal(w, u64, v) else try w.writeAll("null"),
        .real32 => if (vr.readFloat32(data)) |f| try formatFloat32Json(w, f) else try w.writeAll("null"),
        .real64 => if (vr.readFloat64(data)) |f| try formatFloat64Json(w, f) else try w.writeAll("null"),
        .bool => if (vr.readBool(data)) |b| try formatBoolJson(w, b) else try w.writeAll("null"),
        .binary => try formatHexBytesLowerJson(w, data),
        .guid => if (vr.readGuid(data)) |g| try formatGuidJson(w, g) else try w.writeAll("null"),
        .size_t => {
            if (vr.readInt(u64, data)) |v| {
                try formatHexUpperJson(w, u64, v);
            } else if (vr.readInt(u32, data)) |v| {
                try formatHexUpperJson(w, u32, v);
            } else try w.writeAll("null");
        },
        .filetime => if (vr.readFileTime(data)) |ft| try formatFileTimeJson(w, ft) else try w.writeAll("null"),
        .systime => if (vr.readSystemTime(data)) |st| try formatSystemTimeJson(w, st) else try w.writeAll("null"),
        .sid => if (vr.readSid(data)) |s| try formatSidJson(w, s) else try w.writeAll("null"),
        .hex_int32 => if (vr.readInt(u32, data)) |v| try formatHexUpperJson(w, u32, v) else try w.writeAll("null"),
        .hex_int64 => if (vr.readInt(u64, data)) |v| try formatHexUpperJson(w, u64, v) else try w.writeAll("null"),
        .evt_handle => {
            if (vr.readInt(u64, data)) |v| {
                try formatUnsignedDecimal(w, u64, v);
            } else if (vr.readInt(u32, data)) |v| {
                try formatUnsignedDecimal(w, u32, v);
            } else try w.writeAll("0");
        },
        .bin_xml => try w.writeAll("null"),
        .evt_xml => try formatHexBytesLowerJson(w, data),
        else => try w.writeAll("null"),
    }
}

/// Convenience: format from raw u8 type code (masks off array flag internally)
pub fn formatValueXmlFromRaw(w: anytype, raw_type: u8, data: []const u8) !void {
    const base = raw_type & 0x7F;
    const vtype = std.meta.intToEnum(ValueType, base) catch return;
    try formatValueXml(w, vtype, data);
}

/// Convenience: format from raw u8 type code for JSON
pub fn formatValueJsonFromRaw(w: anytype, raw_type: u8, data: []const u8) !void {
    const base = raw_type & 0x7F;
    const vtype = std.meta.intToEnum(ValueType, base) catch {
        try w.writeAll("null");
        return;
    };
    try formatValueJson(w, vtype, data);
}

// ============================================================================
// Unit Tests
// ============================================================================

test "formatGuidXml produces correct output" {
    // GUID: {12345678-1234-5678-1234-567812345678}
    const data = [_]u8{
        0x78, 0x56, 0x34, 0x12, // data1 LE
        0x34, 0x12, // data2 LE
        0x78, 0x56, // data3 LE
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, // data4
    };
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try formatGuidXml(fbs.writer(), vr.readGuid(&data).?);
    try std.testing.expectEqualStrings("{12345678-1234-5678-1234-567812345678}", fbs.getWritten());
}

test "formatGuidJson includes quotes" {
    const data = [_]u8{
        0x78, 0x56, 0x34, 0x12,
        0x34, 0x12, 0x78, 0x56,
        0x12, 0x34, 0x56, 0x78,
        0x12, 0x34, 0x56, 0x78,
    };
    var buf: [72]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try formatGuidJson(fbs.writer(), vr.readGuid(&data).?);
    try std.testing.expectEqualStrings("\"{12345678-1234-5678-1234-567812345678}\"", fbs.getWritten());
}

test "formatSidXml formats SYSTEM SID" {
    // S-1-5-18 (SYSTEM)
    const data = [_]u8{
        0x01, // revision
        0x01, // sub-authority count
        0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // id authority (5) BE
        0x12, 0x00, 0x00, 0x00, // sub-authority 18 LE
    };
    var buf: [32]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try formatSidXml(fbs.writer(), vr.readSid(&data).?);
    try std.testing.expectEqualStrings("S-1-5-18", fbs.getWritten());
}

test "formatSidXml formats multi-subauth SID" {
    // S-1-5-21-100-200-300-1001
    const data = [_]u8{
        0x01, // revision
        0x05, // sub-authority count (5)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // id authority (5) BE
        0x15, 0x00, 0x00, 0x00, // 21
        0x64, 0x00, 0x00, 0x00, // 100
        0xC8, 0x00, 0x00, 0x00, // 200
        0x2C, 0x01, 0x00, 0x00, // 300
        0xE9, 0x03, 0x00, 0x00, // 1001
    };
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try formatSidXml(fbs.writer(), vr.readSid(&data).?);
    try std.testing.expectEqualStrings("S-1-5-21-100-200-300-1001", fbs.getWritten());
}

test "formatFileTimeXml formats timestamp" {
    // Known FILETIME value
    const data = [_]u8{ 0x00, 0x80, 0x3E, 0xD5, 0xDE, 0xB1, 0x9D, 0x01 };
    var buf: [40]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const ft = vr.readFileTime(&data).?;
    try formatFileTimeXml(fbs.writer(), ft);
    // Should produce some output (either ISO8601 or raw number)
    const result = fbs.getWritten();
    try std.testing.expect(result.len > 0);
}

test "formatSystemTimeXml formats correctly" {
    // 2024-01-15 10:30:45.123
    const data = [_]u8{
        0xE8, 0x07, // year 2024
        0x01, 0x00, // month 1
        0x01, 0x00, // day of week
        0x0F, 0x00, // day 15
        0x0A, 0x00, // hour 10
        0x1E, 0x00, // minute 30
        0x2D, 0x00, // second 45
        0x7B, 0x00, // milliseconds 123
    };
    var buf: [32]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try formatSystemTimeXml(fbs.writer(), vr.readSystemTime(&data).?);
    try std.testing.expectEqualStrings("2024-01-15T10:30:45.123Z", fbs.getWritten());
}

test "formatValueXml with int32" {
    const data = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }; // -1
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try formatValueXml(fbs.writer(), .int32, &data);
    try std.testing.expectEqualStrings("-1", fbs.getWritten());
}

test "formatValueXml with uint32" {
    const data = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }; // 4294967295
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try formatValueXml(fbs.writer(), .uint32, &data);
    try std.testing.expectEqualStrings("4294967295", fbs.getWritten());
}

test "formatValueXml with bool" {
    const true_data = [_]u8{ 0x01, 0x00, 0x00, 0x00 };
    const false_data = [_]u8{ 0x00, 0x00, 0x00, 0x00 };

    var buf: [8]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try formatValueXml(fbs.writer(), .bool, &true_data);
    try std.testing.expectEqualStrings("true", fbs.getWritten());

    fbs.reset();
    try formatValueXml(fbs.writer(), .bool, &false_data);
    try std.testing.expectEqualStrings("false", fbs.getWritten());
}

test "formatValueXml with hex_int32" {
    const data = [_]u8{ 0xAB, 0xCD, 0x00, 0x00 }; // 0xCDAB
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try formatValueXml(fbs.writer(), .hex_int32, &data);
    try std.testing.expectEqualStrings("0xCDAB", fbs.getWritten());
}

test "formatValueXml with truncated data returns gracefully" {
    const short_data = [_]u8{ 0x01, 0x02 }; // Only 2 bytes, int32 needs 4
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try formatValueXml(fbs.writer(), .int32, &short_data);
    try std.testing.expectEqualStrings("", fbs.getWritten()); // Nothing written
}

test "formatHexBytesLower produces lowercase hex" {
    const data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try formatHexBytesLower(fbs.writer(), &data);
    try std.testing.expectEqualStrings("deadbeef", fbs.getWritten());
}

test "formatFloat32Xml handles special values" {
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    // NaN
    try formatFloat32Xml(fbs.writer(), std.math.nan(f32));
    try std.testing.expectEqualStrings("-1.#IND", fbs.getWritten());

    // +Inf
    fbs.reset();
    try formatFloat32Xml(fbs.writer(), std.math.inf(f32));
    try std.testing.expectEqualStrings("1.#INF", fbs.getWritten());

    // -Inf
    fbs.reset();
    try formatFloat32Xml(fbs.writer(), -std.math.inf(f32));
    try std.testing.expectEqualStrings("-1.#INF", fbs.getWritten());
}

test "formatValueXmlFromRaw strips array flag" {
    const data = [_]u8{ 0x2A, 0x00, 0x00, 0x00 }; // 42
    var buf: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    // 0x88 = 0x80 | 0x08 = array flag | uint32
    try formatValueXmlFromRaw(fbs.writer(), 0x88, &data);
    try std.testing.expectEqualStrings("42", fbs.getWritten());
}
