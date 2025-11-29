//! Value formatting utilities for BinXML types.
//! Uses concrete std.Io.Writer interface for better performance.

const std = @import("std");
const vr = @import("binxml/value_reader.zig");
const ValueType = @import("binxml/types.zig").ValueType;
const util = @import("util.zig");

// ============================================================================
// Concrete std.Io.Writer Variants (Zig 0.15+)
// ============================================================================
// These functions use the non-generic std.Io.Writer interface for better
// debug-mode performance and reduced code bloat.

/// Writer error type for concrete Io functions.
pub const WriterError = std.Io.Writer.Error;

/// Format a GUID as XML to concrete std.Io.Writer.
pub fn formatGuidXml(w: *std.Io.Writer, guid: vr.Guid) WriterError!void {
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

/// Format a SID as XML to concrete std.Io.Writer.
pub fn formatSidXml(w: *std.Io.Writer, sid: vr.Sid) WriterError!void {
    try w.print("S-{d}-{d}", .{ sid.revision, sid.id_authority });
    var i: usize = 0;
    while (i < sid.sub_authority_count) : (i += 1) {
        if (sid.getSubAuthority(i)) |sub| {
            try w.print("-{d}", .{sub});
        }
    }
}

/// Format a FILETIME as ISO8601 UTC string to concrete std.Io.Writer.
pub fn formatFileTimeXml(w: *std.Io.Writer, ft: vr.FileTime) WriterError!void {
    var buf: [40]u8 = undefined;
    const out = util.formatIso8601UtcFromFiletimeMicros(&buf, ft.raw) catch return;
    try w.writeAll(out);
}

/// Format a SYSTEMTIME as ISO8601 string to concrete std.Io.Writer.
pub fn formatSystemTimeXml(w: *std.Io.Writer, st: vr.SystemTime) WriterError!void {
    var buf: [32]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        st.year,
        st.month,
        st.day,
        st.hour,
        st.minute,
        st.second,
        st.milliseconds,
    }) catch return;
    try w.writeAll(slice);
}

/// Format any integer as decimal to concrete std.Io.Writer.
pub fn formatDecimal(w: *std.Io.Writer, comptime T: type, value: T) WriterError!void {
    var buf: [24]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return;
    try w.writeAll(s);
}

/// Read and format an integer to concrete std.Io.Writer.
pub fn readAndFormatInt(w: *std.Io.Writer, comptime T: type, data: []const u8) WriterError!bool {
    if (vr.readValue(T, data)) |v| {
        try formatDecimal(w, T, v);
        return true;
    }
    return false;
}

/// Format a hex integer to concrete std.Io.Writer.
pub fn formatHexUpper(w: *std.Io.Writer, comptime T: type, value: T) WriterError!void {
    try w.print("0x{X}", .{value});
}

/// Format f32 to concrete std.Io.Writer.
pub fn formatFloat32Xml(w: *std.Io.Writer, f: f32) WriterError!void {
    if (std.math.isNan(f)) return try w.writeAll("-1.#IND");
    if (std.math.isInf(f)) return try w.writeAll(if (f > 0) "1.#INF" else "-1.#INF");
    try w.print("{d}", .{f});
}

/// Format f64 to concrete std.Io.Writer.
pub fn formatFloat64Xml(w: *std.Io.Writer, f: f64) WriterError!void {
    if (std.math.isNan(f)) return try w.writeAll("-1.#IND");
    if (std.math.isInf(f)) return try w.writeAll(if (f > 0) "1.#INF" else "-1.#INF");
    try w.print("{d}", .{f});
}

/// Format boolean to concrete std.Io.Writer.
pub fn formatBool(w: *std.Io.Writer, value: bool) WriterError!void {
    try w.writeAll(if (value) "true" else "false");
}

/// Write bytes as lowercase hex string to concrete std.Io.Writer.
pub fn formatHexBytesLower(w: *std.Io.Writer, bytes: []const u8) WriterError!void {
    const hex_chars = "0123456789abcdef";
    for (bytes) |b| {
        try w.writeByte(hex_chars[b >> 4]);
        try w.writeByte(hex_chars[b & 0x0F]);
    }
}

/// Format UTF-16LE string for XML to concrete std.Io.Writer.
/// Trims null terminator and trailing spaces to match Rust evtx_dump behavior.
pub fn formatUtf16StringXml(w: *std.Io.Writer, data: []const u8) WriterError!void {
    if (data.len == 0) return;
    if ((data.len & 1) != 0) return;
    var num = data.len / 2;
    // Remove null terminator
    if (num > 0) {
        const last = std.mem.readInt(u16, data[data.len - 2 .. data.len][0..2], .little);
        if (last == 0) num -= 1;
    }
    // Trim trailing spaces (0x0020 in UTF-16LE)
    while (num > 0) {
        const pos = (num - 1) * 2;
        const ch = std.mem.readInt(u16, data[pos..][0..2], .little);
        if (ch != 0x0020) break;
        num -= 1;
    }
    if (num == 0) return;
    try util.writeUtf16LeXmlEscaped(w, data[0 .. num * 2], num);
}

/// Format ANSI string for XML to concrete std.Io.Writer.
pub fn formatAnsiStringXml(w: *std.Io.Writer, data: []const u8) WriterError!void {
    try util.writeAnsiCp1252Escaped(w, data);
}

/// Format a binary value to XML based on its ValueType to concrete std.Io.Writer.
pub fn formatValueXml(w: *std.Io.Writer, vtype: ValueType, data: []const u8) WriterError!void {
    switch (vtype) {
        .null => {},
        .string => try formatUtf16StringXml(w, data),
        .ansi_string => try formatAnsiStringXml(w, data),
        .int8 => _ = try readAndFormatInt(w, i8, data),
        .uint8 => _ = try readAndFormatInt(w, u8, data),
        .int16 => _ = try readAndFormatInt(w, i16, data),
        .uint16 => _ = try readAndFormatInt(w, u16, data),
        .int32 => _ = try readAndFormatInt(w, i32, data),
        .uint32 => _ = try readAndFormatInt(w, u32, data),
        .int64 => _ = try readAndFormatInt(w, i64, data),
        .uint64 => _ = try readAndFormatInt(w, u64, data),
        .real32 => if (vr.readValue(f32, data)) |f| try formatFloat32Xml(w, f),
        .real64 => if (vr.readValue(f64, data)) |f| try formatFloat64Xml(w, f),
        .bool => if (vr.readValue(bool, data)) |b| try formatBool(w, b),
        .binary => try formatHexBytesLower(w, data),
        .guid => if (vr.readGuid(data)) |g| try formatGuidXml(w, g),
        .size_t => {
            if (data.len >= 8) {
                if (vr.readValue(u64, data)) |v| try formatHexUpper(w, u64, v);
            } else if (data.len >= 4) {
                if (vr.readValue(u32, data)) |v| try formatHexUpper(w, u32, v);
            }
        },
        .filetime => if (vr.readFileTime(data)) |ft| try formatFileTimeXml(w, ft),
        .systime => if (vr.readSystemTime(data)) |st| try formatSystemTimeXml(w, st),
        .sid => if (vr.readSid(data)) |s| try formatSidXml(w, s),
        .hex_int32 => if (vr.readValue(u32, data)) |v| try formatHexUpper(w, u32, v),
        .hex_int64 => if (vr.readValue(u64, data)) |v| try formatHexUpper(w, u64, v),
        .evt_handle => {
            if (data.len >= 8) {
                if (vr.readValue(u64, data)) |v| try formatDecimal(w, u64, v);
            } else if (data.len >= 4) {
                if (vr.readValue(u32, data)) |v| try formatDecimal(w, u32, v);
            }
        },
        .bin_xml => {},
        .evt_xml => try formatHexBytesLower(w, data),
        else => {},
    }
}

/// Convenience: format from raw u8 type code for XML to concrete std.Io.Writer.
pub fn formatValueXmlFromRaw(w: *std.Io.Writer, raw_type: u8, data: []const u8) WriterError!void {
    const base = raw_type & 0x7F;
    const vtype = std.meta.intToEnum(ValueType, base) catch return;
    try formatValueXml(w, vtype, data);
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
    var w = std.Io.Writer.fixed(&buf);
    try formatGuidXml(&w, vr.readGuid(&data).?);
    try std.testing.expectEqualStrings("{12345678-1234-5678-1234-567812345678}", buf[0..w.end]);
}

test "formatGuidJson includes quotes" {
    const data = [_]u8{
        0x78, 0x56, 0x34, 0x12,
        0x34, 0x12, 0x78, 0x56,
        0x12, 0x34, 0x56, 0x78,
        0x12, 0x34, 0x56, 0x78,
    };
    var buf: [72]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try w.writeByte('"');
    try formatGuidXml(&w, vr.readGuid(&data).?);
    try w.writeByte('"');
    try std.testing.expectEqualStrings("\"{12345678-1234-5678-1234-567812345678}\"", buf[0..w.end]);
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
    var w = std.Io.Writer.fixed(&buf);
    try formatSidXml(&w, vr.readSid(&data).?);
    try std.testing.expectEqualStrings("S-1-5-18", buf[0..w.end]);
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
    var w = std.Io.Writer.fixed(&buf);
    try formatSidXml(&w, vr.readSid(&data).?);
    try std.testing.expectEqualStrings("S-1-5-21-100-200-300-1001", buf[0..w.end]);
}

test "formatFileTimeXml formats timestamp" {
    // Known FILETIME value
    const data = [_]u8{ 0x00, 0x80, 0x3E, 0xD5, 0xDE, 0xB1, 0x9D, 0x01 };
    var buf: [40]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const ft = vr.readFileTime(&data).?;
    try formatFileTimeXml(&w, ft);
    // Should produce some output (either ISO8601 or raw number)
    try std.testing.expect(w.end > 0);
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
    var w = std.Io.Writer.fixed(&buf);
    try formatSystemTimeXml(&w, vr.readSystemTime(&data).?);
    try std.testing.expectEqualStrings("2024-01-15T10:30:45.123Z", buf[0..w.end]);
}

test "formatValueXml with int32" {
    const data = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }; // -1
    var buf: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try formatValueXml(&w, .int32, &data);
    try std.testing.expectEqualStrings("-1", buf[0..w.end]);
}

test "formatValueXml with uint32" {
    const data = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }; // 4294967295
    var buf: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try formatValueXml(&w, .uint32, &data);
    try std.testing.expectEqualStrings("4294967295", buf[0..w.end]);
}

test "formatValueXml with bool" {
    const true_data = [_]u8{ 0x01, 0x00, 0x00, 0x00 };
    const false_data = [_]u8{ 0x00, 0x00, 0x00, 0x00 };

    var buf: [8]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);

    try formatValueXml(&w, .bool, &true_data);
    try std.testing.expectEqualStrings("true", buf[0..w.end]);

    w = std.Io.Writer.fixed(&buf);
    try formatValueXml(&w, .bool, &false_data);
    try std.testing.expectEqualStrings("false", buf[0..w.end]);
}

test "formatValueXml with hex_int32" {
    const data = [_]u8{ 0xAB, 0xCD, 0x00, 0x00 }; // 0xCDAB
    var buf: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try formatValueXml(&w, .hex_int32, &data);
    try std.testing.expectEqualStrings("0xCDAB", buf[0..w.end]);
}

test "formatValueXml with truncated data returns gracefully" {
    const short_data = [_]u8{ 0x01, 0x02 }; // Only 2 bytes, int32 needs 4
    var buf: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try formatValueXml(&w, .int32, &short_data);
    try std.testing.expectEqualStrings("", buf[0..w.end]); // Nothing written
}

test "formatHexBytesLower produces lowercase hex" {
    const data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var buf: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try formatHexBytesLower(&w, &data);
    try std.testing.expectEqualStrings("deadbeef", buf[0..w.end]);
}

test "formatFloat32Xml handles special values" {
    var buf: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);

    // NaN
    try formatFloat32Xml(&w, std.math.nan(f32));
    try std.testing.expectEqualStrings("-1.#IND", buf[0..w.end]);

    // +Inf
    w = std.Io.Writer.fixed(&buf);
    try formatFloat32Xml(&w, std.math.inf(f32));
    try std.testing.expectEqualStrings("1.#INF", buf[0..w.end]);

    // -Inf
    w = std.Io.Writer.fixed(&buf);
    try formatFloat32Xml(&w, -std.math.inf(f32));
    try std.testing.expectEqualStrings("-1.#INF", buf[0..w.end]);
}

test "formatValueXmlFromRaw strips array flag" {
    const data = [_]u8{ 0x2A, 0x00, 0x00, 0x00 }; // 42
    var buf: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    // 0x88 = 0x80 | 0x08 = array flag | uint32
    try formatValueXmlFromRaw(&w, 0x88, &data);
    try std.testing.expectEqualStrings("42", buf[0..w.end]);
}
