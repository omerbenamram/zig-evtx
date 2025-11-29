//! Unified binary reader for EVTX BinXML data.
//!
//! This module provides:
//! - Reader struct for streaming binary parsing with bounds checking
//! - Value types (Guid, Sid, FileTime, SystemTime) for Windows data structures
//! - Comptime type dispatch for reading primitives and packed structs

const std = @import("std");

const BinXmlError = @import("err.zig").BinXmlError;
const types = @import("binxml/types.zig");

// ============================================================================
// Value Types - Windows data structures
// ============================================================================

/// Windows GUID structure (128 bits)
pub const Guid = struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

/// Windows Security Identifier (SID)
pub const Sid = struct {
    revision: u8,
    id_authority: u64,
    sub_authorities: []const u8, // Raw bytes; each sub-auth is 4 bytes LE
    sub_authority_count: u8,

    /// Get sub-authority at index (0-based)
    pub fn getSubAuthority(self: Sid, index: usize) ?u32 {
        const offset = index * 4;
        if (offset + 4 > self.sub_authorities.len) return null;
        return std.mem.readInt(u32, self.sub_authorities[offset..][0..4], .little);
    }
};

/// Windows FILETIME (100-nanosecond intervals since 1601-01-01)
pub const FileTime = struct {
    raw: u64,
};

/// Windows SYSTEMTIME structure - packed for direct memory mapping
pub const SystemTime = packed struct {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
};

// ============================================================================
// Standalone Value Reading Functions
// ============================================================================

/// Read any fixed-size value from bytes using comptime type dispatch.
/// Supports: integers, floats, packed structs, bool.
/// Uses @typeInfo to select the appropriate reading strategy at compile time.
pub fn readValue(comptime T: type, data: []const u8) ?T {
    const size = @sizeOf(T);
    if (data.len < size) return null;

    const info = @typeInfo(T);
    return switch (info) {
        .int => std.mem.readInt(T, data[0..size], .little),
        .float => blk: {
            if (T == f32) {
                const bits = std.mem.readInt(u32, data[0..4], .little);
                break :blk @bitCast(bits);
            } else if (T == f64) {
                const bits = std.mem.readInt(u64, data[0..8], .little);
                break :blk @bitCast(bits);
            } else {
                @compileError("Unsupported float type: " ++ @typeName(T));
            }
        },
        .@"struct" => |s| blk: {
            if (s.layout == .@"packed") {
                break :blk std.mem.bytesToValue(T, data[0..size]);
            } else {
                @compileError("Only packed structs supported in readValue: " ++ @typeName(T));
            }
        },
        .bool => blk: {
            const v = std.mem.readInt(u32, data[0..4], .little);
            break :blk v != 0;
        },
        else => @compileError("Unsupported type in readValue: " ++ @typeName(T)),
    };
}

/// Read a GUID from 16 bytes of data
pub fn readGuid(data: []const u8) ?Guid {
    if (data.len < 16) return null;
    return Guid{
        .data1 = std.mem.readInt(u32, data[0..4], .little),
        .data2 = std.mem.readInt(u16, data[4..6], .little),
        .data3 = std.mem.readInt(u16, data[6..8], .little),
        .data4 = data[8..16].*,
    };
}

/// Read a SID from variable-length data.
/// SID layout: revision (1), sub_count (1), id_authority (6 BE), sub_authorities (sub_count * 4 LE)
pub fn readSid(data: []const u8) ?Sid {
    if (data.len < 8) return null;
    const revision = data[0];
    const sub_count = data[1];
    const ida_bytes = data[2..8];

    // ID Authority is 6 bytes big-endian
    var id_authority: u64 = 0;
    for (ida_bytes) |b| {
        id_authority = (id_authority << 8) | b;
    }

    const sub_auth_len = @as(usize, sub_count) * 4;
    if (data.len < 8 + sub_auth_len) return null;

    return Sid{
        .revision = revision,
        .id_authority = id_authority,
        .sub_authorities = data[8 .. 8 + sub_auth_len],
        .sub_authority_count = sub_count,
    };
}

/// Calculate the byte size of a SID given the data buffer
pub fn sidSize(data: []const u8) ?usize {
    if (data.len < 2) return null;
    const sub_count: usize = data[1];
    return 8 + sub_count * 4;
}

/// Read a FILETIME from 8 bytes.
pub fn readFileTime(data: []const u8) ?FileTime {
    const raw = readValue(u64, data) orelse return null;
    return FileTime{ .raw = raw };
}

/// Read a SYSTEMTIME from 16 bytes using comptime type dispatch
pub fn readSystemTime(data: []const u8) ?SystemTime {
    if (data.len < 16) return null;
    return std.mem.bytesToValue(SystemTime, data[0..16]);
}

// ============================================================================
// Reader Struct - Streaming binary parser
// ============================================================================

/// Zero-copy binary reader for parsing EVTX BinXML data.
///
/// Provides typed access to little-endian binary data with bounds checking.
/// All read operations advance the internal position and return errors on EOF.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    /// Creates a new Reader over the given buffer slice.
    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf, .pos = 0 };
    }

    /// Returns the number of bytes remaining in the buffer.
    pub inline fn rem(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }

    /// Reads a little-endian integer of type T from the current position.
    /// Delegates to readAny for single source of truth.
    pub fn readInt(self: *Reader, comptime T: type) !T {
        return self.readAny(T);
    }

    /// Reads a little-endian integer with bounds check against end_pos.
    /// Use this when parsing bounded regions within a larger buffer.
    pub fn readIntBounded(self: *Reader, comptime T: type, end_pos: usize) !T {
        if (self.pos + @sizeOf(T) > end_pos) return BinXmlError.UnexpectedEof;
        return self.readAny(T);
    }

    /// Reads a struct with bounds check against end_pos.
    /// Uses binarySize for correct size (handles alignment padding).
    pub fn readStructBounded(self: *Reader, comptime T: type, end_pos: usize) !T {
        if (self.pos + types.binarySize(T) > end_pos) return BinXmlError.UnexpectedEof;
        return self.readStruct(T);
    }

    /// Peeks at the next byte without advancing position.
    pub fn peekByte(self: *const Reader) !u8 {
        if (self.pos >= self.buf.len) return BinXmlError.UnexpectedEof;
        return self.buf[self.pos];
    }

    /// Reads a struct by reflecting over its fields and reading each in order.
    /// Uses comptime to specialize for each struct type.
    pub fn readStruct(self: *Reader, comptime T: type) !T {
        var result: T = undefined;
        inline for (std.meta.fields(T)) |field| {
            @field(result, field.name) = try self.readAny(field.type);
        }
        return result;
    }

    /// Comptime type dispatch for reading values.
    fn readAny(self: *Reader, comptime T: type) !T {
        const type_info = @typeInfo(T);
        const size = @sizeOf(T);

        return switch (type_info) {
            // Primitives: delegate to readValue (single source of truth)
            .int, .float, .bool => {
                if (self.pos + size > self.buf.len) return BinXmlError.UnexpectedEof;
                const val = readValue(T, self.buf[self.pos..]) orelse return BinXmlError.UnexpectedEof;
                self.pos += size;
                return val;
            },
            // Enums: read underlying int, then convert
            .@"enum" => |e| {
                const TagType = e.tag_type;
                const val = try self.readAny(TagType);
                return std.meta.intToEnum(T, val) catch return BinXmlError.BadToken;
            },
            // Structs: packed use bytesToValue, others read field-by-field
            .@"struct" => |s| {
                if (s.layout == .@"packed") {
                    if (self.pos + size > self.buf.len) return BinXmlError.UnexpectedEof;
                    const val = readValue(T, self.buf[self.pos..]) orelse return BinXmlError.UnexpectedEof;
                    self.pos += size;
                    return val;
                }
                return self.readStruct(T);
            },
            // Arrays: read element-by-element
            .array => |arr_info| {
                var arr: T = undefined;
                for (&arr) |*elem| {
                    elem.* = try self.readAny(arr_info.child);
                }
                return arr;
            },
            else => @compileError("Unsupported type in readAny: " ++ @typeName(T)),
        };
    }

    /// Reads exactly `n` bytes, but fails if reading would exceed `end_pos`.
    /// Used when parsing bounded regions within a larger buffer.
    /// Returns a slice into the underlying buffer (zero-copy).
    pub inline fn readFixedBytesBounded(self: *Reader, n: usize, end_pos: usize) ![]const u8 {
        if (self.pos + n > end_pos) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return slice;
    }

    /// Reads a slice of `len` bytes with bounds check against `end_pos`.
    /// Alias for readFixedBytesBounded with runtime length.
    pub inline fn readSliceBounded(self: *Reader, len: usize, end_pos: usize) ![]const u8 {
        return self.readFixedBytesBounded(len, end_pos);
    }

    /// Reads a length-prefixed slice.
    ///
    /// - `PrefixT`: Integer type for the length prefix (e.g. u16)
    /// - `unit_size`: Size of each element in bytes (e.g. 2 for UTF-16)
    /// - `end_pos`: Optional absolute position limit
    pub fn readLenPrefixedSlice(self: *Reader, comptime PrefixT: type, comptime unit_size: usize, end_pos: ?usize) ![]const u8 {
        const prefix_size = @sizeOf(PrefixT);
        if (end_pos) |end| {
            if (self.pos + prefix_size > end) return BinXmlError.UnexpectedEof;
        }

        // Read length prefix using generic readInt
        const len = try self.readInt(PrefixT);
        const byte_len = @as(usize, len) * unit_size;

        if (end_pos) |end| {
            if (self.pos + byte_len > end) return BinXmlError.UnexpectedEof;
        } else {
            if (self.pos + byte_len > self.buf.len) return BinXmlError.UnexpectedEof;
        }

        const slice = self.buf[self.pos .. self.pos + byte_len];
        self.pos += byte_len;
        return slice;
    }

    /// Reads a Windows SID (Security Identifier) within the given bounds.
    ///
    /// SID size is variable and determined by the SubAuthorityCount field.
    /// Returns the raw SID bytes as a slice.
    pub fn readSidBytesBounded(self: *Reader, end_pos: usize) ![]const u8 {
        if (self.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
        const start = self.pos;

        const needed = sidSize(self.buf[start..]) orelse {
            return BinXmlError.UnexpectedEof;
        };

        if (start + needed > end_pos) return BinXmlError.UnexpectedEof;
        if (start + needed > self.buf.len) return BinXmlError.UnexpectedEof;

        const slice = self.buf[start .. start + needed];
        self.pos = start + needed;
        return slice;
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "readGuid parses correctly" {
    // GUID: {12345678-1234-5678-1234-567812345678}
    const data = [_]u8{
        0x78, 0x56, 0x34, 0x12, // data1 LE
        0x34, 0x12, // data2 LE
        0x78, 0x56, // data3 LE
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, // data4
    };
    const guid = readGuid(&data).?;
    try std.testing.expectEqual(@as(u32, 0x12345678), guid.data1);
    try std.testing.expectEqual(@as(u16, 0x1234), guid.data2);
    try std.testing.expectEqual(@as(u16, 0x5678), guid.data3);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78 }, &guid.data4);
}

test "readGuid returns null for insufficient data" {
    const data = [_]u8{ 0x01, 0x02, 0x03 };
    try std.testing.expect(readGuid(&data) == null);
}

test "readSid parses SYSTEM SID" {
    // S-1-5-18 (SYSTEM)
    const data = [_]u8{
        0x01, // revision
        0x01, // sub-authority count
        0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // id authority (5) BE
        0x12, 0x00, 0x00, 0x00, // sub-authority 18 LE
    };
    const sid = readSid(&data).?;
    try std.testing.expectEqual(@as(u8, 1), sid.revision);
    try std.testing.expectEqual(@as(u64, 5), sid.id_authority);
    try std.testing.expectEqual(@as(u8, 1), sid.sub_authority_count);
    try std.testing.expectEqual(@as(u32, 18), sid.getSubAuthority(0).?);
}

test "readSid returns null for truncated data" {
    const data = [_]u8{ 0x01, 0x02 }; // Says 2 sub-auths but no data
    try std.testing.expect(readSid(&data) == null);
}

test "readFileTime parses correctly" {
    // Some known FILETIME value
    const data = [_]u8{ 0x00, 0x80, 0x3E, 0xD5, 0xDE, 0xB1, 0x9D, 0x01 };
    const ft = readFileTime(&data).?;
    try std.testing.expectEqual(@as(u64, 0x019DB1DED53E8000), ft.raw);
}

test "readSystemTime parses correctly" {
    // 2024-01-15 10:30:45.123
    const data = [_]u8{
        0xE8, 0x07, // year 2024
        0x01, 0x00, // month 1
        0x01, 0x00, // day of week (Monday)
        0x0F, 0x00, // day 15
        0x0A, 0x00, // hour 10
        0x1E, 0x00, // minute 30
        0x2D, 0x00, // second 45
        0x7B, 0x00, // milliseconds 123
    };
    const st = readSystemTime(&data).?;
    try std.testing.expectEqual(@as(u16, 2024), st.year);
    try std.testing.expectEqual(@as(u16, 1), st.month);
    try std.testing.expectEqual(@as(u16, 15), st.day);
    try std.testing.expectEqual(@as(u16, 10), st.hour);
    try std.testing.expectEqual(@as(u16, 30), st.minute);
    try std.testing.expectEqual(@as(u16, 45), st.second);
    try std.testing.expectEqual(@as(u16, 123), st.milliseconds);
}

test "readValue handles various integer sizes" {
    const data32 = [_]u8{ 0x78, 0x56, 0x34, 0x12 };
    try std.testing.expectEqual(@as(i32, 0x12345678), readValue(i32, &data32).?);
    try std.testing.expectEqual(@as(u32, 0x12345678), readValue(u32, &data32).?);

    const data64 = [_]u8{ 0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12 };
    try std.testing.expectEqual(@as(u64, 0x1234567890ABCDEF), readValue(u64, &data64).?);
}

test "readValue bool interprets zero as false" {
    const false_data = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    const true_data = [_]u8{ 0x01, 0x00, 0x00, 0x00 };
    const nonzero_data = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };

    try std.testing.expectEqual(false, readValue(bool, &false_data).?);
    try std.testing.expectEqual(true, readValue(bool, &true_data).?);
    try std.testing.expectEqual(true, readValue(bool, &nonzero_data).?);
}

test "readValue with comptime type dispatch" {
    // Test integers
    const data32 = [_]u8{ 0x78, 0x56, 0x34, 0x12 };
    try std.testing.expectEqual(@as(u32, 0x12345678), readValue(u32, &data32).?);
    try std.testing.expectEqual(@as(i32, 0x12345678), readValue(i32, &data32).?);

    // Test floats
    const float_data = [_]u8{ 0x00, 0x00, 0x80, 0x3F }; // 1.0f
    try std.testing.expectEqual(@as(f32, 1.0), readValue(f32, &float_data).?);

    // Test packed struct (SystemTime)
    const st_data = [_]u8{
        0xE8, 0x07, // year 2024
        0x01, 0x00, // month 1
        0x01, 0x00, // day of week
        0x0F, 0x00, // day 15
        0x0A, 0x00, // hour 10
        0x1E, 0x00, // minute 30
        0x2D, 0x00, // second 45
        0x7B, 0x00, // milliseconds 123
    };
    const st = readValue(SystemTime, &st_data).?;
    try std.testing.expectEqual(@as(u16, 2024), st.year);
    try std.testing.expectEqual(@as(u16, 123), st.milliseconds);

    // Test bool via readValue
    const bool_data = [_]u8{ 0x01, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(true, readValue(bool, &bool_data).?);
}
