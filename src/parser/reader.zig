//! Reader drives Binary XML token parsing for one buffer slice (record or template definition).
//!
//! This is a zero-allocation slice reader that provides typed access to binary data.
//! All reads are bounds-checked and return errors on EOF.

const std = @import("std");

const BinXmlError = @import("err.zig").BinXmlError;
const tokens = @import("binxml/tokens.zig");
const types = @import("binxml/types.zig");
const value_reader = @import("binxml/value_reader.zig");
const IR = @import("ir.zig").IR;

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
    /// Delegates to value_reader.readValue for the actual byte interpretation.
    pub fn readInt(self: *Reader, comptime T: type) !T {
        const size = @sizeOf(T);
        if (self.pos + size > self.buf.len) return BinXmlError.UnexpectedEof;
        const val = value_reader.readValue(T, self.buf[self.pos..]) orelse return BinXmlError.UnexpectedEof;
        self.pos += size;
        return val;
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
    /// Delegates to value_reader.readValue for primitives, handles compound types locally.
    fn readAny(self: *Reader, comptime T: type) !T {
        const type_info = @typeInfo(T);
        const size = @sizeOf(T);

        return switch (type_info) {
            // Primitives: delegate to value_reader.readValue (single source of truth)
            .int, .float, .bool => {
                if (self.pos + size > self.buf.len) return BinXmlError.UnexpectedEof;
                const val = value_reader.readValue(T, self.buf[self.pos..]) orelse return BinXmlError.UnexpectedEof;
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
                    const val = value_reader.readValue(T, self.buf[self.pos..]) orelse return BinXmlError.UnexpectedEof;
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

    /// Reads a 16-byte GUID from the current position.
    pub fn readGuid(self: *Reader) ![16]u8 {
        const g = try self.readStruct(types.GuidBytes);
        return g.bytes;
    }

    /// Reads exactly `n` bytes from the current position.
    /// Returns a slice into the underlying buffer (zero-copy).
    pub inline fn readFixedBytes(self: *Reader, n: usize) ![]const u8 {
        if (self.rem() < n) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return slice;
    }

    /// Reads exactly `n` bytes, but fails if reading would exceed `end_pos`.
    /// Used when parsing bounded regions within a larger buffer.
    pub inline fn readFixedBytesBounded(self: *Reader, n: usize, end_pos: usize) ![]const u8 {
        if (self.pos + n > end_pos) return BinXmlError.UnexpectedEof;
        return self.readFixedBytes(n);
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

        const needed = value_reader.sidSize(self.buf[start..]) orelse {
            return BinXmlError.UnexpectedEof;
        };

        if (start + needed > end_pos) return BinXmlError.UnexpectedEof;
        if (start + needed > self.buf.len) return BinXmlError.UnexpectedEof;

        const slice = self.buf[start .. start + needed];
        self.pos = start + needed;
        return slice;
    }

    /// Reads an inline NameLink definition used in template definitions.
    ///
    /// Format: 4 bytes next_offset, 2 bytes hash, 2 bytes num_chars, UTF-16 name.
    /// After reading, advances to end-of-block alignment (name data + 4 byte padding).
    /// Returns an IR.Name pointing into the buffer (caller must copy if persistence needed).
    pub fn readTemplateNameLinkInlineView(self: *Reader) !IR.Name {
        const block_start = self.pos;
        const header = try self.readStruct(types.NameHeader);
        const num_chars = header.num_chars;
        const byte_len = @as(usize, num_chars) * 2;

        if (self.rem() < byte_len) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + byte_len];
        self.pos += byte_len;

        // Align to end of name block: header(6) + string + padding(4)
        const block_end = block_start + 6 + byte_len + 4;
        if (self.pos < block_end and block_end <= self.buf.len) {
            self.pos = block_end;
        }
        return .{ .bytes = slice, .num_chars = num_chars };
    }
};
