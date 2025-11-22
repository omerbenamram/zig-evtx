// Reader drives Binary XML token parsing for one buffer slice (record or template definition).
const BinXmlError = @import("err.zig").BinXmlError;
const tokens = @import("binxml/tokens.zig");
const types = @import("binxml/types.zig");

const std = @import("std");

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf, .pos = 0 };
    }

    pub inline fn rem(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }

    pub fn readInt(self: *Reader, comptime T: type) !T {
        const size = @sizeOf(T);
        if (self.pos + size > self.buf.len) return BinXmlError.UnexpectedEof;
        const val = std.mem.readInt(T, self.buf[self.pos..][0..size], .little);
        self.pos += size;
        return val;
    }

    pub fn readByte(self: *Reader) !u8 {
        return self.readInt(u8);
    }

    pub fn peekByte(self: *const Reader) !u8 {
        if (self.pos >= self.buf.len) return BinXmlError.UnexpectedEof;
        return self.buf[self.pos];
    }

    // Generic struct reader using reflection
    pub fn readStruct(self: *Reader, comptime T: type) !T {
        var result: T = undefined;
        inline for (std.meta.fields(T)) |field| {
            @field(result, field.name) = try self.readAny(field.type);
        }
        return result;
    }

    fn readAny(self: *Reader, comptime T: type) !T {
        const type_info = @typeInfo(T);
        switch (type_info) {
            .int => return self.readInt(T),
            .@"enum" => {
                const TagType = type_info.@"enum".tag_type;
                const val = try self.readInt(TagType);
                return std.meta.intToEnum(T, val) catch return BinXmlError.BadToken;
            },
            .@"struct" => return self.readStruct(T),
            .array => |arr_info| {
                var arr: T = undefined;
                for (&arr) |*elem| {
                    elem.* = try self.readAny(arr_info.child);
                }
                return arr;
            },
            else => @compileError("Unsupported type in readAny: " ++ @typeName(T)),
        }
    }

    pub inline fn peekU8(self: *const Reader) !u8 {
        return self.peekByte();
    }

    pub inline fn readU8(self: *Reader) !u8 {
        return self.readByte();
    }

    pub inline fn readU16le(self: *Reader) !u16 {
        return self.readInt(u16);
    }

    pub inline fn readU32le(self: *Reader) !u32 {
        return self.readInt(u32);
    }

    pub fn readGuid(self: *Reader) ![16]u8 {
        const g = try self.readStruct(types.GuidBytes);
        return g.bytes;
    }

    pub fn readLenPrefixedBytes16(self: *Reader) ![]const u8 {
        if (self.rem() < 2) return BinXmlError.UnexpectedEof;
        const h = try self.readStruct(types.NameLengthHeader);
        const blen = h.len;
        if (self.rem() < blen) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + blen];
        self.pos += blen;
        return slice;
    }

    pub fn readSidBytes(self: *Reader) ![]const u8 {
        // Return the exact SID byte sequence: 1 byte rev, 1 byte subcount, 6 bytes authority, subcount*4 bytes subauths
        if (self.rem() < 2) return BinXmlError.UnexpectedEof;
        const start = self.pos;
        // Peek subcount without advancing beyond required bounds unnecessarily
        const subc = self.buf[self.pos + 1];
        const needed: usize = 8 + @as(usize, subc) * 4;
        if (self.rem() < needed) return BinXmlError.UnexpectedEof;
        const slice = self.buf[start .. start + needed];
        self.pos = start + needed;
        return slice;
    }

    pub inline fn readFixedBytes(self: *Reader, n: usize) ![]const u8 {
        if (self.rem() < n) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return slice;
    }

    pub inline fn readFixedBytesBounded(self: *Reader, n: usize, end_pos: usize) ![]const u8 {
        if (self.pos + n > end_pos) return BinXmlError.UnexpectedEof;
        return try self.readFixedBytes(n);
    }

    pub fn readInlineName(self: *Reader) !struct { utf16: []const u8, num_chars: usize } {
        const header = try self.readStruct(types.NameHeader);
        const num = header.num_chars;
        const bytes = @as(usize, num) * 2;
        if (self.pos + bytes > self.buf.len) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + bytes];
        self.pos += bytes;
        return .{ .utf16 = slice, .num_chars = num };
    }

    pub fn readUnicodeTextString(self: *Reader) ![]const u8 {
        // Unicode text string: 2 bytes num chars, then UTF-16LE string without EOS
        const header = try self.readStruct(types.NameLengthHeader);
        const num_chars = header.len;
        const byte_len = @as(usize, num_chars) * 2;
        if (self.pos + byte_len > self.buf.len) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + byte_len];
        self.pos += byte_len;
        return slice;
    }

    pub fn readUnicodeTextStringBounded(self: *Reader, end_pos: usize) ![]const u8 {
        if (self.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
        const header = try self.readStruct(types.NameLengthHeader);
        const num_chars = header.len;
        const byte_len = @as(usize, num_chars) * 2;
        if (self.pos + byte_len > end_pos) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + byte_len];
        self.pos += byte_len;
        return slice;
    }

    pub fn readLenPrefixedBytes16Bounded(self: *Reader, end_pos: usize) ![]const u8 {
        if (self.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
        const header = try self.readStruct(types.NameLengthHeader);
        const blen = header.len;
        if (self.pos + @as(usize, blen) > end_pos) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + blen];
        self.pos += blen;
        return slice;
    }

    pub fn readSidBytesBounded(self: *Reader, end_pos: usize) ![]const u8 {
        if (self.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
        const start = self.pos;
        const subc = self.buf[self.pos + 1];
        const needed: usize = 8 + @as(usize, subc) * 4;
        if (start + needed > end_pos) return BinXmlError.UnexpectedEof;
        const slice = self.buf[start .. start + needed];
        self.pos = start + needed;
        return slice;
    }

    // Name definitions (per EVTX BinXML spec: Name)
    // Inline Name used in value contexts (no leading unknown/hash fields)
    // According to the spec "Name" section, there are two on-wire encodings that can appear
    // depending on context:
    // - Template NameLink form (handled by readTemplateNameLinkInlineView): 4 bytes next pointer,
    //   2 bytes hash, 2 bytes num chars, UTF-16 name, then advance to the end of the inline name block.
    // - Value-context inline name form (this function): num-chars (u16) followed by UTF-16 string.
    //   Some real-world payloads prepend an extra u16 before num-chars. We handle both by first
    //   attempting the prefixed variant, then falling back to the plain form.
    // In both cases we also tolerate and trim a trailing UTF-16 NUL (EOS) after the string.
    pub fn readValueNameInlineView(self: *Reader) !struct { utf16: []const u8, num_chars: usize } {
        return self.readNumCharsUtf16OptionalPrefixView();
    }

    // Generic helper: read a UTF-16 name given a num-chars (u16) field, allowing an optional
    // leading u16 prefix before the num-chars. Trims a trailing UTF-16 NUL if present.
    // This centralizes the two-branch logic used by value-context names (see above).
    pub fn readNumCharsUtf16OptionalPrefixView(self: *Reader) !struct { utf16: []const u8, num_chars: usize } {
        if (self.rem() >= 4) {
            const saveA = self.pos;
            _ = try self.readStruct(types.NameLengthHeader);
            // Attempt prefixed form: treat next u16 as num-chars and read the UTF-16 string
            if (self.readLenPrefixedUtf16TrimEos()) |v| return v else |_| self.pos = saveA;
        }
        // Fallback: plain num-chars + UTF-16
        return try self.readLenPrefixedUtf16TrimEos();
    }

    // Read a length-prefixed UTF-16LE string: first u16 = number of UTF-16 code units,
    // then that many bytes. If an immediate trailing UTF-16 NUL follows, consume it.
    // Returns a view into the buffer and the number of characters.
    pub fn readLenPrefixedUtf16TrimEos(self: *Reader) !struct { utf16: []const u8, num_chars: usize } {
        const header = try self.readStruct(types.NameLengthHeader);
        const num = header.len;
        const bytes = @as(usize, num) * 2;
        if (self.rem() < bytes) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + bytes];
        self.pos += bytes;
        if (self.rem() >= 2) {
            const eos = std.mem.readInt(u16, self.buf[self.pos .. self.pos + 2][0..2], .little);
            if (eos == 0) self.pos += 2;
        }
        return .{ .utf16 = slice, .num_chars = num };
    }

    // Inline NameLink definition used in template definitions; includes next/hash and aligns to end-of-block
    pub fn readTemplateNameLinkInlineView(self: *Reader) !struct { utf16: []const u8, num_chars: usize } {
        const inl_start = self.pos;
        const header = try self.readStruct(types.NameHeader);
        const num = header.num_chars;
        const bytes = @as(usize, num) * 2;
        if (self.rem() < bytes) return BinXmlError.UnexpectedEof;
        const slice_src = self.buf[self.pos .. self.pos + bytes];
        self.pos += bytes;
        const want_end = inl_start + 6 + bytes + 4;
        if (self.pos < want_end and want_end <= self.buf.len) self.pos = want_end;
        return .{ .utf16 = slice_src, .num_chars = num };
    }

    pub const TemplateInstanceHeader = struct {
        def_data_off: u32,
    };

    pub fn readTemplateInstanceHeader(self: *Reader) !TemplateInstanceHeader {
        // Caller should have peeked TOK_TEMPLATE_INSTANCE; be tolerant and just consume
        const tag = try self.readU8();
        if ((tag & 0x1f) != tokens.TOK_TEMPLATE_INSTANCE) return BinXmlError.BadToken;
        // Template instance layout:
        //   1 byte  : unknown/version
        //   4 bytes : template identifier (ignored here)
        //   4 bytes : template definition data offset (chunk-relative)
        // Followed optionally by an inline template definition if def_data_off == current pos.
        if (self.rem() < 1 + 4 + 4) return BinXmlError.UnexpectedEof;
        _ = try self.readU8(); // unknown/version
        _ = try self.readU32le(); // template id
        const def_data_off = try self.readU32le();

        // Inline template definition: definition data is embedded immediately after the header.
        // def_data_off then points to the current reader position.
        if (def_data_off == @as(u32, @intCast(self.pos))) {
            // TemplateDefinition data header:
            //   4 bytes : next_offset
            //   16 bytes: GUID
            //   4 bytes : data_size
            if (self.rem() < 24) return BinXmlError.UnexpectedEof;
            _ = try self.readU32le(); // next_offset
            _ = try self.readGuid(); // GUID (16 bytes)
            const data_size_inline = try self.readU32le();
            if (self.rem() < data_size_inline) return BinXmlError.UnexpectedEof;
            self.pos += @as(usize, data_size_inline);
        }
        return .{ .def_data_off = def_data_off };
    }
};
