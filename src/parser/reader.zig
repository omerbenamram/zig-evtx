// Reader drives Binary XML token parsing for one buffer slice (record or template definition).
const BinXmlError = @import("err.zig").BinXmlError;
const tokens = @import("binxml/tokens.zig");

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

    pub inline fn peekU8(self: *const Reader) !u8 {
        if (self.pos >= self.buf.len) return BinXmlError.UnexpectedEof;
        return self.buf[self.pos];
    }

    pub inline fn readU8(self: *Reader) !u8 {
        if (self.pos >= self.buf.len) return BinXmlError.UnexpectedEof;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }

    pub inline fn readU16le(self: *Reader) !u16 {
        if (self.pos + 2 > self.buf.len) return BinXmlError.UnexpectedEof;
        const v = std.mem.readInt(u16, self.buf[self.pos .. self.pos + 2][0..2], .little);
        self.pos += 2;
        return v;
    }

    pub inline fn readU32le(self: *Reader) !u32 {
        if (self.pos + 4 > self.buf.len) return BinXmlError.UnexpectedEof;
        const v = std.mem.readInt(u32, self.buf[self.pos .. self.pos + 4][0..4], .little);
        self.pos += 4;
        return v;
    }

    pub fn readGuid(self: *Reader) ![16]u8 {
        if (self.pos + 16 > self.buf.len) return BinXmlError.UnexpectedEof;
        var g: [16]u8 = undefined;
        @memcpy(&g, self.buf[self.pos .. self.pos + 16]);
        self.pos += 16;
        return g;
    }

    pub fn readLenPrefixedBytes16(self: *Reader) ![]const u8 {
        if (self.rem() < 2) return BinXmlError.UnexpectedEof;
        const blen = try self.readU16le();
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
        _ = try self.readU32le(); // unknown
        _ = try self.readU16le(); // hash
        const num = try self.readU16le();
        const bytes = @as(usize, num) * 2;
        if (self.pos + bytes > self.buf.len) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + bytes];
        self.pos += bytes;
        return .{ .utf16 = slice, .num_chars = num };
    }

    pub fn readUnicodeTextString(self: *Reader) ![]const u8 {
        // Unicode text string: 2 bytes num chars, then UTF-16LE string without EOS
        const num_chars = try self.readU16le();
        const byte_len = @as(usize, num_chars) * 2;
        if (self.pos + byte_len > self.buf.len) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + byte_len];
        self.pos += byte_len;
        return slice;
    }

    pub fn readUnicodeTextStringBounded(self: *Reader, end_pos: usize) ![]const u8 {
        if (self.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
        const num_chars = try self.readU16le();
        const byte_len = @as(usize, num_chars) * 2;
        if (self.pos + byte_len > end_pos) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + byte_len];
        self.pos += byte_len;
        return slice;
    }

    pub fn readLenPrefixedBytes16Bounded(self: *Reader, end_pos: usize) ![]const u8 {
        if (self.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
        const blen = try self.readU16le();
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
            _ = try self.readU16le();
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
        const num = try self.readU16le();
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
        _ = try self.readU32le(); // next string
        _ = try self.readU16le(); // name hash
        const num = try self.readU16le();
        const bytes = @as(usize, num) * 2;
        if (self.rem() < bytes) return BinXmlError.UnexpectedEof;
        const slice_src = self.buf[self.pos .. self.pos + bytes];
        self.pos += bytes;
        const want_end = inl_start + 6 + bytes + 4;
        if (self.pos < want_end and want_end <= self.buf.len) self.pos = want_end;
        return .{ .utf16 = slice_src, .num_chars = num };
    }

    pub const TemplateInstanceHeader = struct { def_data_off: u32 };

    pub fn readTemplateInstanceHeader(self: *Reader) !TemplateInstanceHeader {
        // Caller should have peeked TOK_TEMPLATE_INSTANCE; be tolerant and just consume
        const tag = try self.readU8();
        if ((tag & 0x1f) != tokens.TOK_TEMPLATE_INSTANCE) return BinXmlError.BadToken;
        if (self.rem() < 1 + 4 + 4) return BinXmlError.UnexpectedEof;
        _ = try self.readU8(); // unknown
        _ = try self.readU32le(); // template id
        const def_data_off = try self.readU32le();
        if (def_data_off == @as(u32, @intCast(self.pos))) {
            if (self.rem() < 24) return BinXmlError.UnexpectedEof;
            _ = try self.readU32le();
            _ = try self.readGuid();
            const data_size_inline = try self.readU32le();
            if (self.rem() < data_size_inline) return BinXmlError.UnexpectedEof;
            self.pos += @as(usize, data_size_inline);
        }
        return .{ .def_data_off = def_data_off };
    }
};
