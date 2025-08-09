// Reader drives Binary XML token parsing for one buffer slice (record or template definition).
const BinXmlError = @import("err.zig").BinXmlError;

const std = @import("std");

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf, .pos = 0 };
    }

    pub fn rem(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }

    pub fn peekU8(self: *const Reader) !u8 {
        if (self.pos >= self.buf.len) return BinXmlError.UnexpectedEof;
        return self.buf[self.pos];
    }

    pub fn readU8(self: *Reader) !u8 {
        if (self.pos >= self.buf.len) return BinXmlError.UnexpectedEof;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }

    pub fn readU16le(self: *Reader) !u16 {
        if (self.pos + 2 > self.buf.len) return BinXmlError.UnexpectedEof;
        const v = std.mem.readInt(u16, self.buf[self.pos .. self.pos + 2][0..2], .little);
        self.pos += 2;
        return v;
    }

    pub fn readU32le(self: *Reader) !u32 {
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

    pub fn readFixedBytes(self: *Reader, n: usize) ![]const u8 {
        if (self.rem() < n) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return slice;
    }

    pub fn readFixedBytesBounded(self: *Reader, n: usize, end_pos: usize) ![]const u8 {
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
};
