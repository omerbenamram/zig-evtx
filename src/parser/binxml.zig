const std = @import("std");
const util = @import("util.zig");
const writeXmlEscaped = util.writeXmlEscaped;
const writeUtf16LeXmlEscaped = util.writeUtf16LeXmlEscaped;
const utf16EqualsAscii = util.utf16EqualsAscii;
const normalizeAndWriteSystemTimeAscii = util.normalizeAndWriteSystemTimeAscii;
const writePaddedInt = util.writePaddedInt;
const writeUnicodeStringArrayCommaSeparated = util.writeUnicodeStringArrayCommaSeparated;
const formatIso8601UtcFromUnixMs = util.formatIso8601UtcFromUnixMs;
const formatIso8601UtcFromFiletimeMicros = util.formatIso8601UtcFromFiletimeMicros;

pub const RenderMode = enum { xml, json, jsonl };

pub const BinXmlError = error{
    UnexpectedEof,
    BadToken,
    OutOfBounds,
};

// Token constants (subset)
const TOK_FRAGMENT_HEADER: u8 = 0x0f;
const TOK_OPEN_START: u8 = 0x01; // or 0x41 with has-more flag
const TOK_CLOSE_START: u8 = 0x02;
const TOK_CLOSE_EMPTY: u8 = 0x03;
const TOK_END_ELEMENT: u8 = 0x04;
const TOK_VALUE: u8 = 0x05; // or 0x45 with has-more flag
const TOK_ATTRIBUTE: u8 = 0x06; // or 0x46 with has-more flag
const TOK_TEMPLATE_INSTANCE: u8 = 0x0c;
const TOK_NORMAL_SUBST: u8 = 0x0d;
const TOK_OPTIONAL_SUBST: u8 = 0x0e;
const TOK_EOF: u8 = 0x00;
const TOK_CDATA: u8 = 0x07; // or 0x47 with has-more flag
const TOK_CHARREF: u8 = 0x08; // or 0x48 with has-more flag
const TOK_ENTITYREF: u8 = 0x09; // or 0x49 with has-more flag

fn hasMore(flagged: u8, base: u8) bool {
    return (flagged & 0x1f) == base and (flagged & 0x40) != 0;
}
fn isToken(flagged: u8, base: u8) bool {
    return (flagged & 0x1f) == base;
}

// Reader drives Binary XML token parsing for one buffer slice (record or template definition).
const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn init(buf: []const u8) Reader {
        return .{ .buf = buf, .pos = 0 };
    }

    fn rem(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }

    fn peekU8(self: *const Reader) !u8 {
        if (self.pos >= self.buf.len) return BinXmlError.UnexpectedEof;
        return self.buf[self.pos];
    }

    fn readU8(self: *Reader) !u8 {
        if (self.pos >= self.buf.len) return BinXmlError.UnexpectedEof;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }

    fn readU16le(self: *Reader) !u16 {
        if (self.pos + 2 > self.buf.len) return BinXmlError.UnexpectedEof;
        const v = std.mem.readInt(u16, self.buf[self.pos .. self.pos + 2][0..2], .little);
        self.pos += 2;
        return v;
    }

    fn readU32le(self: *Reader) !u32 {
        if (self.pos + 4 > self.buf.len) return BinXmlError.UnexpectedEof;
        const v = std.mem.readInt(u32, self.buf[self.pos .. self.pos + 4][0..4], .little);
        self.pos += 4;
        return v;
    }

    fn readGuid(self: *Reader) ![16]u8 {
        if (self.pos + 16 > self.buf.len) return BinXmlError.UnexpectedEof;
        var g: [16]u8 = undefined;
        @memcpy(&g, self.buf[self.pos .. self.pos + 16]);
        self.pos += 16;
        return g;
    }

    fn readLenPrefixedBytes16(self: *Reader) ![]const u8 {
        if (self.rem() < 2) return BinXmlError.UnexpectedEof;
        const blen = try self.readU16le();
        if (self.rem() < blen) return BinXmlError.UnexpectedEof;
        const slice = self.buf[self.pos .. self.pos + blen];
        self.pos += blen;
        return slice;
    }

    fn readSidBytes(self: *Reader) ![]const u8 {
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
};

fn writeNameFromOffset(chunk: []const u8, name_offset: u32, w: anytype) !void {
    const off = @as(usize, name_offset);
    if (off + 8 > chunk.len) return BinXmlError.OutOfBounds;
    // Name: u32 unknown, u16 hash, u16 num_chars, then UTF-16LE chars
    const num_chars = std.mem.readInt(u16, chunk[off + 6 .. off + 8][0..2], .little);
    const str_start = off + 8;
    const byte_len = @as(usize, num_chars) * 2;
    if (str_start + byte_len > chunk.len) return BinXmlError.OutOfBounds;
    try writeUtf16LeXmlEscaped(w, chunk[str_start .. str_start + byte_len], num_chars);
}

fn readFixedBytes(r: *Reader, n: usize) ![]const u8 {
    if (r.rem() < n) return BinXmlError.UnexpectedEof;
    const slice = r.buf[r.pos .. r.pos + n];
    r.pos += n;
    return slice;
}

fn valueTypeFixedSize(vtype: u8) ?usize {
    return switch (vtype) {
        0x07, // Int32
        0x08, // UInt32
        0x0d, // Bool (DWORD)
        0x14,
        => 4, // HexInt32
        0x09, // Int64
        0x0a, // UInt64
        0x11,
        => 8, // FILETIME
        0x15 => 8, // HexInt64
        0x0f, // GUID
        0x12,
        => 16, // SYSTEMTIME
        else => null, // 0x01 string (variable), 0x0e binary (variable), 0x13 SID (variable), others unknown
    };
}

fn readUnicodeTextString(r: *Reader) ![]const u8 {
    // Unicode text string: 2 bytes num chars, then UTF-16LE string without EOS
    const num_chars = try r.readU16le();
    const byte_len = @as(usize, num_chars) * 2;
    if (r.pos + byte_len > r.buf.len) return BinXmlError.UnexpectedEof;
    const slice = r.buf[r.pos .. r.pos + byte_len];
    r.pos += byte_len;
    return slice;
}

const Source = enum { rec, def };

fn writeNameFromUtf16(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    try writeUtf16LeXmlEscaped(w, utf16le, num_chars);
}

// moved to util.utf16EqualsAscii

fn isNameSystemTimeFromOffset(chunk: []const u8, name_offset: u32) bool {
    const off = @as(usize, name_offset);
    if (off + 8 > chunk.len) return false;
    const num_chars = std.mem.readInt(u16, chunk[off + 6 .. off + 8][0..2], .little);
    const str_start = off + 8;
    const byte_len = @as(usize, num_chars) * 2;
    if (str_start + byte_len > chunk.len) return false;
    return utf16EqualsAscii(chunk[str_start .. str_start + byte_len], num_chars, "SystemTime");
}

// moved to util.normalizeAndWriteSystemTimeAscii

// Collect attribute value tokens (including substitutions) into a buffer writer.
// Mirrors the logic used for generic attribute values, so special cases are centralized.
fn collectAttributeValue(_: []const u8, _: *Reader, _: anytype, _: []const TemplateValue) !void {}

fn writeSystemTimeAttributeValue(chunk: []const u8, r: *Reader, w: anytype, values: []const TemplateValue) !void {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const aw = fbs.writer();
    try collectAttributeValue(chunk, r, aw, values);
    const written = fbs.getWritten();
    // Drop '+' sentinels
    var tmp: [256]u8 = undefined;
    var idx: usize = 0;
    var j: usize = 0;
    while (idx < written.len and j < tmp.len) : (idx += 1) {
        const ch = written[idx];
        if (ch == '+') continue;
        tmp[j] = ch;
        j += 1;
    }
    try normalizeAndWriteSystemTimeAscii(w, tmp[0..j]);
}

fn readInlineName(r: *Reader) !struct { utf16: []const u8, num_chars: usize } {
    _ = try r.readU32le(); // unknown
    _ = try r.readU16le(); // hash
    const num = try r.readU16le();
    const bytes = @as(usize, num) * 2;
    if (r.pos + bytes > r.buf.len) return BinXmlError.UnexpectedEof;
    const slice = r.buf[r.pos .. r.pos + bytes];
    r.pos += bytes;
    return .{ .utf16 = slice, .num_chars = num };
}

fn readInlineNameDefFlexible(r: *Reader) !struct { utf16: []const u8, num_chars: usize } {
    // Variant C: u32 unknown + u32 zero/unknown + u16 hash + u16 num + UTF16 (+ optional EOS)
    if (r.rem() >= 12) {
        const saveC = r.pos;
        _ = try r.readU32le();
        _ = try r.readU32le();
        _ = try r.readU16le(); // hash
        const numC = try r.readU16le();
        const bytesC = @as(usize, numC) * 2;
        if (r.rem() >= bytesC and r.pos + bytesC <= r.buf.len) {
            const sliceC = r.buf[r.pos .. r.pos + bytesC];
            r.pos += bytesC;
            // Optional EOS (u16 0)
            if (r.rem() >= 2) {
                const eos = std.mem.readInt(u16, r.buf[r.pos .. r.pos + 2][0..2], .little);
                if (eos == 0) r.pos += 2;
            }
            return .{ .utf16 = sliceC, .num_chars = numC };
        }
        r.pos = saveC;
    }
    // Try variant A: u16 hash + u16 num + UTF16
    if (r.rem() >= 4) {
        const save = r.pos;
        _ = try r.readU16le(); // hash
        const numA = try r.readU16le();
        const bytesA = @as(usize, numA) * 2;
        if (r.rem() >= bytesA and r.pos + bytesA <= r.buf.len) {
            const slice = r.buf[r.pos .. r.pos + bytesA];
            r.pos += bytesA;
            return .{ .utf16 = slice, .num_chars = numA };
        }
        r.pos = save;
    }
    // Variant B: u16 num + UTF16
    if (r.rem() >= 2) {
        const numB = try r.readU16le();
        const bytesB = @as(usize, numB) * 2;
        if (r.rem() >= bytesB and r.pos + bytesB <= r.buf.len) {
            const slice = r.buf[r.pos .. r.pos + bytesB];
            r.pos += bytesB;
            return .{ .utf16 = slice, .num_chars = numB };
        }
    }
    // Fallback to full variant with unknown+hash
    _ = try r.readU32le(); // unknown
    _ = try r.readU16le(); // hash
    const num = try r.readU16le();
    const bytes = @as(usize, num) * 2;
    if (r.pos + bytes > r.buf.len) return BinXmlError.UnexpectedEof;
    const slice = r.buf[r.pos .. r.pos + bytes];
    r.pos += bytes;
    return .{ .utf16 = slice, .num_chars = num };
}

fn writeAttributeListXml(chunk: []const u8, r: *Reader, w: anytype, src: Source, values: []const TemplateValue) !void {
    // Attribute list: u32 size (excludes the 4 size bytes), then attributes
    const list_size = try r.readU32le();
    {
        var stderr = std.io.getStdErr().writer();
        _ = try stderr.print("[binxml] attr list_size={d} rem={d}\n", .{ list_size, r.rem() });
    }
    const list_start = r.pos;
    const list_end = list_start + list_size;
    if (list_end > r.buf.len) return BinXmlError.UnexpectedEof;

    while (r.pos < list_end) {
        if (r.rem() == 0) break;
        const tok_peek = r.buf[r.pos];
        if (!isToken(tok_peek, TOK_ATTRIBUTE)) break;
        _ = try r.readU8();
        var name_off: u32 = 0;
        var have_name_off: bool = false;
        var def_attr_utf16: []const u8 = &[_]u8{};
        var def_attr_num_chars: usize = 0;
        var have_inline_name: bool = false;
        switch (src) {
            .rec => {
                // Attribute name offset (chunk-relative)
                name_off = try r.readU32le();
                have_name_off = true;
            },
            .def => {
                const nm = try readInlineNameDefFlexible(r);
                def_attr_utf16 = nm.utf16;
                def_attr_num_chars = nm.num_chars;
                have_inline_name = true;
            },
        }
        // Collect attribute value into a temporary buffer first
        var final_attr_buf: [2048]u8 = undefined;
        var fbs_final = std.io.fixedBufferStream(&final_attr_buf);
        var final_writer = fbs_final.writer();

        // Special-case TimeCreated SystemTime to render with normalized padding into temp buffer
        if ((have_name_off and isNameSystemTimeFromOffset(chunk, name_off)) or (have_inline_name and utf16EqualsAscii(def_attr_utf16, def_attr_num_chars, "SystemTime"))) {
            try writeSystemTimeAttributeValue(chunk, r, fbs_final.writer(), values);
        } else {
            var attr_buf: [2048]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&attr_buf);
            const aw = fbs.writer();
            try collectAttributeValue(chunk, r, aw, values);
            const written = fbs.getWritten();
            // Drop '+' sentinels and write via writer safely
            var i_norm: usize = 0;
            while (i_norm < written.len) : (i_norm += 1) {
                const ch = written[i_norm];
                if (ch == '+') continue;
                try final_writer.writeByte(ch);
            }
        }
        const final_written = fbs_final.getWritten();
        if (final_written.len == 0) {
            // Skip emitting this attribute entirely (e.g., optional NULL substitution)
            continue;
        }
        // Emit attribute header and value now
        try w.writeByte(' ');
        if (have_name_off) try writeNameFromOffset(chunk, name_off, w) else try writeNameFromUtf16(w, def_attr_utf16, def_attr_num_chars);
        try w.writeAll("=\"");
        try w.writeAll(final_written);
        try w.writeByte('"');

        // If attribute token had has-more flag, continue; else if we're at end, loop ends naturally
        // Note: More attributes are indicated by 0x46, but we already consumed current token; loop proceeds to next
    }

    // Attribute list may include padding; ensure we align to list_end
    if (r.pos != list_end) r.pos = list_end;
}

// Move TemplateValue up so IR can reference it
const TemplateValue = struct {
    t: u8,
    data: []const u8,
};

fn parseTemplateInstanceValues(r: *Reader, allocator: std.mem.Allocator) ![]TemplateValue {
    // Strict descriptor parsing: u32 count, then count descriptors (u16 size, u8 type, u8 reserved=0), then payloads
    const num_values = try r.readU32le();
    if (r.rem() < num_values * 4) return BinXmlError.UnexpectedEof;

    var sizes = try allocator.alloc(u16, num_values);
    errdefer allocator.free(sizes);
    var types = try allocator.alloc(u8, num_values);
    errdefer allocator.free(types);

    var i: usize = 0;
    while (i < num_values) : (i += 1) {
        sizes[i] = try r.readU16le();
        types[i] = try r.readU8();
        const reserved = try r.readU8();
        if (reserved != 0) return BinXmlError.BadToken;
    }

    var values = try allocator.alloc(TemplateValue, num_values);
    i = 0;
    while (i < num_values) : (i += 1) {
        const need: usize = @intCast(sizes[i]);
        if (r.rem() < need) return BinXmlError.UnexpectedEof;
        const slice = r.buf[r.pos .. r.pos + need];
        r.pos += need;
        values[i] = .{ .t = types[i], .data = slice };
    }
    allocator.free(sizes);
    allocator.free(types);
    return values;
}

fn writeValueXml(w: anytype, t: u8, data: []const u8) !void {
    switch (t) {
        0x04 => { // UInt8
            if (data.len < 1) return;
            const v: u8 = data[0];
            try w.print("{d}", .{v});
        },
        0x05 => { // Int16
            if (data.len < 2) return;
            const v = std.mem.readInt(i16, data[0..2], .little);
            try w.print("{d}", .{v});
        },
        0x06 => { // UInt16
            if (data.len < 2) return;
            const v = std.mem.readInt(u16, data[0..2], .little);
            try w.print("{d}", .{v});
        },
        0x01 => { // StringType -> expect Unicode text string layout (num_chars + UTF-16LE)
            if (data.len < 2) {
                // Treat as empty
                return;
            }
            const num_chars = std.mem.readInt(u16, data[0..2], .little);
            const byte_len = @as(usize, num_chars) * 2;
            if (2 + byte_len > data.len) {
                const avail = if (data.len > 2) data.len - 2 else 0;
                const safe_chars: usize = @min(@divFloor(avail, 2), num_chars);
                if (safe_chars == 0) return;
                try writeUtf16LeXmlEscaped(w, data[2 .. 2 + safe_chars * 2], safe_chars);
            } else {
                try writeUtf16LeXmlEscaped(w, data[2 .. 2 + byte_len], num_chars);
            }
        },
        0x02 => { // AnsiStringType (codepage) - treat as bytes, escape
            try writeXmlEscaped(w, data);
        },
        0x07 => { // Int32Type
            if (data.len < 4) return;
            const v = std.mem.readInt(i32, data[0..4], .little);
            try w.print("{d}", .{v});
        },
        0x08 => { // UInt32Type
            if (data.len < 4) return;
            const v = std.mem.readInt(u32, data[0..4], .little);
            try w.print("{d}", .{v});
        },
        0x09 => { // Int64Type
            if (data.len < 8) return;
            const v = std.mem.readInt(i64, data[0..8], .little);
            try w.print("{d}", .{v});
        },
        0x0a => { // UInt64Type
            if (data.len < 8) return;
            const v = std.mem.readInt(u64, data[0..8], .little);
            try w.print("{d}", .{v});
        },
        0x0d => { // BoolType - 32-bit 0/1
            if (data.len < 4) return;
            const v = std.mem.readInt(u32, data[0..4], .little);
            try w.writeAll(if (v == 0) "false" else "true");
        },
        0x0f => { // GuidType (16 bytes, first 3 components little-endian)
            if (data.len < 16) return;
            const d1 = std.mem.readInt(u32, data[0..4], .little);
            const d2 = std.mem.readInt(u16, data[4..6], .little);
            const d3 = std.mem.readInt(u16, data[6..8], .little);
            const d4 = data[8..16];
            try w.print("{{{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}}}", .{
                d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7],
            });
        },
        0x11 => { // FileTimeType (64-bit)
            if (data.len < 8) return;
            const ft = std.mem.readInt(u64, data[0..8], .little);
            var buf: [40]u8 = undefined;
            const out = formatIso8601UtcFromFiletimeMicros(&buf, ft) catch {
                return try w.print("{d}", .{ft});
            };
            try w.writeAll(out);
        },
        0x12 => { // SysTimeType (128-bit)
            if (data.len < 16) return;
            const year = std.mem.readInt(u16, data[0..2], .little);
            const month = std.mem.readInt(u16, data[2..4], .little);
            // data[4..6] day of week
            const day = std.mem.readInt(u16, data[6..8], .little);
            const hour = std.mem.readInt(u16, data[8..10], .little);
            const minute = std.mem.readInt(u16, data[10..12], .little);
            const second = std.mem.readInt(u16, data[12..14], .little);
            const millis = std.mem.readInt(u16, data[14..16], .little);
            var buf: [32]u8 = undefined;
            const slice = try std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
                year, month, day, hour, minute, second, millis,
            });
            try w.writeAll(slice);
        },
        0x13 => { // SidType
            if (data.len < 8) return BinXmlError.UnexpectedEof;
            const rev = data[0];
            const sub_count = data[1];
            const ida_bytes = data[2..8];
            var idauth: u64 = 0;
            // IdentifierAuthority is big-endian 48-bit
            var k: usize = 0;
            while (k < 6) : (k += 1) {
                idauth = (idauth << 8) | ida_bytes[k];
            }
            try w.print("S-{d}-{d}", .{ rev, idauth });
            var off: usize = 8;
            var i: usize = 0;
            while (i < sub_count and off + 4 <= data.len) : (i += 1) {
                const sub = std.mem.readInt(u32, data[off .. off + 4][0..4], .little);
                off += 4;
                try w.print("-{d}", .{sub});
            }
        },
        0x0e => { // BinaryType → hex
            var i: usize = 0;
            while (i < data.len) : (i += 1) {
                try w.print("{x:0>2}", .{data[i]});
            }
        },
        0x14 => { // HexInt32Type
            if (data.len < 4) return BinXmlError.UnexpectedEof;
            const v = std.mem.readInt(u32, data[0..4], .little);
            try w.print("0x{X}", .{v});
        },
        0x15 => { // HexInt64Type
            if (data.len < 8) return BinXmlError.UnexpectedEof;
            const v = std.mem.readInt(u64, data[0..8], .little);
            try w.print("0x{X}", .{v});
        },
        // 0x21 => EvtXml (nested binary XML) is not handled here to avoid re-entrant parsing in value writer
        else => {
            // TODO: implement other types; for now, no-op for unsupported
        },
    }
}

// Render an array of Unicode strings (UTF-16LE, NUL-terminated per item, packed back-to-back)
// as a comma-separated list, trimming trailing empty items but preserving empty items in between.
// moved to util.writeUnicodeStringArrayCommaSeparated

// moved to util.formatIso8601UtcFromUnixMs

// moved to util.formatIso8601UtcFromFiletimeMicros

// moved to util.writePaddedInt

fn renderSubstitutionXml(_chunk: []const u8, w: anytype, is_optional: bool, r: *Reader, values: []const TemplateValue, pad_width: usize) anyerror!void {
    _ = _chunk;
    const id = try r.readU16le();
    const vtype = try r.readU8();
    if (id >= values.len) return BinXmlError.OutOfBounds;
    const v = values[id];
    // debug
    {
        var stderr = std.io.getStdErr().writer();
        _ = stderr.print("[binxml] subst id={d} vtype=0x{x} store.t=0x{x} len={d} opt={d} pad={d}\n", .{ id, vtype, v.t, v.data.len, @intFromBool(is_optional), pad_width }) catch {};
    }
    if (is_optional and (v.t == 0x00 or v.data.len == 0)) {
        // Skip emitting anything for NULL optional
        return;
    }
    // Array handling: if MSB set, repeat for each element
    if ((vtype & 0x80) != 0) {
        const base = vtype & 0x7F;
        switch (base) {
            0x01 => { // array of Unicode strings: emit comma-separated; trim trailing empty items
                // First pass: identify item ranges and last non-empty index
                var ranges = std.ArrayList(struct { start: usize, end: usize }).init(std.heap.page_allocator);
                defer ranges.deinit();
                var i: usize = 0;
                while (i <= v.data.len) {
                    const start = i;
                    var end = i;
                    while (end + 1 < v.data.len) : (end += 2) {
                        const u = std.mem.readInt(u16, v.data[end .. end + 2][0..2], .little);
                        if (u == 0) break;
                    }
                    try ranges.append(.{ .start = start, .end = end });
                    if (end + 1 < v.data.len) {
                        i = end + 2;
                        continue;
                    } else break;
                }
                var last_non_empty: isize = -1;
                var idx_scan: usize = 0;
                while (idx_scan < ranges.items.len) : (idx_scan += 1) {
                    const rr = ranges.items[idx_scan];
                    if (rr.end > rr.start) last_non_empty = @as(isize, @intCast(idx_scan));
                }
                if (last_non_empty >= 0) {
                    var out_idx: usize = 0;
                    while (out_idx <= @as(usize, @intCast(last_non_empty))) : (out_idx += 1) {
                        if (out_idx > 0) try w.writeByte(',');
                        const rr2 = ranges.items[out_idx];
                        if (rr2.end > rr2.start) {
                            const num_chars = (rr2.end - rr2.start) / 2;
                            try writeUtf16LeXmlEscaped(w, v.data[rr2.start..rr2.end], num_chars);
                        }
                    }
                }
            },
            else => {
                // TODO: implement arrays for other base types
            },
        }
        return;
    }
    // Queue nested EvtXml (0x21) from substitutions
    if ((v.t & 0x7F) == 0x21 and v.data.len > 0) {
        // If a child element just closed, this substitution arrives in the parent
        // content. Queue onto the current frame so it flushes on the parent’s close.
        r.queueEvtXml(v.data);
        return;
    }

    // If padding requested and base type is integer, pad
    const base = vtype & 0x7F;
    if (pad_width > 0) {
        switch (base) {
            0x07 => { // Int32
                if (v.data.len < 4) return BinXmlError.UnexpectedEof;
                const num = std.mem.readInt(i32, v.data[0..4], .little);
                try writePaddedInt(w, i32, num, pad_width);
                return;
            },
            0x08 => { // UInt32
                if (v.data.len < 4) return BinXmlError.UnexpectedEof;
                const num = std.mem.readInt(u32, v.data[0..4], .little);
                try writePaddedInt(w, u32, num, pad_width);
                return;
            },
            0x09 => { // Int64
                if (v.data.len < 8) return BinXmlError.UnexpectedEof;
                const num = std.mem.readInt(i64, v.data[0..8], .little);
                try writePaddedInt(w, i64, num, pad_width);
                return;
            },
            0x0a => { // UInt64
                if (v.data.len < 8) return BinXmlError.UnexpectedEof;
                const num = std.mem.readInt(u64, v.data[0..8], .little);
                try writePaddedInt(w, u64, num, pad_width);
                return;
            },
            else => {},
        }
    }
    try writeValueXml(w, v.t, v.data);
}

fn renderElementXml(chunk: []const u8, r: *Reader, w: anytype, values: []const TemplateValue, src: Source) anyerror!void {
    {
        var stderr = std.io.getStdErr().writer();
        const show = @min(r.rem(), 12);
        _ = try stderr.print("[binxml] elem start peek src={s} bytes:", .{if (src == .rec) "rec" else "def"});
        var i: usize = 0;
        while (i < show) : (i += 1) {
            _ = try stderr.print(" {x:0>2}", .{r.buf[r.pos + i]});
        }
        _ = try stderr.print("\n", .{});
    }
    const element_start_pos = r.pos;
    const start_tok = try r.readU8();
    {
        var stderr = std.io.getStdErr().writer();
        _ = try stderr.print("[binxml] elem start_tok=0x{x} src={s}\n", .{ start_tok, if (src == .rec) "rec" else "def" });
    }
    if (!isToken(start_tok, TOK_OPEN_START)) return BinXmlError.BadToken;
    // dependency id
    if (r.rem() < 2) return BinXmlError.UnexpectedEof;
    const dep_id = try r.readU16le();
    {
        var stderr = std.io.getStdErr().writer();
        _ = try stderr.print("[binxml] dep_id=0x{x}\n", .{dep_id});
    }
    const data_size = try r.readU32le();
    const element_end_pos = element_start_pos + 7 + @as(usize, data_size);
    var name_off: u32 = 0;
    var def_name: []const u8 = &[_]u8{};
    var def_name_chars: usize = 0;
    var use_name_offset: bool = (src == .rec);
    switch (src) {
        .rec => {
            name_off = try r.readU32le();
            use_name_offset = true;
        },
        .def => {
            {
                var stderr = std.io.getStdErr().writer();
                const show = @min(r.rem(), 24);
                _ = try stderr.print("[binxml] def name bytes:", .{});
                var i: usize = 0;
                while (i < show) : (i += 1) {
                    _ = try stderr.print(" {x:0>2}", .{r.buf[r.pos + i]});
                }
                _ = try stderr.print("\n", .{});
            }
            const nm = try readInlineNameDefFlexible(r);
            def_name = nm.utf16;
            def_name_chars = nm.num_chars;
            use_name_offset = false;
        },
    }
    // New element scope
    r.pushFrame();
    try w.writeByte('<');
    if (use_name_offset) try writeNameFromOffset(chunk, name_off, w) else try writeNameFromUtf16(w, def_name, def_name_chars);
    const has_attrs = hasMore(start_tok, TOK_OPEN_START);
    var pad: usize = 0;
    if (has_attrs) {
        try writeAttributeListXml(chunk, r, w, src, values);
        if (r.pos > element_end_pos) r.pos = element_end_pos;
        // Some definitions include padding (up to 4 zero bytes) after attribute list
        while (pad < 4 and r.rem() > 0 and r.buf[r.pos] == 0) : (pad += 1) {
            r.pos += 1;
        }
    }
    if (r.pos >= element_end_pos) return BinXmlError.UnexpectedEof;
    const nxt = try r.readU8();
    {
        var stderr = std.io.getStdErr().writer();
        _ = try stderr.print("[binxml] after attrs nxt=0x{x} pad={d}\n", .{ nxt, pad });
    }
    if (isToken(nxt, TOK_CLOSE_EMPTY)) {
        // Determine if evtx_dump would emit a self-closing or expanded form.
        // Based on observed output: Provider and TimeCreated are expanded, others may be self-closing.
        const expand = if (use_name_offset)
            isNameSystemTimeFromOffset(chunk, name_off)
        else
            utf16EqualsAscii(def_name, def_name_chars, "Provider") or utf16EqualsAscii(def_name, def_name_chars, "TimeCreated");
        if (expand) {
            try w.writeByte('>');
            // streaming queued nested payloads no longer used
            try w.writeAll("</");
            if (use_name_offset) try writeNameFromOffset(chunk, name_off, w) else try writeNameFromUtf16(w, def_name, def_name_chars);
            try w.writeByte('>');
            if (r.depth > 0) r.depth -= 1;
        } else {
            try w.writeAll("/>");
        }
        return;
    }
    if (!isToken(nxt, TOK_CLOSE_START)) return BinXmlError.BadToken;
    try w.writeByte('>');

    // content
    var content_pad2: bool = false;
    while (true) {
        const t = try r.peekU8();
        {
            var stderr = std.io.getStdErr().writer();
            _ = try stderr.print("[binxml] content tok=0x{x} rem={d}\n", .{ t, r.rem() });
        }
        if (isToken(t, TOK_END_ELEMENT)) {
            _ = try r.readU8();
            // streaming queued nested payloads no longer used; IR path appends children
            try w.writeAll("</");
            if (use_name_offset) try writeNameFromOffset(chunk, name_off, w) else try writeNameFromUtf16(w, def_name, def_name_chars);
            try w.writeByte('>');
            // Pop scope after closing tag
            if (r.depth > 0) r.depth -= 1;
            return;
        } else if (isToken(t, TOK_OPEN_START)) {
            // legacy streaming recursion removed; this path should not be taken
            return BinXmlError.BadToken;
        } else if (isToken(t, TOK_VALUE)) {
            // Concatenate value tokens sequence
            while (true) {
                _ = try r.readU8();
                const vtype = try r.readU8();
                {
                    var stderr = std.io.getStdErr().writer();
                    _ = try stderr.print("[binxml] value vtype=0x{x}\n", .{vtype});
                }
                if ((vtype & 0x7f) == 0x21) {
                    // Nested EvtXml payload embedded directly in content
                    const payload = try r.readLenPrefixedBytes16();
                    r.queueEvtXml(payload);
                } else if (vtype == 0x01) {
                    var text = try readUnicodeTextString(r);
                    // Handle '+' formatting sentinel like in attributes: a standalone '+' (UTF-16LE) requests zero-padding for the next number
                    if (text.len >= 2 and text[0] == 0x2B and text[1] == 0x00) {
                        if (text.len == 2) {
                            content_pad2 = true;
                            // Do not emit this sentinel
                            // fallthrough to next token
                        } else {
                            // Strip leading '+' and emit the rest
                            text = text[2..];
                            try writeUtf16LeXmlEscaped(w, text, text.len / 2);
                        }
                    } else {
                        try writeUtf16LeXmlEscaped(w, text, text.len / 2);
                    }
                } else if (valueTypeFixedSize(vtype)) |sz| {
                    const payload = try readFixedBytes(r, sz);
                    if (content_pad2 and (vtype == 0x07 or vtype == 0x08 or vtype == 0x09 or vtype == 0x0a)) {
                        switch (vtype) {
                            0x07 => {
                                const num = std.mem.readInt(i32, payload[0..4], .little);
                                try writePaddedInt(w, i32, num, 2);
                            },
                            0x08 => {
                                const num = std.mem.readInt(u32, payload[0..4], .little);
                                try writePaddedInt(w, u32, num, 2);
                            },
                            0x09 => {
                                const num = std.mem.readInt(i64, payload[0..8], .little);
                                try writePaddedInt(w, i64, num, 2);
                            },
                            0x0a => {
                                const num = std.mem.readInt(u64, payload[0..8], .little);
                                try writePaddedInt(w, u64, num, 2);
                            },
                            else => unreachable,
                        }
                        content_pad2 = false;
                    } else {
                        try writeValueXml(w, vtype, payload);
                    }
                } else if (vtype == 0x0e) {
                    const payload = try r.readLenPrefixedBytes16();
                    try writeValueXml(w, vtype, payload);
                } else if (vtype == 0x13) {
                    const payload = try r.readSidBytes();
                    try writeValueXml(w, vtype, payload);
                } else {
                    return BinXmlError.BadToken;
                }
                if (r.rem() == 0) break;
                const pk = try r.peekU8();
                if (!isToken(pk, TOK_VALUE)) break;
            }
            if (r.depth > 0) r.frames[r.depth - 1].had_text_content = true;
        } else if (isToken(t, TOK_CDATA)) {
            _ = try r.readU8();
            const data = try readUnicodeTextString(r);
            try w.writeAll("<![CDATA[");
            // Emit raw UTF-8; CDATA must not be escaped; here we best-effort convert to UTF-8
            try writeUtf16LeXmlEscaped(w, data, data.len / 2);
            try w.writeAll("]]>");
            if (r.depth > 0) r.frames[r.depth - 1].had_text_content = true;
        } else if (isToken(t, TOK_CHARREF)) {
            _ = try r.readU8();
            // 16-bit value
            const v = try r.readU16le();
            try w.print("&#{d};", .{v});
            if (r.depth > 0) r.frames[r.depth - 1].had_text_content = true;
        } else if (isToken(t, TOK_ENTITYREF)) {
            _ = try r.readU8();
            // Name offset variant for entity. Read name-offset like a Name and output &name;
            const ent_name_off = try r.readU32le();
            try w.writeByte('&');
            try writeNameFromOffset(chunk, ent_name_off, w);
            try w.writeByte(';');
            if (r.depth > 0) r.frames[r.depth - 1].had_text_content = true;
        } else if (isToken(t, TOK_NORMAL_SUBST)) {
            _ = try r.readU8();
            const padw: usize = if (content_pad2) 2 else 0;
            try renderSubstitutionXml(chunk, w, false, r, values, padw);
            content_pad2 = false;
            if (r.depth > 0) r.frames[r.depth - 1].had_text_content = true;
        } else if (isToken(t, TOK_OPTIONAL_SUBST)) {
            _ = try r.readU8();
            const padw: usize = if (content_pad2) 2 else 0;
            try renderSubstitutionXml(chunk, w, true, r, values, padw);
            content_pad2 = false;
            if (r.depth > 0) r.frames[r.depth - 1].had_text_content = true;
        } else if (t == TOK_EOF) {
            return BinXmlError.UnexpectedEof;
        } else {
            return BinXmlError.BadToken;
        }
    }
}

fn renderXmlWithContext(ctx: *Context, chunk: []const u8, bin: []const u8, w: anytype) anyerror!void {
    var r = Reader.init(bin);

    // Optional fragment header
    if (r.rem() >= 4 and r.buf[r.pos] == TOK_FRAGMENT_HEADER) {
        _ = try r.readU8(); // token
        _ = try r.readU8(); // major
        _ = try r.readU8(); // minor
        _ = try r.readU8(); // flags
    }

    if (r.rem() == 0) {
        try w.writeAll("<Event/>");
        return;
    }

    const first = try r.peekU8();
    if (ctx.verbose) {
        var stderr = std.io.getStdErr().writer();
        _ = try stderr.print("[binxml] first=0x{x} len={d}\n", .{ first, bin.len });
    }
    if (first == TOK_TEMPLATE_INSTANCE) {
        _ = try r.readU8(); // consume
        // Template definition (header within the record, data in chunk at def_data_off)
        if (r.rem() < 1 + 4 + 4 + 4 + 16 + 4) return BinXmlError.UnexpectedEof;
        _ = try r.readU8(); // unknown
        _ = try r.readU32le(); // template id (unused)
        const def_data_off = try r.readU32le();
        _ = try r.readU32le(); // next def off (unused)
        // GUID
        const guid = try r.readGuid();
        const def_size = try r.readU32le();
        if (ctx.verbose) {
            var stderr = std.io.getStdErr().writer();
            _ = try stderr.print("[binxml] tmpl def_off=0x{x} def_size={d}\n", .{ def_data_off, def_size });
        }

        // Use alternative TemplateDefinition header layout: [4 bytes unknown][16 bytes GUID][4 bytes data_size][data...]
        const def_off_usize: usize = @intCast(def_data_off);
        if (def_off_usize + 24 > chunk.len) return BinXmlError.OutOfBounds;
        const td_data_size = std.mem.readInt(u32, chunk[def_off_usize + 20 .. def_off_usize + 24][0..4], .little);
        const data_start = def_off_usize + 24;
        const data_end = data_start + @as(usize, td_data_size);
        if (data_end > chunk.len or data_start >= chunk.len) return BinXmlError.OutOfBounds;
        if (ctx.verbose) {
            var stderr = std.io.getStdErr().writer();
            _ = try stderr.print("[binxml] using chunk def data at 0x{x}..0x{x}\n", .{ data_start, data_end });
        }
        var def_r = Reader.init(chunk[data_start..data_end]);
        // Optional fragment header inside definition
        if (def_r.rem() >= 4 and def_r.buf[def_r.pos] == TOK_FRAGMENT_HEADER) {
            _ = try def_r.readU8();
            _ = try def_r.readU8();
            _ = try def_r.readU8();
            _ = try def_r.readU8();
        }

        // Skip inline copy of template definition data in the record if present
        if (r.rem() >= def_size and (r.buf[r.pos] == TOK_FRAGMENT_HEADER or r.buf[r.pos] == TOK_OPEN_START)) {
            const start = r.pos;
            const end = start + @as(usize, def_size);
            r.pos = end;
            if (ctx.verbose) {
                var stderr = std.io.getStdErr().writer();
                _ = try stderr.print("[binxml] skipped inline def at rec+0x{x}..0x{x}\n", .{ start, end });
            }
        }

        // Values follow in the record after the header we just read (and possible inline data)
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const alloc = gpa.allocator();
        const values = try parseTemplateInstanceValues(&r, alloc);
        // Copy value descriptors into context arena to ensure stable lifetime in Release builds
        const vals_copy = try ctx.arena.allocator().alloc(TemplateValue, values.len);
        var vi: usize = 0;
        while (vi < values.len) : (vi += 1) vals_copy[vi] = values[vi];
        defer alloc.free(values);
        const key: Context.DefKey = .{ .def_data_off = def_data_off, .guid = guid };
        const got = try ctx.cache.getOrPut(key);
        if (!got.found_existing) {
            const parsed = try parseElementIR(chunk, &def_r, ctx.arena.allocator(), .def);
            got.value_ptr.* = parsed;
        }
        const cloned = try cloneElementTree(got.value_ptr.*, ctx.arena.allocator());
        cloned.local_values = vals_copy;
        try renderElementIRXml(chunk, cloned, vals_copy, w, 0);
        return;
    } else {
        // Non-template path: IR parse and render for parity
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const alloc = gpa.allocator();
        const root = try parseElementIR(chunk, &r, alloc, .rec);
        try renderElementIRXml(chunk, root, &[_]TemplateValue{}, w, 0);
        return;
    }
}

pub fn render(chunk: []const u8, bin: []const u8, mode: RenderMode, w: anytype) !void {
    var ctx = try Context.init(std.heap.page_allocator);
    defer ctx.deinit();
    switch (mode) {
        .xml => try renderXmlWithContext(&ctx, chunk, bin, w),
        .json => try w.writeAll("{}"),
        .jsonl => try w.writeAll("{}"),
    }
}

// --- Context and template cache (IR) ---
pub const Context = struct {
    const DefKey = struct {
        def_data_off: u32,
        guid: [16]u8,

        pub fn hash(self: @This()) u64 {
            var h = std.hash.Wyhash.init(0);
            h.update(std.mem.asBytes(&self.def_data_off));
            h.update(&self.guid);
            return h.final();
        }

        pub fn eql(a: @This(), b: @This()) bool {
            return a.def_data_off == b.def_data_off and std.mem.eql(u8, &a.guid, &b.guid);
        }
    };

    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    cache: std.AutoHashMap(DefKey, *IR.Element),
    verbose: bool = false,

    pub fn init(allocator: std.mem.Allocator) !Context {
        return .{ .allocator = allocator, .arena = std.heap.ArenaAllocator.init(allocator), .cache = std.AutoHashMap(DefKey, *IR.Element).init(allocator), .verbose = false };
    }

    pub fn deinit(self: *Context) void {
        self.cache.deinit();
        self.arena.deinit();
    }

    pub fn resetPerChunk(self: *Context) void {
        // EVTX template definitions are chunk-local. Reset arena and clear cache buckets.
        self.cache.clearRetainingCapacity();
        self.arena.deinit();
        self.arena = std.heap.ArenaAllocator.init(self.allocator);
    }
};

fn cloneElementTree(src: *const IR.Element, alloc: std.mem.Allocator) !*IR.Element {
    const dst = try irNewElement(alloc, src.name);
    // copy local_values slice
    dst.local_values = src.local_values;
    // copy render hint flags
    dst.has_element_child = src.has_element_child;
    dst.has_evtxml_value_in_tree = src.has_evtxml_value_in_tree;
    dst.has_evtxml_subst_in_tree = src.has_evtxml_subst_in_tree;
    dst.has_attr_evtxml_value = src.has_attr_evtxml_value;
    dst.has_attr_evtxml_subst = src.has_attr_evtxml_subst;
    // clone attrs
    var ai: usize = 0;
    while (ai < src.attrs.items.len) : (ai += 1) {
        const a = src.attrs.items[ai];
        var vals = std.ArrayList(IR.Node).init(alloc);
        var vi: usize = 0;
        while (vi < a.value.items.len) : (vi += 1) {
            const nd = a.value.items[vi];
            if (nd.tag == .Element) {
                // elements are not expected in attr values; skip defensively
                continue;
            }
            try vals.append(nd);
        }
        try dst.attrs.append(.{ .name = a.name, .value = vals });
    }
    // clone children
    var ci: usize = 0;
    while (ci < src.children.items.len) : (ci += 1) {
        const nd = src.children.items[ci];
        if (nd.tag == .Element) {
            const child = try cloneElementTree(nd.elem.?, alloc);
            try dst.children.append(.{ .tag = .Element, .elem = child });
        } else {
            try dst.children.append(nd);
        }
    }
    return dst;
}

pub fn renderWithContext(ctx: *Context, chunk: []const u8, bin: []const u8, mode: RenderMode, w: anytype) !void {
    switch (mode) {
        .xml => try renderXmlWithContext(ctx, chunk, bin, w),
        .json => try w.writeAll("{}"),
        .jsonl => try w.writeAll("{}"),
    }
}

// --- IR types (subset) ---
const IR = struct {
    const Name = union(enum) {
        NameOffset: u32,
        InlineUtf16: struct { bytes: []const u8, num_chars: usize },
    };

    const NodeTag = enum { Element, Text, Value, Subst, CharRef, EntityRef, CData, Pad };

    const Node = struct {
        tag: NodeTag,
        elem: ?*Element = null,
        text_utf16: []const u8 = &[_]u8{},
        text_num_chars: usize = 0,
        vtype: u8 = 0,
        vbytes: []const u8 = &[_]u8{},
        subst_id: u16 = 0,
        subst_vtype: u8 = 0,
        subst_optional: bool = false,
        charref_value: u16 = 0,
        entity_name_off: u32 = 0,
        pad_width: usize = 0,
    };

    const Attr = struct {
        name: Name,
        // Flat token list allowed in attribute contexts
        value: std.ArrayList(Node),
    };

    const Element = struct {
        name: Name,
        attrs: std.ArrayList(Attr),
        children: std.ArrayList(Node),
        // Optional nested template instance values that apply to this element subtree
        local_values: []const TemplateValue = &[_]TemplateValue{},
        // Render hints computed during IR build
        has_element_child: bool = false,
        has_evtxml_value_in_tree: bool = false,
        has_evtxml_subst_in_tree: bool = false,
        has_attr_evtxml_value: bool = false,
        has_attr_evtxml_subst: bool = false,
    };
};

fn irNewElement(allocator: std.mem.Allocator, name: IR.Name) !*IR.Element {
    const el = try allocator.create(IR.Element);
    el.* = .{ .name = name, .attrs = std.ArrayList(IR.Attr).init(allocator), .children = std.ArrayList(IR.Node).init(allocator), .local_values = &[_]TemplateValue{} };
    return el;
}

fn irPushText(list: *std.ArrayList(IR.Node), utf16: []const u8, num_chars: usize) !void {
    try list.append(.{ .tag = .Text, .text_utf16 = utf16, .text_num_chars = num_chars });
}

fn irPushPad2(list: *std.ArrayList(IR.Node)) !void {
    try list.append(.{ .tag = .Pad, .pad_width = 2 });
}

fn parseInlineNameFlexibleIR(r: *Reader) !IR.Name {
    const nm = try readInlineNameDefFlexible(r);
    return IR.Name{ .InlineUtf16 = .{ .bytes = nm.utf16, .num_chars = nm.num_chars } };
}

fn parseAttributeListIR(chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source) !std.ArrayList(IR.Attr) {
    _ = chunk;
    const list_size = try r.readU32le();
    const list_start = r.pos;
    const list_end = list_start + list_size;
    var out = std.ArrayList(IR.Attr).init(allocator);
    while (r.pos < list_end and r.rem() > 0 and isToken(r.buf[r.pos], TOK_ATTRIBUTE)) {
        _ = try r.readU8();
        var name: IR.Name = undefined;
        switch (src) {
            .rec => {
                const off = try r.readU32le();
                name = IR.Name{ .NameOffset = off };
            },
            .def => {
                name = try parseInlineNameFlexibleIR(r);
            },
        }
        // Collect attribute value tokens into IR
        var tokens = std.ArrayList(IR.Node).init(allocator);
        try collectValueTokensIR(r, &tokens);
        try out.append(.{ .name = name, .value = tokens });
    }
    if (r.pos != list_end) r.pos = list_end;
    return out;
}

fn collectValueTokensIR(r: *Reader, out: *std.ArrayList(IR.Node)) !void {
    var want_pad2: bool = false;
    while (true) {
        if (r.rem() == 0) break;
        const pk = r.buf[r.pos];
        if (isToken(pk, TOK_ATTRIBUTE) or isToken(pk, TOK_CLOSE_START) or isToken(pk, TOK_CLOSE_EMPTY)) break;
        if (isToken(pk, TOK_VALUE)) {
            _ = try r.readU8();
            const vtype = try r.readU8();
            if ((vtype & 0x7f) == 0x21) {
                if (r.rem() < 2) return BinXmlError.UnexpectedEof;
                const blen = try r.readU16le();
                if (r.rem() < blen) return BinXmlError.UnexpectedEof;
                // Store as Value node with vtype=0x21 and bytes payload; will be parsed and spliced at resolution/render time
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = r.buf[r.pos .. r.pos + blen] });
                r.pos += blen;
            } else if (vtype == 0x01) {
                const text = try readUnicodeTextString(r);
                if (text.len == 2 and text[0] == 0x2B and text[1] == 0x00) {
                    want_pad2 = true;
                    continue;
                }
                try out.append(.{ .tag = .Text, .text_utf16 = text, .text_num_chars = text.len / 2 });
            } else if (valueTypeFixedSize(vtype)) |sz| {
                const payload = try readFixedBytes(r, sz);
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = payload, .pad_width = if (want_pad2) 2 else 0 });
                want_pad2 = false;
            } else if (vtype == 0x0e) {
                const payload = try r.readLenPrefixedBytes16();
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = payload, .pad_width = if (want_pad2) 2 else 0 });
                want_pad2 = false;
            } else if (vtype == 0x13) {
                const payload = try r.readSidBytes();
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = payload });
            } else return BinXmlError.BadToken;
            continue;
        } else if (isToken(pk, TOK_NORMAL_SUBST) or isToken(pk, TOK_OPTIONAL_SUBST)) {
            const optional = isToken(pk, TOK_OPTIONAL_SUBST);
            _ = try r.readU8();
            const id = try r.readU16le();
            const vtype = try r.readU8();
            try out.append(.{ .tag = .Subst, .subst_id = id, .subst_vtype = vtype, .subst_optional = optional, .pad_width = if (want_pad2) 2 else 0 });
            want_pad2 = false;
            continue;
        } else if (isToken(pk, TOK_CHARREF)) {
            _ = try r.readU8();
            const v = try r.readU16le();
            try out.append(.{ .tag = .CharRef, .charref_value = v });
            continue;
        } else if (isToken(pk, TOK_ENTITYREF)) {
            _ = try r.readU8();
            const ent_name_off = try r.readU32le();
            try out.append(.{ .tag = .EntityRef, .entity_name_off = ent_name_off });
            continue;
        } else if (isToken(pk, TOK_CDATA)) {
            _ = try r.readU8();
            const data = try readUnicodeTextString(r);
            try out.append(.{ .tag = .CData, .text_utf16 = data, .text_num_chars = data.len / 2 });
            continue;
        } else break;
    }
}

fn updateHintsFromNodes(el: *IR.Element, nodes: []const IR.Node, include_attr: bool) void {
    var i: usize = 0;
    while (i < nodes.len) : (i += 1) {
        const nd = nodes[i];
        switch (nd.tag) {
            .Value => if ((nd.vtype & 0x7f) == 0x21 and nd.vbytes.len > 0) {
                el.has_evtxml_value_in_tree = true;
                if (include_attr) el.has_attr_evtxml_value = true;
            },
            .Subst => if ((nd.subst_vtype & 0x7f) == 0x21) {
                el.has_evtxml_subst_in_tree = true;
                if (include_attr) el.has_attr_evtxml_subst = true;
            },
            else => {},
        }
    }
}

fn parseElementIR(chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source) !*IR.Element {
    const element_start = r.pos;
    const start = try r.readU8();
    if (!isToken(start, TOK_OPEN_START)) return BinXmlError.BadToken;
    _ = try r.readU16le(); // dep_id
    const data_size = try r.readU32le();
    const header_len: usize = 1 + 2 + 4;
    var element_end = element_start + header_len + @as(usize, data_size);
    if (element_end > r.buf.len) element_end = r.buf.len;
    const name: IR.Name = switch (src) {
        .rec => IR.Name{ .NameOffset = try r.readU32le() },
        .def => try parseInlineNameFlexibleIR(r),
    };
    const el = try irNewElement(allocator, name);
    if (hasMore(start, TOK_OPEN_START)) {
        el.attrs = try parseAttributeListIR(chunk, r, allocator, src);
        // hints from attributes
        var ai_h: usize = 0;
        while (ai_h < el.attrs.items.len) : (ai_h += 1) {
            updateHintsFromNodes(el, el.attrs.items[ai_h].value.items, true);
        }
        // skip padding up to 4 zeros
        var pad: usize = 0;
        while (pad < 4 and r.pos < element_end and r.buf[r.pos] == 0) : (pad += 1) r.pos += 1;
    }
    if (r.pos >= element_end or r.rem() == 0) return el;
    const nxt = try r.readU8();
    if (isToken(nxt, TOK_CLOSE_EMPTY)) {
        return el;
    }
    if (!isToken(nxt, TOK_CLOSE_START)) return BinXmlError.BadToken;
    // content
    while (true) {
        if (r.pos >= element_end or r.rem() == 0) break;
        const t = r.buf[r.pos];
        if (isToken(t, TOK_END_ELEMENT)) {
            _ = try r.readU8();
            break;
        } else if (isToken(t, TOK_OPEN_START)) {
            const child = try parseElementIR(chunk, r, allocator, src);
            try el.children.append(.{ .tag = .Element, .elem = child });
            el.has_element_child = true;
        } else if (isToken(t, TOK_VALUE) or isToken(t, TOK_NORMAL_SUBST) or isToken(t, TOK_OPTIONAL_SUBST) or isToken(t, TOK_CDATA) or isToken(t, TOK_CHARREF) or isToken(t, TOK_ENTITYREF)) {
            var seq = std.ArrayList(IR.Node).init(allocator);
            try collectValueTokensIR(r, &seq);
            // append tokens into children list as individual nodes
            for (seq.items) |nd| try el.children.append(nd);
            // update hints from these tokens
            updateHintsFromNodes(el, seq.items, false);
        } else break;
        if (r.pos >= element_end) break;
    }
    return el;
}

fn writeNameXml(chunk: []const u8, name: IR.Name, w: anytype) !void {
    switch (name) {
        .NameOffset => |off| try writeNameFromOffset(chunk, off, w),
        .InlineUtf16 => |inl| try writeNameFromUtf16(w, inl.bytes, inl.num_chars),
    }
}

fn attrNameIsSystemTime(name: IR.Name, chunk: []const u8) bool {
    return switch (name) {
        .NameOffset => |off| isNameSystemTimeFromOffset(chunk, off),
        .InlineUtf16 => |inl| utf16EqualsAscii(inl.bytes, inl.num_chars, "SystemTime"),
    };
}

fn renderAttrValueFromIR(chunk: []const u8, nodes: []const IR.Node, values: []const TemplateValue, w: anytype) !void {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const aw = fbs.writer();
    var pending_pad: usize = 0;
    for (nodes) |nd| switch (nd.tag) {
        .Text => try writeUtf16LeXmlEscaped(aw, nd.text_utf16, nd.text_num_chars),
        .Pad => pending_pad = nd.pad_width,
        .Value => {
            if (pending_pad > 0 and (nd.vtype == 0x07 or nd.vtype == 0x08 or nd.vtype == 0x09 or nd.vtype == 0x0a)) {
                switch (nd.vtype) {
                    0x07 => try writePaddedInt(aw, i32, std.mem.readInt(i32, nd.vbytes[0..4], .little), pending_pad),
                    0x08 => try writePaddedInt(aw, u32, std.mem.readInt(u32, nd.vbytes[0..4], .little), pending_pad),
                    0x09 => try writePaddedInt(aw, i64, std.mem.readInt(i64, nd.vbytes[0..8], .little), pending_pad),
                    0x0a => try writePaddedInt(aw, u64, std.mem.readInt(u64, nd.vbytes[0..8], .little), pending_pad),
                    else => {},
                }
                pending_pad = 0;
            } else {
                try writeValueXml(aw, nd.vtype, nd.vbytes);
            }
        },
        .Subst => {
            if (nd.subst_id >= values.len) continue;
            const vv = values[nd.subst_id];
            if (nd.subst_optional and (vv.t == 0x00 or vv.data.len == 0)) continue;
            if ((vv.t & 0x7f) == 0x21) {
                // Nested EvtXml: parse and render inline into attribute buffer by flattening text
                // For now, ignore nested EvtXml inside attributes for parity; rarely used
                continue;
            }
            // Array handling driven by declared substitution vtype
            if ((nd.subst_vtype & 0x80) != 0) {
                const base = nd.subst_vtype & 0x7f;
                if (base == 0x01) {
                    try writeUnicodeStringArrayCommaSeparated(aw, vv.data);
                    continue;
                }
            }
            if (nd.pad_width > 0 and (vv.t == 0x07 or vv.t == 0x08 or vv.t == 0x09 or vv.t == 0x0a)) {
                switch (vv.t) {
                    0x07 => try writePaddedInt(aw, i32, std.mem.readInt(i32, vv.data[0..4], .little), nd.pad_width),
                    0x08 => try writePaddedInt(aw, u32, std.mem.readInt(u32, vv.data[0..4], .little), nd.pad_width),
                    0x09 => try writePaddedInt(aw, i64, std.mem.readInt(i64, vv.data[0..8], .little), nd.pad_width),
                    0x0a => try writePaddedInt(aw, u64, std.mem.readInt(u64, vv.data[0..8], .little), nd.pad_width),
                    else => try writeValueXml(aw, vv.t, vv.data),
                }
            } else {
                try writeValueXml(aw, vv.t, vv.data);
            }
        },
        .CharRef => try aw.print("&#{d};", .{nd.charref_value}),
        .EntityRef => {
            try aw.writeByte('&');
            try writeNameFromOffset(chunk, nd.entity_name_off, aw);
            try aw.writeByte(';');
        },
        .CData => try writeUtf16LeXmlEscaped(aw, nd.text_utf16, nd.text_num_chars),
        .Element => {},
    };
    // Drop '+' sentinels if any made it through
    const written = fbs.getWritten();
    var i: usize = 0;
    while (i < written.len) : (i += 1) {
        const ch = written[i];
        if (ch == '+') continue;
        try w.writeByte(ch);
    }
}

fn hasNestedEvtXmlSubst(nodes: []const IR.Node, values: []const TemplateValue) bool {
    var i: usize = 0;
    while (i < nodes.len) : (i += 1) {
        const nd = nodes[i];
        if (nd.tag == .Subst and nd.subst_id < values.len) {
            const vv = values[nd.subst_id];
            if ((vv.t & 0x7f) == 0x21 and vv.data.len > 0) return true;
        }
    }
    return false;
}

fn renderTextContentFromIR(chunk: []const u8, nodes: []const IR.Node, values: []const TemplateValue, w: anytype) !void {
    var pending_pad: usize = 0;
    var i: usize = 0;
    while (i < nodes.len) : (i += 1) {
        const nd = nodes[i];
        switch (nd.tag) {
            .Text => try writeUtf16LeXmlEscaped(w, nd.text_utf16, nd.text_num_chars),
            .Pad => pending_pad = nd.pad_width,
            .Value => {
                if (pending_pad > 0 and (nd.vtype == 0x07 or nd.vtype == 0x08 or nd.vtype == 0x09 or nd.vtype == 0x0a)) {
                    switch (nd.vtype) {
                        0x07 => try writePaddedInt(w, i32, std.mem.readInt(i32, nd.vbytes[0..4], .little), pending_pad),
                        0x08 => try writePaddedInt(w, u32, std.mem.readInt(u32, nd.vbytes[0..4], .little), pending_pad),
                        0x09 => try writePaddedInt(w, i64, std.mem.readInt(i64, nd.vbytes[0..8], .little), pending_pad),
                        0x0a => try writePaddedInt(w, u64, std.mem.readInt(u64, nd.vbytes[0..8], .little), pending_pad),
                        else => {},
                    }
                    pending_pad = 0;
                } else {
                    try writeValueXml(w, nd.vtype, nd.vbytes);
                }
            },
            .Subst => {
                if (nd.subst_id >= values.len) continue;
                const vv = values[nd.subst_id];
                if (nd.subst_optional and (vv.t == 0x00 or vv.data.len == 0)) continue;
                if ((vv.t & 0x7f) == 0x21) {
                    // nested evt xml: not part of inline text
                    continue;
                }
                // Array handling
                if ((nd.subst_vtype & 0x80) != 0) {
                    const base = nd.subst_vtype & 0x7f;
                    if (base == 0x01) {
                        try writeUnicodeStringArrayCommaSeparated(w, vv.data);
                        continue;
                    }
                }
                if (nd.pad_width > 0 and (vv.t == 0x07 or vv.t == 0x08 or vv.t == 0x09 or vv.t == 0x0a)) {
                    switch (vv.t) {
                        0x07 => try writePaddedInt(w, i32, std.mem.readInt(i32, vv.data[0..4], .little), nd.pad_width),
                        0x08 => try writePaddedInt(w, u32, std.mem.readInt(u32, vv.data[0..4], .little), nd.pad_width),
                        0x09 => try writePaddedInt(w, i64, std.mem.readInt(i64, vv.data[0..8], .little), nd.pad_width),
                        0x0a => try writePaddedInt(w, u64, std.mem.readInt(u64, vv.data[0..8], .little), nd.pad_width),
                        else => try writeValueXml(w, vv.t, vv.data),
                    }
                } else {
                    try writeValueXml(w, vv.t, vv.data);
                }
            },
            .CharRef => try w.print("&#{d};", .{nd.charref_value}),
            .EntityRef => {
                try w.writeByte('&');
                try writeNameFromOffset(chunk, nd.entity_name_off, w);
                try w.writeByte(';');
            },
            .CData => try writeUtf16LeXmlEscaped(w, nd.text_utf16, nd.text_num_chars),
            .Element => {},
        }
    }
}

fn renderEvtXmlPayloadAsChildren(chunk: []const u8, data: []const u8, alloc: std.mem.Allocator, values: []const TemplateValue, w: anytype, indent: usize) anyerror!void {
    if (data.len == 0) return;
    var r = Reader.init(data);
    if (r.rem() >= 4 and r.buf[r.pos] == TOK_FRAGMENT_HEADER) {
        _ = try r.readU8();
        _ = try r.readU8();
        _ = try r.readU8();
        _ = try r.readU8();
    }
    while (r.rem() > 0) {
        const pk = r.buf[r.pos];
        if (isToken(pk, TOK_OPEN_START)) {
            const child = try parseElementIR(chunk, &r, alloc, .def);
            try renderElementIRXml(chunk, child, values, w, indent);
        } else break;
    }
}

fn appendEvtXmlPayloadChildrenIR(chunk: []const u8, data: []const u8, alloc: std.mem.Allocator, parent: *IR.Element) anyerror!void {
    if (data.len == 0) return;
    var r = Reader.init(data);
    if (r.rem() >= 4 and r.buf[r.pos] == TOK_FRAGMENT_HEADER) {
        _ = try r.readU8();
        _ = try r.readU8();
        _ = try r.readU8();
        _ = try r.readU8();
    }
    while (r.rem() > 0) {
        const pk = r.buf[r.pos];
        if (isToken(pk, TOK_OPEN_START)) {
            const child = try parseElementIR(chunk, &r, alloc, .def);
            try parent.children.append(.{ .tag = .Element, .elem = child });
        } else if (pk == TOK_TEMPLATE_INSTANCE) {
            _ = try r.readU8();
            if (r.rem() < 1 + 4 + 4 + 4 + 16 + 4) break;
            _ = try r.readU8(); // unknown
            _ = try r.readU32le(); // template id
            const def_data_off = try r.readU32le();
            _ = try r.readU32le(); // next def off
            if (r.rem() < 16) break;
            _ = try r.readGuid(); // GUID
            const def_size = try r.readU32le();
            const def_off_usize: usize = @intCast(def_data_off);
            if (def_off_usize + 24 > chunk.len) break;
            const td_data_size = std.mem.readInt(u32, chunk[def_off_usize + 20 .. def_off_usize + 24][0..4], .little);
            const data_start = def_off_usize + 24;
            const data_end = data_start + @as(usize, td_data_size);
            if (data_end > chunk.len or data_start >= chunk.len) break;
            var def_r = Reader.init(chunk[data_start..data_end]);
            if (def_r.rem() >= 4 and def_r.buf[def_r.pos] == TOK_FRAGMENT_HEADER) {
                _ = try def_r.readU8();
                _ = try def_r.readU8();
                _ = try def_r.readU8();
                _ = try def_r.readU8();
            }
            if (r.rem() >= def_size and (r.buf[r.pos] == TOK_FRAGMENT_HEADER or r.buf[r.pos] == TOK_OPEN_START)) {
                r.pos += @as(usize, def_size);
            }
            // Parse values that follow the template header
            const vals = try parseTemplateInstanceValues(&r, alloc);
            // Parse definition into IR and attach local_values
            const child = try parseElementIR(chunk, &def_r, alloc, .def);
            child.local_values = vals;
            try parent.children.append(.{ .tag = .Element, .elem = child });
        } else break;
    }
}

// (removed) markReferencedEvtXmlSubs*/markEmbedded* helpers; we detect needs inline at the call site

fn renderElementIRXml(chunk: []const u8, el: *const IR.Element, values: []const TemplateValue, w: anytype, indent: usize) anyerror!void {
    // If this element has local template values, prefer them for its subtree
    const eff_values: []const TemplateValue = if (el.local_values.len > 0) el.local_values else values;
    // indent
    var i: usize = 0;
    while (i < indent) : (i += 1) try w.writeByte(' ');
    try w.writeByte('<');
    try writeNameXml(chunk, el.name, w);
    // attributes
    var ai: usize = 0;
    while (ai < el.attrs.items.len) : (ai += 1) {
        const a = el.attrs.items[ai];
        try w.writeByte(' ');
        try writeNameXml(chunk, a.name, w);
        try w.writeAll("=\"");
        if (attrNameIsSystemTime(a.name, chunk)) {
            var tmp: [512]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&tmp);
            try renderAttrValueFromIR(chunk, a.value.items, eff_values, fbs.writer());
            const s = fbs.getWritten();
            // normalize
            try normalizeAndWriteSystemTimeAscii(w, s);
        } else {
            try renderAttrValueFromIR(chunk, a.value.items, eff_values, w);
        }
        try w.writeByte('"');
    }
    if (el.children.items.len == 0) {
        // Expanded empty form
        try w.writeByte('>');
        try w.writeAll("</");
        try writeNameXml(chunk, el.name, w);
        try w.writeByte('>');
        try w.writeByte('\n');
        return;
    }
    // Use precomputed hints instead of scanning
    const has_elem_child = el.has_element_child;
    const has_evtxml_subst = el.has_evtxml_subst_in_tree;
    const has_evtxml_value = el.has_evtxml_value_in_tree;
    if (!has_elem_child and !has_evtxml_subst and !has_evtxml_value) {
        // Inline textual content
        try w.writeByte('>');
        try renderTextContentFromIR(chunk, el.children.items, eff_values, w);
        try w.writeAll("</");
        try writeNameXml(chunk, el.name, w);
        try w.writeByte('>');
        try w.writeByte('\n');
        return;
    }
    // Block form for element children and evtxml substitutions
    try w.writeByte('>');
    try w.writeByte('\n');
    // Splice any nested EvtXml payloads that appeared inside attribute value token streams
    if (el.has_attr_evtxml_value) {
        var ai_pre: usize = 0;
        while (ai_pre < el.attrs.items.len) : (ai_pre += 1) {
            const a = el.attrs.items[ai_pre];
            var vi_pre: usize = 0;
            while (vi_pre < a.value.items.len) : (vi_pre += 1) {
                const ndv = a.value.items[vi_pre];
                if (ndv.tag == .Value and (ndv.vtype & 0x7f) == 0x21 and ndv.vbytes.len > 0) {
                    try appendEvtXmlPayloadChildrenIR(chunk, ndv.vbytes, std.heap.page_allocator, @constCast(el));
                }
            }
        }
    }
    // First render textual tokens (if any) as indented separate line(s)
    var idx: usize = 0;
    while (idx < el.children.items.len) : (idx += 1) {
        const nd = el.children.items[idx];
        switch (nd.tag) {
            .Element => try renderElementIRXml(chunk, nd.elem.?, eff_values, w, indent + 2),
            .Subst => {
                if (nd.subst_id < values.len) {
                    const vv = eff_values[nd.subst_id];
                    if ((vv.t & 0x7f) == 0x21 and vv.data.len > 0) {
                        // Render nested payload as children: append IR children and then render
                        try appendEvtXmlPayloadChildrenIR(chunk, vv.data, std.heap.page_allocator, @constCast(el));
                        // Already appended as proper children, nothing to print here
                        continue;
                    }
                }
                // Treat other substitutions as text lines
                var k: usize = 0;
                while (k < indent + 2) : (k += 1) try w.writeByte(' ');
                try renderTextContentFromIR(chunk, &[_]IR.Node{nd}, eff_values, w);
                try w.writeByte('\n');
            },
            .Value => {
                if ((nd.vtype & 0x7f) == 0x21 and nd.vbytes.len > 0) {
                    // Append nested payload as proper element children
                    try appendEvtXmlPayloadChildrenIR(chunk, nd.vbytes, std.heap.page_allocator, @constCast(el));
                    continue;
                }
                var k: usize = 0;
                while (k < indent + 2) : (k += 1) try w.writeByte(' ');
                try renderTextContentFromIR(chunk, &[_]IR.Node{nd}, eff_values, w);
                try w.writeByte('\n');
            },
            .Text, .Pad, .CharRef, .EntityRef, .CData => {
                var k: usize = 0;
                while (k < indent + 2) : (k += 1) try w.writeByte(' ');
                try renderTextContentFromIR(chunk, &[_]IR.Node{nd}, eff_values, w);
                try w.writeByte('\n');
            },
        }
    }
    // close tag
    i = 0;
    while (i < indent) : (i += 1) try w.writeByte(' ');
    try w.writeAll("</");
    try writeNameXml(chunk, el.name, w);
    try w.writeByte('>');
    try w.writeByte('\n');
}
