const std = @import("std");
const logger = @import("../logger.zig");
const log = logger.scoped("binxml");
const util = @import("util.zig");
const writeXmlEscaped = util.writeXmlEscaped;
const writeUtf16LeXmlEscaped = util.writeUtf16LeXmlEscaped;
const writeUtf16LeRawToUtf8 = util.writeUtf16LeRawToUtf8;
const utf16EqualsAscii = util.utf16EqualsAscii;
const normalizeAndWriteSystemTimeAscii = util.normalizeAndWriteSystemTimeAscii;
const writePaddedInt = util.writePaddedInt;
const formatIso8601UtcFromUnixMs = util.formatIso8601UtcFromUnixMs;
const formatIso8601UtcFromFiletimeMicros = util.formatIso8601UtcFromFiletimeMicros;
const writeAnsiCp1252Escaped = util.writeAnsiCp1252Escaped;

// EVTX Binary XML parsing and rendering.
//
// Substitution scoping and template expansion (important design notes):
// - Each TemplateInstance (token 0x0C) contains its own substitution descriptor table and data area.
// - Template definitions referenced by offset contain SubstitutionDescriptor tokens which index into
//   the substitution array of the TemplateInstance that is currently being expanded.
// - Templates can be nested (including inside EvtXml/BinXml payloads, token 0x21). Each nested
//   TemplateInstance introduces a new substitution scope. Substitution resolution must always use
//   the substitution array associated with the TemplateInstance that owns the definition being
//   expanded; parent scopes must not leak.
//
// Implementation strategy:
// - We parse a template definition into an IR element tree (see IR types below).
// - Before rendering, we expand substitutions in the IR using the correct scope via
//   `expandElementWithValues`. This function clones the element and replaces `.Subst` nodes with
//   concrete `.Text`/`.Value` nodes. For nested elements that carry their own `local_values`
//   (i.e., child TemplateInstances), we recurse with those values, ensuring proper scoping.
// - Arrays are expanded deterministically into multiple nodes. In text contexts, string arrays are
//   joined with commas; in attribute contexts, items are separated by spaces (see `joinerFor`).
// - String substitutions are sized UTF-16 (no length prefix); NullType still consumes the declared
//   size bytes in the data area but resolves to no content.
// - This expansion removes the need for late substitution resolution during render and eliminates
//   any heuristics that attempt to “search” for child blocks after the root.
//
// Other correctness details:
// - The TemplateInstance descriptor’s third byte is reserved and must be consumed.
// - Inline cached template definition blocks (header + fragment) are skipped deterministically
//   based on their `data_size` and a fragment header check.
// - Empty BinaryType values render as `<Binary></Binary>` to match `evtx_dump` output.

// Gate non-spec "+" integer padding sentinel behind build flag
const ENABLE_PLUS_PAD: bool = false;

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
const TOK_PITARGET: u8 = 0x0a;
const TOK_PIDATA: u8 = 0x0b;

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
    // Defensive: trim a trailing NUL if manifests encoded EOS in num_chars
    var num = num_chars;
    if (byte_len >= 2) {
        const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
        if (last == 0 and num > 0) num -= 1;
    }
    try writeUtf16LeXmlEscaped(w, chunk[str_start .. str_start + num * 2], num);
}

fn readFixedBytes(r: *Reader, n: usize) ![]const u8 {
    if (r.rem() < n) return BinXmlError.UnexpectedEof;
    const slice = r.buf[r.pos .. r.pos + n];
    r.pos += n;
    return slice;
}

fn readFixedBytesBounded(r: *Reader, n: usize, end_pos: usize) ![]const u8 {
    if (r.pos + n > end_pos) return BinXmlError.UnexpectedEof;
    return try readFixedBytes(r, n);
}

fn valueTypeFixedSize(vtype: u8) ?usize {
    return switch (vtype) {
        0x03, // Int8
        0x04, // UInt8
        => 1,
        0x05, // Int16
        0x06, // UInt16
        => 2,
        0x07, // Int32
        0x08, // UInt32
        0x0d, // Bool (DWORD)
        0x14,
        => 4, // HexInt32
        0x09, // Int64
        0x0a, // UInt64
        0x0b, // Real32
        0x0c, // Real64
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

fn readUnicodeTextStringBounded(r: *Reader, end_pos: usize) ![]const u8 {
    if (r.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
    const num_chars = try r.readU16le();
    const byte_len = @as(usize, num_chars) * 2;
    if (r.pos + byte_len > end_pos) return BinXmlError.UnexpectedEof;
    const slice = r.buf[r.pos .. r.pos + byte_len];
    r.pos += byte_len;
    return slice;
}

fn readLenPrefixedBytes16Bounded(r: *Reader, end_pos: usize) ![]const u8 {
    if (r.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
    const blen = try r.readU16le();
    if (r.pos + @as(usize, blen) > end_pos) return BinXmlError.UnexpectedEof;
    const slice = r.buf[r.pos .. r.pos + blen];
    r.pos += blen;
    return slice;
}

fn readSidBytesBounded(r: *Reader, end_pos: usize) ![]const u8 {
    if (r.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
    const start = r.pos;
    const subc = r.buf[r.pos + 1];
    const needed: usize = 8 + @as(usize, subc) * 4;
    if (start + needed > end_pos) return BinXmlError.UnexpectedEof;
    const slice = r.buf[start .. start + needed];
    r.pos = start + needed;
    return slice;
}

const Source = enum { rec, def };

fn writeNameFromUtf16(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    try writeUtf16LeXmlEscaped(w, utf16le, num_chars);
}

fn logNameTrace(chunk: []const u8, name: IR.Name, label: []const u8) !void {
    if (!log.enabled(.trace)) return;
    var tmp: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&tmp);
    const w = fbs.writer();
    try w.writeAll("[");
    try w.writeAll(label);
    try w.writeAll("] ");
    switch (name) {
        .NameOffset => |off| try writeNameFromOffset(chunk, off, w),
        .InlineUtf16 => |inl| try writeNameFromUtf16(w, inl.bytes, inl.num_chars),
    }
    log.trace("{s}", .{fbs.getWritten()});
}

fn isNameSystemTimeFromOffset(chunk: []const u8, name_offset: u32) bool {
    const off = @as(usize, name_offset);
    if (off + 8 > chunk.len) return false;
    const num_chars = std.mem.readInt(u16, chunk[off + 6 .. off + 8][0..2], .little);
    const str_start = off + 8;
    const byte_len = @as(usize, num_chars) * 2;
    if (str_start + byte_len > chunk.len) return false;
    return utf16EqualsAscii(chunk[str_start .. str_start + byte_len], num_chars, "SystemTime");
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
    // Deterministic variants accepted by Windows manifests. Try explicit, then simpler ones.
    // Variant C: u32 unknown + u32 zero/unknown + u16 hash + u16 num + UTF16 (+ optional EOS)
    if (r.rem() >= 12) {
        const saveC = r.pos;
        _ = try r.readU32le();
        _ = try r.readU32le();
        _ = try r.readU16le(); // hash
        const numC = try r.readU16le();
        const bytesC = @as(usize, numC) * 2;
        if (numC > 0 and r.rem() >= bytesC and r.pos + bytesC <= r.buf.len) {
            const sliceC = r.buf[r.pos .. r.pos + bytesC];
            r.pos += bytesC;
            if (r.rem() >= 2) {
                const eos = std.mem.readInt(u16, r.buf[r.pos .. r.pos + 2][0..2], .little);
                if (eos == 0) r.pos += 2;
            }
            return .{ .utf16 = sliceC, .num_chars = numC };
        }
        r.pos = saveC;
    }
    // Variant A: u16 hash + u16 num + UTF16
    if (r.rem() >= 4) {
        const saveA = r.pos;
        _ = try r.readU16le(); // hash
        const numA = try r.readU16le();
        const bytesA = @as(usize, numA) * 2;
        if (numA > 0 and r.rem() >= bytesA and r.pos + bytesA <= r.buf.len) {
            const sliceA = r.buf[r.pos .. r.pos + bytesA];
            r.pos += bytesA;
            return .{ .utf16 = sliceA, .num_chars = numA };
        }
        r.pos = saveA;
    }
    // Variant B: u16 num + UTF16
    if (r.rem() >= 2) {
        const saveB = r.pos;
        const numB = try r.readU16le();
        const bytesB = @as(usize, numB) * 2;
        if (numB > 0 and r.rem() >= bytesB and r.pos + bytesB <= r.buf.len) {
            const sliceB = r.buf[r.pos .. r.pos + bytesB];
            r.pos += bytesB;
            return .{ .utf16 = sliceB, .num_chars = numB };
        }
        r.pos = saveB;
    }
    // No additional fallback variants per important.mdc
    return BinXmlError.UnexpectedEof;
}

// (removed) legacy streaming attribute writer `writeAttributeListXml`

// Move TemplateValue up so IR can reference it
const TemplateValue = struct {
    t: u8,
    data: []const u8,
};

fn maxSubstIndexNodes(nodes: []const IR.Node) ?usize {
    var max: ?usize = null;
    var i: usize = 0;
    while (i < nodes.len) : (i += 1) {
        const nd = nodes[i];
        if (nd.tag == .Subst) {
            if (max) |m| {
                if (@as(usize, nd.subst_id) > m) max = nd.subst_id;
            } else max = nd.subst_id;
        } else if (nd.tag == .Element) {
            if (nd.elem) |child| {
                // attributes of child
                var ai: usize = 0;
                while (ai < child.attrs.items.len) : (ai += 1) {
                    if (maxSubstIndexNodes(child.attrs.items[ai].value.items)) |v| {
                        if (max) |m2| {
                            if (v > m2) max = v;
                        } else max = v;
                    }
                }
                if (maxSubstIndexNodes(child.children.items)) |v2| {
                    if (max) |m3| {
                        if (v2 > m3) max = v2;
                    } else max = v2;
                }
            }
        }
    }
    return max;
}

fn expectedValuesFromTemplate(el: *const IR.Element) usize {
    var max: ?usize = null;
    // attributes
    var ai: usize = 0;
    while (ai < el.attrs.items.len) : (ai += 1) {
        if (maxSubstIndexNodes(el.attrs.items[ai].value.items)) |v| {
            if (max) |m| {
                if (v > m) max = v;
            } else max = v;
        }
    }
    // children
    if (maxSubstIndexNodes(el.children.items)) |v2| {
        if (max) |m2| {
            if (v2 > m2) max = v2;
        } else max = v2;
    }
    return if (max) |mfinal| mfinal + 1 else 0;
}

fn parseTemplateInstanceValues(r: *Reader, allocator: std.mem.Allocator) ![]TemplateValue {
    // Spec-compliant: MUST start with u32 number_of_substitutions
    if (r.rem() < 4) return BinXmlError.UnexpectedEof;
    const declared_u32 = try r.readU32le();
    const declared: usize = @intCast(declared_u32);
    if (log.enabled(.trace)) log.trace("tmpl values declared={d}", .{declared});
    if (declared == 0) return allocator.alloc(TemplateValue, 0);
    if (r.rem() < 4 * declared) return BinXmlError.UnexpectedEof;
    // Read descriptor table
    var sizes = try allocator.alloc(u16, declared);
    errdefer allocator.free(sizes);
    var types = try allocator.alloc(u8, declared);
    errdefer allocator.free(types);
    var reserved = try allocator.alloc(u8, declared);
    errdefer allocator.free(reserved);
    var i: usize = 0;
    while (i < declared) : (i += 1) {
        sizes[i] = try r.readU16le();
        types[i] = try r.readU8();
        reserved[i] = try r.readU8();
        if (log.enabled(.trace)) log.trace("  desc[{d}]: size={d} type=0x{x} reserved={d}", .{ i, sizes[i], types[i], reserved[i] });
    }
    // Payloads
    var values = try allocator.alloc(TemplateValue, declared);
    i = 0;
    while (i < declared) : (i += 1) {
        const need: usize = @intCast(sizes[i]);
        if (r.rem() < need) return BinXmlError.UnexpectedEof;
        const slice = r.buf[r.pos .. r.pos + need];
        r.pos += need;
        if (types[i] == 0x00) {
            // NullType: keep an empty value; data bytes are skipped by size
            values[i] = .{ .t = 0x00, .data = &[_]u8{} };
        } else {
            values[i] = .{ .t = types[i], .data = slice };
        }
        if (log.enabled(.trace)) log.trace("  payload[{d}]: t=0x{x} len={d}", .{ i, types[i], need });
    }
    allocator.free(sizes);
    allocator.free(types);
    allocator.free(reserved);
    return values;
}

fn parseTemplateInstanceValuesExpected(r: *Reader, allocator: std.mem.Allocator, expected: usize) ![]TemplateValue {
    if (r.rem() < 4) return BinXmlError.UnexpectedEof;
    const declared_u32 = try r.readU32le();
    const declared: usize = @intCast(declared_u32);
    _ = expected; // trust declared count per spec (Rust behavior)
    if (log.enabled(.trace)) log.trace("tmpl values declared={d}", .{declared});
    if (declared == 0) return allocator.alloc(TemplateValue, 0);
    if (r.rem() < 4 * declared) return BinXmlError.UnexpectedEof;
    // Read descriptor table
    var sizes = try allocator.alloc(u16, declared);
    errdefer allocator.free(sizes);
    var types = try allocator.alloc(u8, declared);
    errdefer allocator.free(types);
    var reserved = try allocator.alloc(u8, declared);
    errdefer allocator.free(reserved);
    var i: usize = 0;
    while (i < declared) : (i += 1) {
        sizes[i] = try r.readU16le();
        types[i] = try r.readU8();
        reserved[i] = try r.readU8();
        if (log.enabled(.trace)) log.trace("  desc[{d}]: size={d} type=0x{x} reserved={d}", .{ i, sizes[i], types[i], reserved[i] });
    }
    // Payloads
    var values = try allocator.alloc(TemplateValue, declared);
    i = 0;
    while (i < declared) : (i += 1) {
        const need: usize = @intCast(sizes[i]);
        if (r.rem() < need) return BinXmlError.UnexpectedEof;
        const slice = r.buf[r.pos .. r.pos + need];
        r.pos += need;
        if (types[i] == 0x00) {
            values[i] = .{ .t = 0x00, .data = &[_]u8{} };
        } else {
            values[i] = .{ .t = types[i], .data = slice };
        }
        if (log.enabled(.trace)) log.trace("  payload[{d}]: t=0x{x} len={d}", .{ i, types[i], need });
    }
    allocator.free(sizes);
    allocator.free(types);
    allocator.free(reserved);
    return values;
}

fn writeValueXml(w: anytype, t: u8, data: []const u8) !void {
    switch (t) {
        0x03 => { // Int8
            if (data.len < 1) return;
            const v: i8 = @bitCast(data[0]);
            try w.print("{d}", .{v});
        },
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
        0x01 => { // StringType
            // In template substitutions the payload is sized UTF-16 bytes without a length prefix.
            // In value tokens inside definitions we never reach here (they become Text nodes).
            if (data.len == 0) return; // empty string
            if ((data.len & 1) != 0) return BinXmlError.UnexpectedEof; // must be UTF-16LE bytes
            var num = data.len / 2;
            if (num > 0) {
                const last = std.mem.readInt(u16, data[data.len - 2 .. data.len][0..2], .little);
                if (last == 0) num -= 1;
            }
            if (num == 0) return;
            try writeUtf16LeXmlEscaped(w, data[0 .. num * 2], num);
        },
        0x02 => { // AnsiStringType (codepage) - payload is exactly the descriptor-sized byte slice
            try writeAnsiCp1252Escaped(w, data);
        },
        0x0b => { // Real32Type
            if (data.len < 4) return;
            const bits = std.mem.readInt(u32, data[0..4], .little);
            const f: f32 = @bitCast(bits);
            if (std.math.isNan(f)) return try w.writeAll("-1.#IND");
            if (std.math.isInf(f)) return try w.writeAll(if (f > 0) "1.#INF" else "-1.#INF");
            // Format with 6 fractional digits when needed
            try w.print("{d}", .{f});
        },
        0x0c => { // Real64Type
            if (data.len < 8) return;
            const bits = std.mem.readInt(u64, data[0..8], .little);
            const f: f64 = @bitCast(bits);
            if (std.math.isNan(f)) return try w.writeAll("-1.#IND");
            if (std.math.isInf(f)) return try w.writeAll(if (f > 0) "1.#INF" else "-1.#INF");
            try w.print("{d}", .{f});
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
            if (data.len == 0) {
                // Represent empty binary as empty element content; caller will produce <Binary></Binary>
                return;
            }
            var i: usize = 0;
            while (i < data.len) : (i += 1) {
                try w.print("{x:0>2}", .{data[i]});
            }
        },
        0x10 => { // SizeTType — represent as hex (size depends on platform; we cannot know, prefer 32-bit if length==4 else 64)
            if (data.len >= 8) {
                const v = std.mem.readInt(u64, data[0..8], .little);
                try w.print("0x{X}", .{v});
            } else if (data.len >= 4) {
                const v = std.mem.readInt(u32, data[0..4], .little);
                try w.print("0x{X}", .{v});
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
        0x20 => { // EvtHandle – render as integer value length-based
            if (data.len >= 8) {
                const v = std.mem.readInt(u64, data[0..8], .little);
                try w.print("{d}", .{v});
            } else if (data.len >= 4) {
                const v = std.mem.readInt(u32, data[0..4], .little);
                try w.print("{d}", .{v});
            }
        },
        0x23 => { // EvtXml (opaque) – provide a sane fallback as hex string
            var i: usize = 0;
            while (i < data.len) : (i += 1) {
                try w.print("{x:0>2}", .{data[i]});
            }
        },
        // 0x21 => EvtXml (nested binary XML) is not handled here to avoid re-entrant parsing in value writer
        else => {
            // TODO: implement other types; for now, no-op for unsupported
        },
    }
}

const JoinerPolicy = enum { Attr, Text };

fn joinerFor(policy: JoinerPolicy, base: u8) []const u8 {
    return switch (policy) {
        .Attr => " ",
        .Text => if (base == 0x01 or base == 0x02) "," else " ",
    };
}

fn writeSingleWithPad(w: anytype, t: u8, bytes: []const u8, pad: usize) !void {
    if (pad > 0 and (t == 0x07 or t == 0x08 or t == 0x09 or t == 0x0a)) {
        switch (t) {
            0x07 => try writePaddedInt(w, i32, std.mem.readInt(i32, bytes[0..4], .little), pad),
            0x08 => try writePaddedInt(w, u32, std.mem.readInt(u32, bytes[0..4], .little), pad),
            0x09 => try writePaddedInt(w, i64, std.mem.readInt(i64, bytes[0..8], .little), pad),
            0x0a => try writePaddedInt(w, u64, std.mem.readInt(u64, bytes[0..8], .little), pad),
            else => try writeValueXml(w, t, bytes),
        }
    } else {
        try writeValueXml(w, t, bytes);
    }
}

fn arrayItemNext(base: u8, backing_t: u8, data: []const u8, idx: *usize) ?[]const u8 {
    switch (base) {
        0x01 => { // Unicode string, NUL-terminated items
            const i = idx.*;
            if (i >= data.len) return null;
            if (data.len - i < 2) {
                idx.* = data.len;
                return null;
            }
            const start = i;
            var end = i;
            while (end + 1 < data.len) : (end += 2) {
                const u = std.mem.readInt(u16, data[end .. end + 2][0..2], .little);
                if (u == 0) break;
            }
            // Advance idx beyond terminator if present
            const new_idx = if (end + 1 < data.len) end + 2 else end;
            if (new_idx <= i) {
                idx.* = data.len;
                return null;
            }
            idx.* = new_idx;
            return data[start..end];
        },
        0x02 => { // ANSI string, NUL-terminated items
            const i = idx.*;
            if (i >= data.len) return null;
            const start = i;
            var end = i;
            while (end < data.len and data[end] != 0) : (end += 1) {}
            const new_idx = if (end < data.len and data[end] == 0) end + 1 else end;
            if (new_idx <= i) {
                idx.* = data.len;
                return null;
            }
            idx.* = new_idx;
            return data[start..end];
        },
        0x13 => { // SID: 8 + subcount*4
            const i = idx.*;
            if (i + 8 > data.len) return null;
            const subc: usize = data[i + 1];
            const need: usize = 8 + subc * 4;
            if (i + need > data.len) return null;
            idx.* = i + need;
            return data[i .. i + need];
        },
        0x10 => { // size_t: enforce 0x94/0x95 backing
            var esz: usize = 0;
            if (backing_t == 0x94) esz = 4 else if (backing_t == 0x95) esz = 8 else return null;
            const i = idx.*;
            if (i + esz > data.len) return null;
            const out = data[i .. i + esz];
            idx.* = i + esz;
            return out;
        },
        else => {
            if (valueTypeFixedSize(base)) |esz| {
                const i = idx.*;
                if (i + esz > data.len) return null;
                const out = data[i .. i + esz];
                idx.* = i + esz;
                return out;
            }
            return null;
        },
    }
}

// writeArrayItemsJoined and writeSubstAsText are no longer needed after IR expansion

// (removed) legacy streaming substitution renderer `renderSubstitutionXml`

// (removed) legacy streaming element renderer `renderElementXml`

fn renderXmlWithContext(ctx: *Context, chunk: []const u8, bin: []const u8, w: anytype) anyerror!void {
    // Honor per-record verbosity by bumping module level to trace for this call
    if (ctx.verbose) logger.setModuleLevel("binxml", .trace);
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
    log.debug("first=0x{x} len={d}", .{ first, bin.len });
    if (first == TOK_TEMPLATE_INSTANCE) {
        _ = try r.readU8(); // consume 0x0c
        if (r.rem() < 1 + 4 + 4) return BinXmlError.UnexpectedEof;
        _ = try r.readU8(); // unknown (matches Rust reader)
        _ = try r.readU32le(); // template id (unused)
        const def_data_off = try r.readU32le();
        log.debug("tmpl def_off=0x{x} def_size={d}", .{ def_data_off, 0 });

        // Per Rust: template header: next_template_offset (4), guid (16), data_size (4), then payload of size data_size
        const def_off_usize: usize = @intCast(def_data_off);
        if (def_off_usize + 24 > chunk.len) return BinXmlError.OutOfBounds;
        const td_data_size = std.mem.readInt(u32, chunk[def_off_usize + 20 .. def_off_usize + 24][0..4], .little);
        const data_start = def_off_usize + 24;
        const data_end = data_start + @as(usize, td_data_size);
        if (data_end > chunk.len or data_start >= chunk.len) return BinXmlError.OutOfBounds;
        log.trace("using chunk def data at 0x{x}..0x{x}", .{ data_start, data_end });
        var def_r = Reader.init(chunk[data_start..data_end]);
        if (ctx.verbose and def_r.rem() >= 8) {
            log.trace("def_r first8: {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}", .{
                def_r.buf[0], def_r.buf[1], def_r.buf[2], def_r.buf[3], def_r.buf[4], def_r.buf[5], def_r.buf[6], def_r.buf[7],
            });
        }
        // Optional fragment header inside definition (chunk copy)
        if (def_r.rem() >= 4 and def_r.buf[def_r.pos] == TOK_FRAGMENT_HEADER) {
            _ = try def_r.readU8();
            _ = try def_r.readU8();
            _ = try def_r.readU8();
            _ = try def_r.readU8();
        }

        // Skip inline copy when def_data_off equals current record-relative cursor position
        // Match Rust: compare against cursor.position() within the record buffer
        // If the template definition header is inlined at the current record cursor, skip it deterministically
        if (def_data_off == @as(u32, @intCast(r.pos))) {
            if (r.rem() < 24) return BinXmlError.UnexpectedEof;
            _ = try r.readU32le(); // next_template_offset
            _ = try r.readGuid();
            const data_size_inline = try r.readU32le();
            if (r.rem() < data_size_inline) return BinXmlError.UnexpectedEof;
            r.pos += @as(usize, data_size_inline);
        }

        // Some records embed additional cached template definition blocks before the substitution array.
        // These blocks have a fixed 24-byte header followed by a fragment of size `data_size` beginning with 0x0f.
        // Skip any such blocks deterministically before reading substitutions.
        while (r.rem() >= 28) {
            const data_size_peek = std.mem.readInt(u32, r.buf[r.pos + 20 .. r.pos + 24][0..4], .little);
            const block_end = r.pos + 24 + @as(usize, data_size_peek);
            if (block_end > r.buf.len) break;
            const payload_first = r.buf[r.pos + 24];
            if (payload_first != TOK_FRAGMENT_HEADER) break;
            if (ctx.verbose) log.trace("skipping inline cached template def: size={d} at 0x{x}..0x{x}", .{ data_size_peek, r.pos, block_end });
            r.pos = block_end;
        }

        // Parse the template definition IR (using chunk copy) before values so we can compute expected substitutions
        const parsed_def = parseElementIR(chunk, &def_r, ctx.arena.allocator(), .def) catch |e| {
            log.err("parse def IR failed: {s}", .{@errorName(e)});
            return e;
        };
        // With the template parsed, compute expected substitution count and parse values accordingly
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const alloc = gpa.allocator();
        const expected = expectedValuesFromTemplate(parsed_def);
        log.trace("values start at rec+0x{x}; rem={d} expected={d}", .{ r.pos, r.rem(), expected });
        if (ctx.verbose and r.rem() >= 8) {
            log.trace("values first8: {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}", .{
                r.buf[r.pos + 0], r.buf[r.pos + 1], r.buf[r.pos + 2], r.buf[r.pos + 3],
                r.buf[r.pos + 4], r.buf[r.pos + 5], r.buf[r.pos + 6], r.buf[r.pos + 7],
            });
        }
        const values = parseTemplateInstanceValuesExpected(&r, alloc, expected) catch |e| {
            log.err("parse values (expected) failed: {s} rem={d}", .{ @errorName(e), r.rem() });
            return e;
        };
        if (ctx.verbose) log.trace("parsed {d} values; rec_pos=0x{x} rem={d}", .{ values.len, r.pos, r.rem() });
        // Copy value descriptors into context arena to ensure stable lifetime in Release builds
        const vals_copy = try ctx.arena.allocator().alloc(TemplateValue, values.len);
        var vi: usize = 0;
        while (vi < values.len) : (vi += 1) vals_copy[vi] = values[vi];
        defer alloc.free(values);
        // Fetch GUID from the chunk template header for cache keying
        var guid: [16]u8 = undefined;
        std.mem.copyForwards(u8, guid[0..], chunk[def_off_usize + 4 .. def_off_usize + 20]);
        const key: Context.DefKey = .{ .def_data_off = def_data_off, .guid = guid };
        const got = try ctx.cache.getOrPut(key);
        if (!got.found_existing) {
            got.value_ptr.* = parsed_def;
            if (ctx.verbose) {
                try logNameTrace(chunk, got.value_ptr.*.name, "tmpl root");
            }
        }
        // Expand substitutions into the IR using the correct scope
        const expanded = try expandElementWithValues(got.value_ptr.*, vals_copy, ctx.arena.allocator());
        renderElementIRXml(chunk, expanded, &[_]TemplateValue{}, w, 0) catch |e| {
            log.err("render tmpl failed: {s}", .{@errorName(e)});
            return e;
        };
        return;
    } else {
        // Non-template path: IR parse and render for parity
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const alloc = gpa.allocator();
        const root = parseElementIR(chunk, &r, alloc, .rec) catch |e| {
            log.err("parse root IR failed: {s} first4=0x{x} 0x{x} 0x{x} 0x{x}", .{ @errorName(e), r.buf[0], r.buf[1], r.buf[2], r.buf[3] });
            return e;
        };
        if (ctx.verbose) {
            try logNameTrace(chunk, root.name, "root");
        }
        renderElementIRXml(chunk, root, &[_]TemplateValue{}, w, 0) catch |e| {
            log.err("render root failed: {s}", .{@errorName(e)});
            return e;
        };
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

    const NodeTag = enum { Element, Text, Value, Subst, CharRef, EntityRef, CData, Pad, PITarget, PIData };

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
        entity_name: Name = Name{ .NameOffset = 0 },
        pad_width: usize = 0,
        // PI
        pi_target: Name = Name{ .NameOffset = 0 },
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

fn utf16FromAscii(alloc: std.mem.Allocator, ascii: []const u8) ![]u8 {
    if (ascii.len == 0) return try alloc.alloc(u8, 0);
    var buf = try alloc.alloc(u8, ascii.len * 2);
    var i: usize = 0;
    while (i < ascii.len) : (i += 1) {
        buf[i * 2] = ascii[i];
        buf[i * 2 + 1] = 0;
    }
    return buf;
}

// Clone a node list while replacing `.Subst` nodes with concrete `.Text`/`.Value` nodes.
// The `policy` controls joining for string arrays in text vs attribute contexts.
fn cloneNodesReplacingSubstWithPolicy(policy: JoinerPolicy, alloc: std.mem.Allocator, nodes: []const IR.Node, values: []const TemplateValue) anyerror!std.ArrayList(IR.Node) {
    var out = std.ArrayList(IR.Node).init(alloc);
    var i: usize = 0;
    while (i < nodes.len) : (i += 1) {
        const nd = nodes[i];
        switch (nd.tag) {
            .Subst => {
                if (nd.subst_id >= values.len) continue;
                const vv = values[nd.subst_id];
                if (nd.subst_optional and (vv.t == 0x00 or vv.data.len == 0)) {
                    continue;
                }
                const is_arr = (nd.subst_vtype & 0x80) != 0;
                const base: u8 = nd.subst_vtype & 0x7f;
                if (is_arr) {
                    var idx: usize = 0;
                    var first = true;
                    const sep_ascii = joinerFor(policy, base);
                    while (arrayItemNext(base, vv.t, vv.data, &idx)) |seg| {
                        if (!first and sep_ascii.len > 0) {
                            const sep_utf16 = try utf16FromAscii(alloc, sep_ascii);
                            try out.append(.{ .tag = .Text, .text_utf16 = sep_utf16, .text_num_chars = sep_ascii.len });
                        }
                        first = false;
                        if (base == 0x01) {
                            try out.append(.{ .tag = .Text, .text_utf16 = seg, .text_num_chars = seg.len / 2 });
                        } else {
                            try out.append(.{ .tag = .Value, .vtype = base, .vbytes = seg });
                        }
                    }
                } else {
                    if (base == 0x01) {
                        // sized UTF-16 (possibly NUL-terminated)
                        var num = vv.data.len / 2;
                        if (num > 0 and std.mem.readInt(u16, vv.data[vv.data.len - 2 .. vv.data.len][0..2], .little) == 0) num -= 1;
                        try out.append(.{ .tag = .Text, .text_utf16 = vv.data[0 .. num * 2], .text_num_chars = num });
                    } else {
                        try out.append(.{ .tag = .Value, .vtype = vv.t, .vbytes = vv.data, .pad_width = nd.pad_width });
                    }
                }
            },
            .Element => {
                const child = nd.elem.?;
                const eff_vals: []const TemplateValue = if (child.local_values.len > 0) child.local_values else values;
                const repl = try expandElementWithValues(child, eff_vals, alloc);
                try out.append(.{ .tag = .Element, .elem = repl });
            },
            else => try out.append(nd),
        }
    }
    return out;
}

// Expand substitutions inside a template definition IR using a specific substitution array (scope).
//
// This is the only place where `.Subst` nodes are resolved. For nested TemplateInstances the
// child element will carry its own `local_values`; in that case we recurse with that array and do
// not use the parent `values`. This guarantees substitutions are evaluated in the correct scope.
fn expandElementWithValues(src: *const IR.Element, values: []const TemplateValue, alloc: std.mem.Allocator) anyerror!*IR.Element {
    const dst = try irNewElement(alloc, src.name);
    // attributes
    var ai: usize = 0;
    while (ai < src.attrs.items.len) : (ai += 1) {
        const a = src.attrs.items[ai];
        const expanded = try cloneNodesReplacingSubstWithPolicy(.Attr, alloc, a.value.items, values);
        try dst.attrs.append(.{ .name = a.name, .value = expanded });
    }
    // children
    const expanded_children = try cloneNodesReplacingSubstWithPolicy(.Text, alloc, src.children.items, values);
    var ci: usize = 0;
    while (ci < expanded_children.items.len) : (ci += 1) try dst.children.append(expanded_children.items[ci]);
    // flags (conservative)
    dst.has_element_child = src.has_element_child;
    dst.has_evtxml_value_in_tree = false;
    dst.has_evtxml_subst_in_tree = false;
    dst.has_attr_evtxml_value = false;
    dst.has_attr_evtxml_subst = false;
    return dst;
}
fn nameEqualsAscii(chunk: []const u8, name: IR.Name, ascii: []const u8) bool {
    switch (name) {
        .NameOffset => |off| {
            const o: usize = @intCast(off);
            if (o + 8 > chunk.len) return false;
            const num_chars = std.mem.readInt(u16, chunk[o + 6 .. o + 8][0..2], .little);
            const str_start = o + 8;
            const byte_len = @as(usize, num_chars) * 2;
            if (str_start + byte_len > chunk.len) return false;
            return utf16EqualsAscii(chunk[str_start .. str_start + byte_len], num_chars, ascii);
        },
        .InlineUtf16 => |inl| return utf16EqualsAscii(inl.bytes, inl.num_chars, ascii),
    }
}

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

fn parseAttributeListIR(chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source, max_end: usize) !std.ArrayList(IR.Attr) {
    const list_size = try r.readU32le();
    const list_start = r.pos;
    const list_end = list_start + list_size;
    if (list_end > max_end or list_end < list_start) return BinXmlError.UnexpectedEof;
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
        if (log.enabled(.trace)) {
            try logNameTrace(chunk, name, "attr");
        }
        // Collect attribute value tokens into IR
        var tokens = std.ArrayList(IR.Node).init(allocator);
        try collectValueTokensIRWithCtx(chunk, r, &tokens, src, list_end);
        try out.append(.{ .name = name, .value = tokens });
    }
    if (r.pos != list_end) r.pos = list_end;
    return out;
}

fn collectValueTokensIRWithCtx(_: []const u8, r: *Reader, out: *std.ArrayList(IR.Node), src: Source, end_pos: usize) !void {
    var want_pad2: bool = false;
    while (true) {
        if (r.rem() == 0 or r.pos >= end_pos) break;
        const pk = r.buf[r.pos];
        if (log.enabled(.trace)) log.trace("valtok pk=0x{x} at 0x{x}", .{ pk, r.pos });
        if (isToken(pk, TOK_ATTRIBUTE) or isToken(pk, TOK_CLOSE_START) or isToken(pk, TOK_CLOSE_EMPTY)) break;
        if (isToken(pk, TOK_VALUE)) {
            _ = try r.readU8();
            const vtype = try r.readU8();
            if (log.enabled(.trace)) log.trace("  vtype=0x{x}", .{vtype});
            if ((vtype & 0x7f) == 0x21) {
                if (r.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
                const blen = try r.readU16le();
                if (r.pos + @as(usize, blen) > end_pos) return BinXmlError.UnexpectedEof;
                // Store as Value node with vtype=0x21 and bytes payload; will be parsed and spliced at resolution/render time
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = r.buf[r.pos .. r.pos + blen] });
                r.pos += blen;
            } else if (vtype == 0x01) {
                const text = try readUnicodeTextStringBounded(r, end_pos);
                if (ENABLE_PLUS_PAD and text.len == 2 and text[0] == 0x2B and text[1] == 0x00) {
                    want_pad2 = true;
                    continue;
                }
                try out.append(.{ .tag = .Text, .text_utf16 = text, .text_num_chars = text.len / 2 });
            } else if (vtype == 0x02) {
                // Some manifests use ANSI string in value text; treat like 0x0e (len-prefixed) but decode as CP-1252 during rendering
                const payload = try readLenPrefixedBytes16Bounded(r, end_pos);
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = payload, .pad_width = if (want_pad2) 2 else 0 });
                want_pad2 = false;
            } else if (valueTypeFixedSize(vtype)) |sz| {
                const payload = try readFixedBytesBounded(r, sz, end_pos);
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = payload, .pad_width = if (want_pad2) 2 else 0 });
                want_pad2 = false;
            } else if (vtype == 0x0e) {
                const payload = try readLenPrefixedBytes16Bounded(r, end_pos);
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = payload, .pad_width = if (want_pad2) 2 else 0 });
                want_pad2 = false;
            } else if (vtype == 0x13) {
                const payload = try readSidBytesBounded(r, end_pos);
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = payload });
            } else {
                log.err("unknown value vtype=0x{x} at pos=0x{x} src={s}", .{ vtype, r.pos, switch (src) {
                    .rec => "rec",
                    .def => "def",
                } });
                return BinXmlError.BadToken;
            }
            continue;
        } else if (isToken(pk, TOK_NORMAL_SUBST) or isToken(pk, TOK_OPTIONAL_SUBST)) {
            const optional = isToken(pk, TOK_OPTIONAL_SUBST);
            _ = try r.readU8();
            if (r.pos + 2 + 1 > end_pos) return BinXmlError.UnexpectedEof;
            const id = try r.readU16le();
            const vtype = try r.readU8();
            try out.append(.{ .tag = .Subst, .subst_id = id, .subst_vtype = vtype, .subst_optional = optional, .pad_width = if (want_pad2) 2 else 0 });
            want_pad2 = false;
            continue;
        } else if (isToken(pk, TOK_CHARREF)) {
            _ = try r.readU8();
            if (r.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
            const v = try r.readU16le();
            try out.append(.{ .tag = .CharRef, .charref_value = v });
            continue;
        } else if (isToken(pk, TOK_ENTITYREF)) {
            _ = try r.readU8();
            var nm: IR.Name = undefined;
            switch (src) {
                .rec => {
                    if (r.pos + 4 > end_pos) return BinXmlError.UnexpectedEof;
                    const ent_name_off = try r.readU32le();
                    nm = IR.Name{ .NameOffset = ent_name_off };
                },
                .def => {
                    nm = try parseInlineNameFlexibleIR(r);
                },
            }
            try out.append(.{ .tag = .EntityRef, .entity_name = nm });
            continue;
        } else if (isToken(pk, TOK_CDATA)) {
            _ = try r.readU8();
            const data = try readUnicodeTextStringBounded(r, end_pos);
            try out.append(.{ .tag = .CData, .text_utf16 = data, .text_num_chars = data.len / 2 });
            continue;
        } else if (isToken(pk, TOK_PITARGET)) {
            _ = try r.readU8();
            var nm: IR.Name = undefined;
            switch (src) {
                .rec => {
                    if (r.pos + 4 > end_pos) return BinXmlError.UnexpectedEof;
                    nm = IR.Name{ .NameOffset = try r.readU32le() };
                },
                .def => nm = try parseInlineNameFlexibleIR(r),
            }
            try out.append(.{ .tag = .PITarget, .pi_target = nm });
            continue;
        } else if (isToken(pk, TOK_PIDATA)) {
            _ = try r.readU8();
            const data = try readUnicodeTextStringBounded(r, end_pos);
            try out.append(.{ .tag = .PIData, .text_utf16 = data, .text_num_chars = data.len / 2 });
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
            .Subst => {
                const base = nd.subst_vtype & 0x7f;
                const is_arr = (nd.subst_vtype & 0x80) != 0;
                if (base == 0x21) {
                    el.has_evtxml_subst_in_tree = true;
                    if (include_attr) el.has_attr_evtxml_subst = true;
                }
                // If an array substitution appears only inside attributes, we will warn later at render time
                _ = is_arr;
            },
            else => {},
        }
    }
}

fn parseElementIR(chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source) !*IR.Element {
    const element_start = r.pos;
    if (log.enabled(.trace)) {
        var tmp: [24]u8 = undefined;
        const take = @min(r.rem(), tmp.len);
        @memcpy(tmp[0..take], r.buf[r.pos .. r.pos + take]);
        log.trace("parseElementIR src={s} pos=0x{x} first: {s}", .{ switch (src) {
            .rec => "rec",
            .def => "def",
        }, r.pos, std.fmt.fmtSliceHexLower(tmp[0..take]) });
    }
    const start = try r.readU8();
    if (!isToken(start, TOK_OPEN_START)) return BinXmlError.BadToken;
    var data_size: u32 = 0;
    var header_len: usize = 0;
    var name: IR.Name = undefined;
    switch (src) {
        .rec => {
            _ = try r.readU16le(); // dep_id required
            data_size = try r.readU32le();
            header_len = 1 + 2 + 4;
            name = IR.Name{ .NameOffset = try r.readU32le() };
        },
        .def => {
            // Attempt with dependency_identifier first; rollback if resulting window is invalid
            const save0 = r.pos;
            var parsed_with_dep = false;
            if (r.rem() >= 2 + 4) {
                const save1 = r.pos;
                if (r.readU16le()) |_| {
                    if (r.readU32le()) |dsz| {
                        if (parseInlineNameFlexibleIR(r)) |nm| {
                            const hdr_len_try: usize = 1 + 2 + 4;
                            const end_try = element_start + hdr_len_try + @as(usize, dsz);
                            if (end_try <= r.buf.len) {
                                data_size = dsz;
                                header_len = hdr_len_try;
                                name = nm;
                                parsed_with_dep = true;
                            } else {
                                r.pos = save1;
                            }
                        } else |_| {
                            r.pos = save1;
                        }
                    } else |_| {
                        r.pos = save1;
                    }
                } else |_| {
                    r.pos = save1;
                }
            }
            if (!parsed_with_dep) {
                r.pos = save0;
                data_size = try r.readU32le();
                header_len = 1 + 4;
                name = try parseInlineNameFlexibleIR(r);
            }
            if (log.enabled(.trace)) log.trace("def hdr: data_size={d} header_len={d} pos=0x{x}", .{ data_size, header_len, r.pos });
        },
    }
    const element_end = element_start + header_len + @as(usize, data_size);
    if (element_end > r.buf.len or element_end < element_start) return BinXmlError.UnexpectedEof;
    const el = try irNewElement(allocator, name);
    if (hasMore(start, TOK_OPEN_START)) {
        el.attrs = try parseAttributeListIR(chunk, r, allocator, src, element_end);
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
    if (log.enabled(.trace)) log.trace("parseElementIR nxt=0x{x} pos=0x{x} end=0x{x}", .{ nxt, r.pos, element_end });
    if (isToken(nxt, TOK_CLOSE_EMPTY)) {
        return el;
    }
    if (!isToken(nxt, TOK_CLOSE_START)) {
        log.err("expected CloseStart, got 0x{x} at 0x{x}", .{ nxt, r.pos - 1 });
        return BinXmlError.BadToken;
    }
    // content
    while (true) {
        if (r.pos >= element_end or r.rem() == 0) break;
        const t = r.buf[r.pos];
        if (log.enabled(.trace)) log.trace("content token 0x{x} at 0x{x}/0x{x}", .{ t, r.pos, element_end });
        if (isToken(t, TOK_END_ELEMENT)) {
            _ = try r.readU8();
            break;
        } else if (isToken(t, TOK_OPEN_START)) {
            // Optional dependency id handling for nested 0x21 payload elements (spec: dep-id may be omitted)
            const child = try parseElementIR(chunk, r, allocator, src);
            try el.children.append(.{ .tag = .Element, .elem = child });
            el.has_element_child = true;
        } else if (isToken(t, TOK_VALUE) or isToken(t, TOK_NORMAL_SUBST) or isToken(t, TOK_OPTIONAL_SUBST) or isToken(t, TOK_CDATA) or isToken(t, TOK_CHARREF) or isToken(t, TOK_ENTITYREF) or isToken(t, TOK_PITARGET) or isToken(t, TOK_PIDATA)) {
            var seq = std.ArrayList(IR.Node).init(allocator);
            try collectValueTokensIRWithCtx(chunk, r, &seq, src, element_end);
            if (r.pos > element_end) r.pos = element_end;
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

fn renderAttrValueFromIR(chunk: []const u8, nodes: []const IR.Node, _: []const TemplateValue, w: anytype) !void {
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
        .Subst => {}, // no Subst nodes remain post-expansion
        .CharRef => try aw.print("&#{d};", .{nd.charref_value}),
        .EntityRef => {
            try aw.writeByte('&');
            try writeNameXml(chunk, nd.entity_name, aw);
            try aw.writeByte(';');
        },
        .CData => try writeUtf16LeXmlEscaped(aw, nd.text_utf16, nd.text_num_chars),
        .PITarget => {
            try aw.writeAll("<?");
            try writeNameXml(chunk, nd.pi_target, aw);
        },
        .PIData => {
            try aw.writeByte(' ');
            try writeUtf16LeRawToUtf8(aw, nd.text_utf16, nd.text_num_chars);
            try aw.writeAll("?>");
        },
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

// hasNestedEvtXmlSubst obsolete after IR expansion

fn renderTextContentFromIR(chunk: []const u8, nodes: []const IR.Node, _: []const TemplateValue, w: anytype) !void {
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
            .Subst => {}, // no Subst nodes remain post-expansion
            .CharRef => try w.print("&#{d};", .{nd.charref_value}),
            .EntityRef => {
                try w.writeByte('&');
                try writeNameXml(chunk, nd.entity_name, w);
                try w.writeByte(';');
            },
            .CData => {
                try w.writeAll("<![CDATA[");
                try writeUtf16LeRawToUtf8(w, nd.text_utf16, nd.text_num_chars);
                try w.writeAll("]]>");
            },
            .PITarget => {
                try w.writeAll("<?");
                try writeNameXml(chunk, nd.pi_target, w);
            },
            .PIData => {
                try w.writeByte(' ');
                try writeUtf16LeRawToUtf8(w, nd.text_utf16, nd.text_num_chars);
                try w.writeAll("?>");
            },
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
            // Allow offset-based names inside payloads (treat like record context)
            const child = try parseElementIR(chunk, &r, alloc, .rec);
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
        if (pk == TOK_TEMPLATE_INSTANCE) {
            _ = try r.readU8();
            if (r.rem() < 1 + 4 + 4) break;
            _ = try r.readU8(); // unknown
            _ = try r.readU32le(); // template id
            const def_data_off = try r.readU32le();
            // Skip any inline cached template definition blocks deterministically
            while (r.rem() >= 28) {
                const data_size_inline = std.mem.readInt(u32, r.buf[r.pos + 20 .. r.pos + 24][0..4], .little);
                const block_end_inline = r.pos + 24 + @as(usize, data_size_inline);
                if (block_end_inline <= r.buf.len and r.buf[r.pos + 24] == TOK_FRAGMENT_HEADER) {
                    r.pos = block_end_inline;
                } else break;
            }
            // Use chunk-stored definition to parse expected substitutions
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
            const child_def = try parseElementIR(chunk, &def_r, alloc, .def);
            const expected = expectedValuesFromTemplate(child_def);
            const vals = try parseTemplateInstanceValuesExpected(&r, alloc, expected);
            const expanded_child = try expandElementWithValues(child_def, vals, alloc);
            try parent.children.append(.{ .tag = .Element, .elem = expanded_child });
        } else break;
    }
}

// (removed) markReferencedEvtXmlSubs*/markEmbedded* helpers; we detect needs inline at the call site

fn renderElementIRXml(chunk: []const u8, el: *const IR.Element, values: []const TemplateValue, w: anytype, indent: usize) anyerror!void {
    // If this element has local template values, prefer them for its subtree
    const eff_values: []const TemplateValue = if (el.local_values.len > 0) el.local_values else values;
    // Use precomputed hints
    const has_elem_child = el.has_element_child;
    const has_evtxml_subst = el.has_evtxml_subst_in_tree;
    const has_evtxml_value = el.has_evtxml_value_in_tree;
    // Drop debug-only Data tracing (kept minimal logging elsewhere)
    // Early: drop element if its only content is an optional substitution resolving to NULL
    if (!has_elem_child and el.children.items.len == 1) {
        const only = el.children.items[0];
        if (only.tag == .Subst and only.subst_optional and only.subst_id < eff_values.len) {
            const vv0 = eff_values[only.subst_id];
            if (vv0.t == 0x00 or vv0.data.len == 0) return;
        }
    }
    // Early: array substitution repetition for sole content
    if (!has_elem_child and !has_evtxml_subst and !has_evtxml_value and el.children.items.len == 1 and !nameEqualsAscii(chunk, el.name, "Data")) {
        const c0 = el.children.items[0];
        if (c0.tag == .Subst and (c0.subst_vtype & 0x80) != 0 and c0.subst_id < eff_values.len) {
            const vv = eff_values[c0.subst_id];
            const base: u8 = c0.subst_vtype & 0x7f;
            if (base == 0x21) {
                log.warn("array of 0x21 not supported; skipping repetition", .{});
            } else if (base == 0x10 and !(vv.t == 0x94 or vv.t == 0x95)) {
                log.warn("size array backing mismatch in element repetition: got 0x{x}", .{vv.t});
                return;
            }
            // Helper lambdas
            const write_open = struct {
                fn go(chunk_: []const u8, el_: *const IR.Element, w_: anytype, indent_spaces: usize) !void {
                    var i_: usize = 0;
                    while (i_ < indent_spaces) : (i_ += 1) try w_.writeByte(' ');
                    try w_.writeByte('<');
                    try writeNameXml(chunk_, el_.name, w_);
                    // re-emit attributes
                    var ai_: usize = 0;
                    while (ai_ < el_.attrs.items.len) : (ai_ += 1) {
                        const a_ = el_.attrs.items[ai_];
                        var tmp_: [512]u8 = undefined;
                        var fbs_ = std.io.fixedBufferStream(&tmp_);
                        const eff_vals_: []const TemplateValue = if (el_.local_values.len > 0) el_.local_values else &[_]TemplateValue{};
                        try renderAttrValueFromIR(chunk_, a_.value.items, eff_vals_, fbs_.writer());
                        const rendered_ = fbs_.getWritten();
                        if (rendered_.len == 0) continue;
                        try w_.writeByte(' ');
                        try writeNameXml(chunk_, a_.name, w_);
                        try w_.writeAll("=\"");
                        if (attrNameIsSystemTime(a_.name, chunk_)) {
                            try normalizeAndWriteSystemTimeAscii(w_, rendered_);
                        } else {
                            try w_.writeAll(rendered_);
                        }
                        try w_.writeByte('"');
                    }
                    try w_.writeByte('>');
                }
            };

            const write_close = struct {
                fn go(chunk_: []const u8, el_: *const IR.Element, w_: anytype, _: usize) !void {
                    try w_.writeAll("</");
                    try writeNameXml(chunk_, el_.name, w_);
                    try w_.writeByte('>');
                    try w_.writeByte('\n');
                }
            };

            // Determine iteration by base type
            var any_item = false;
            if (base == 0x01) { // Unicode string array: NUL-terminated items
                var j: usize = 0;
                while (j <= vv.data.len) {
                    const start = j;
                    var end = j;
                    while (end + 1 < vv.data.len) : (end += 2) {
                        if (std.mem.readInt(u16, vv.data[end .. end + 2][0..2], .little) == 0) break;
                    }
                    try write_open.go(chunk, el, w, indent);
                    if (end > start) try writeUtf16LeXmlEscaped(w, vv.data[start..end], (end - start) / 2);
                    try write_close.go(chunk, el, w, indent);
                    any_item = true;
                    if (end + 1 < vv.data.len) j = end + 2 else break;
                }
            } else if (base == 0x02) { // ANSI string array: NUL-separated
                var j: usize = 0;
                while (j <= vv.data.len) {
                    const start = j;
                    var end = j;
                    while (end < vv.data.len and vv.data[end] != 0) : (end += 1) {}
                    try write_open.go(chunk, el, w, indent);
                    if (end > start) try writeAnsiCp1252Escaped(w, vv.data[start..end]);
                    try write_close.go(chunk, el, w, indent);
                    any_item = true;
                    if (end < vv.data.len and vv.data[end] == 0) j = end + 1 else break;
                }
            } else if (valueTypeFixedSize(base)) |esz| {
                var j: usize = 0;
                while (j + esz <= vv.data.len) : (j += esz) {
                    try write_open.go(chunk, el, w, indent);
                    try writeValueXml(w, base, vv.data[j .. j + esz]);
                    try write_close.go(chunk, el, w, indent);
                    any_item = true;
                }
            } else if (base == 0x13) { // SID array
                var j: usize = 0;
                while (j + 8 <= vv.data.len) {
                    const subc: usize = vv.data[j + 1];
                    const need: usize = 8 + subc * 4;
                    if (j + need > vv.data.len) break;
                    try write_open.go(chunk, el, w, indent);
                    try writeValueXml(w, 0x13, vv.data[j .. j + need]);
                    try write_close.go(chunk, el, w, indent);
                    any_item = true;
                    j += need;
                }
            }
            if (!any_item) {
                // zero-length arrays -> one empty element
                try write_open.go(chunk, el, w, indent);
                try write_close.go(chunk, el, w, indent);
            }
            return;
        }
    }

    // Debug: trace block removed after expansion; retain normal logging elsewhere

    // Write opening tag and attributes (after early structural decisions)
    var i: usize = 0;
    while (i < indent) : (i += 1) try w.writeByte(' ');
    try w.writeByte('<');
    try writeNameXml(chunk, el.name, w);

    var ai: usize = 0;
    while (ai < el.attrs.items.len) : (ai += 1) {
        const a = el.attrs.items[ai];
        // Render attribute value to buffer
        var tmp: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&tmp);
        try renderAttrValueFromIR(chunk, a.value.items, eff_values, fbs.writer());
        const rendered = fbs.getWritten();
        // Drop only if the attribute is a single optional substitution resolving NULL
        var drop_attr = false;
        if (a.value.items.len == 1) {
            const n0 = a.value.items[0];
            if (n0.tag == .Subst and n0.subst_optional and n0.subst_id < eff_values.len) {
                const vv0 = eff_values[n0.subst_id];
                if (vv0.t == 0x00 or vv0.data.len == 0) drop_attr = true;
            }
        }
        if (drop_attr) continue;
        try w.writeByte(' ');
        try writeNameXml(chunk, a.name, w);
        try w.writeAll("=\"");
        if (attrNameIsSystemTime(a.name, chunk)) {
            try normalizeAndWriteSystemTimeAscii(w, rendered);
        } else {
            try w.writeAll(rendered);
        }
        try w.writeByte('"');
    }
    if (el.children.items.len == 0) {
        // Emit explicit open/close for elements that can be compared with rust output (<Binary></Binary>)
        try w.writeByte('>');
        try w.writeAll("</");
        try writeNameXml(chunk, el.name, w);
        try w.writeByte('>');
        try w.writeByte('\n');
        return;
    }

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
            .Text, .Pad, .CharRef, .EntityRef, .CData, .PITarget, .PIData => {
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
