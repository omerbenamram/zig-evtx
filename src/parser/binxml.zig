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
const Reader = @import("reader.zig").Reader;
const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const irNewElement = IRModule.irNewElement;
const renderXmlWithContext = @import("render_xml.zig").renderXmlWithContext;
const renderElementJson = @import("render_json.zig").renderElementJson;
// Local name writers for tracing (avoid renderer dependency)
fn writeNameFromOffset(chunk: []const u8, name_offset: u32, w: anytype) !void {
    const off = @as(usize, name_offset);
    if (off + 8 > chunk.len) return BinXmlError.OutOfBounds;
    const num_chars = std.mem.readInt(u16, chunk[off + 6 .. off + 8][0..2], .little);
    const str_start = off + 8;
    const byte_len = @as(usize, num_chars) * 2;
    if (str_start + byte_len > chunk.len) return BinXmlError.OutOfBounds;
    var num = num_chars;
    if (byte_len >= 2) {
        const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
        if (last == 0 and num > 0) num -= 1;
    }
    try writeUtf16LeXmlEscaped(w, chunk[str_start .. str_start + num * 2], num);
}

fn writeNameFromUtf16(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    try writeUtf16LeXmlEscaped(w, utf16le, num_chars);
}

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
pub const TOK_FRAGMENT_HEADER: u8 = 0x0f;
pub const TOK_OPEN_START: u8 = 0x01; // or 0x41 with has-more flag
pub const TOK_CLOSE_START: u8 = 0x02;
pub const TOK_CLOSE_EMPTY: u8 = 0x03;
pub const TOK_END_ELEMENT: u8 = 0x04;
pub const TOK_VALUE: u8 = 0x05; // or 0x45 with has-more flag
pub const TOK_ATTRIBUTE: u8 = 0x06; // or 0x46 with has-more flag
pub const TOK_TEMPLATE_INSTANCE: u8 = 0x0c;
pub const TOK_NORMAL_SUBST: u8 = 0x0d;
pub const TOK_OPTIONAL_SUBST: u8 = 0x0e;
pub const TOK_EOF: u8 = 0x00;
pub const TOK_CDATA: u8 = 0x07; // or 0x47 with has-more flag
pub const TOK_CHARREF: u8 = 0x08; // or 0x48 with has-more flag
pub const TOK_ENTITYREF: u8 = 0x09; // or 0x49 with has-more flag
pub const TOK_PITARGET: u8 = 0x0a;
pub const TOK_PIDATA: u8 = 0x0b;

pub fn hasMore(flagged: u8, base: u8) bool {
    return (flagged & 0x1f) == base and (flagged & 0x40) != 0;
}
pub fn isToken(flagged: u8, base: u8) bool {
    return (flagged & 0x1f) == base;
}

pub fn valueTypeFixedSize(vtype: u8) ?usize {
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

const Source = enum { rec, def };
fn materializeNameFromChunkOffset(chunk: []const u8, allocator: std.mem.Allocator, off_u32: u32) !IR.Name {
    const off_usize: usize = @intCast(off_u32);
    if (off_usize + 8 > chunk.len) return BinXmlError.UnexpectedEof;
    const num_chars = std.mem.readInt(u16, chunk[off_usize + 6 .. off_usize + 8][0..2], .little);
    const str_start = off_usize + 8;
    const byte_len = @as(usize, num_chars) * 2;
    if (str_start + byte_len > chunk.len) return BinXmlError.UnexpectedEof;
    var take_chars = num_chars;
    if (byte_len >= 2) {
        const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
        if (last == 0 and take_chars > 0) take_chars -= 1;
    }
    const buf = try allocator.alloc(u8, take_chars * 2);
    @memcpy(buf, chunk[str_start .. str_start + take_chars * 2]);
    return IR.Name{ .InlineUtf16 = .{ .bytes = buf, .num_chars = take_chars } };
}

fn parseDefNameIR(chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, chunk_base: usize) !IR.Name {
    const name_off = try r.readU32le();
    if (log.enabled(.trace)) log.trace("def name_off=0x{x} cur_after_off=0x{x}", .{ name_off, r.pos });
    const abs_after_off: usize = chunk_base + r.pos;
    if (name_off == @as(u32, @intCast(abs_after_off))) {
        const inl_start = r.pos;
        if (r.rem() < 6) return BinXmlError.UnexpectedEof;
        const next_string = try r.readU32le();
        const name_hash = try r.readU16le();
        if (log.enabled(.trace)) log.trace("inline NameLink next=0x{x} hash=0x{x} inl_start=0x{x}", .{ next_string, name_hash, inl_start });
        // The inline name layout then carries a u16 length, followed by UTF-16 bytes and 4 bytes padding/terminator.
        if (r.rem() < 2) return BinXmlError.UnexpectedEof;
        const num = try r.readU16le();
        const bytes = @as(usize, num) * 2;
        if (log.enabled(.trace)) log.trace("inline name num={d} r.pos=0x{x}", .{ num, r.pos });
        if (r.rem() < bytes) return BinXmlError.UnexpectedEof;
        const slice_src = r.buf[r.pos .. r.pos + bytes];
        r.pos += bytes;
        // Seek to end of inline name block: NameLink(6) + string(len*2) + 4 (terminator/padding)
        const want_end = inl_start + 6 + @as(usize, num) * 2 + 4;
        if (log.enabled(.trace)) log.trace("inline name end want=0x{x} now=0x{x}", .{ want_end, r.pos });
        if (r.pos < want_end and want_end <= r.buf.len) r.pos = want_end;
        const buf = try allocator.alloc(u8, bytes);
        @memcpy(buf, slice_src);
        return IR.Name{ .InlineUtf16 = .{ .bytes = buf, .num_chars = @intCast(num) } };
    }
    // Name by chunk offset
    return materializeNameFromChunkOffset(chunk, allocator, name_off);
}

pub fn logNameTrace(chunk: []const u8, name: IR.Name, label: []const u8) !void {
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

fn readInlineNameDefFlexibleAlloc(r: *Reader, alloc: std.mem.Allocator) !struct { bytes: []u8, num_chars: usize } {
    // According to the spec (Windows XML Event Log (EVTX).asciidoc -> Name),
    // the 4-byte unknown prefix is NOT present in Windows Event Template resources.
    // Therefore, for definitions we must read the inline name as:
    //   u16 hash + u16 num_chars + UTF-16LE string + optional end-of-string (u16 0)
    // Try the hash-prefixed form first, then a minimal (num + UTF16) fallback.

    // Variant A: u16 hash + u16 num + UTF16 (+ optional EOS)
    if (r.rem() >= 4) {
        const saveA = r.pos;
        _ = try r.readU16le(); // hash
        const numA = try r.readU16le();
        const bytesA = @as(usize, numA) * 2;
        if (numA > 0 and r.rem() >= bytesA and r.pos + bytesA <= r.buf.len) {
            const sliceA_src = r.buf[r.pos .. r.pos + bytesA];
            r.pos += bytesA;
            // Optional end-of-string (u16 0)
            if (r.rem() >= 2) {
                const eos = std.mem.readInt(u16, r.buf[r.pos .. r.pos + 2][0..2], .little);
                if (eos == 0) r.pos += 2;
            }
            const buf = try alloc.alloc(u8, bytesA);
            @memcpy(buf, sliceA_src);
            return .{ .bytes = buf, .num_chars = numA };
        }
        r.pos = saveA;
    }

    // Variant B: u16 num + UTF16 (+ optional EOS)
    if (r.rem() >= 2) {
        const saveB = r.pos;
        const numB = try r.readU16le();
        const bytesB = @as(usize, numB) * 2;
        if (numB > 0 and r.rem() >= bytesB and r.pos + bytesB <= r.buf.len) {
            const sliceB_src = r.buf[r.pos .. r.pos + bytesB];
            r.pos += bytesB;
            // Optional end-of-string (u16 0)
            if (r.rem() >= 2) {
                const eos = std.mem.readInt(u16, r.buf[r.pos .. r.pos + 2][0..2], .little);
                if (eos == 0) r.pos += 2;
            }
            const buf = try alloc.alloc(u8, bytesB);
            @memcpy(buf, sliceB_src);
            return .{ .bytes = buf, .num_chars = numB };
        }
        r.pos = saveB;
    }

    // No additional fallback variants per important.mdc
    return BinXmlError.UnexpectedEof;
}

// Move TemplateValue up so IR can reference it
pub const TemplateValue = struct {
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

pub fn expectedValuesFromTemplate(el: *const IR.Element) usize {
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

pub fn parseTemplateInstanceValuesExpected(r: *Reader, allocator: std.mem.Allocator, expected: usize) ![]TemplateValue {
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

pub fn writeValueXml(w: anytype, t: u8, data: []const u8) !void {
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

pub fn render(chunk: []const u8, bin: []const u8, mode: RenderMode, w: anytype) !void {
    var ctx = try Context.init(std.heap.page_allocator);
    defer ctx.deinit();
    switch (mode) {
        .xml => try renderXmlWithContext(&ctx, chunk, bin, w),
        .json => {
            var ctx2 = try Context.init(std.heap.page_allocator);
            defer ctx2.deinit();
            const root = try buildExpandedElementTree(&ctx2, chunk, bin);
            try renderElementJson(chunk, root, ctx2.arena.allocator(), w);
        },
        .jsonl => {
            var ctx2 = try Context.init(std.heap.page_allocator);
            defer ctx2.deinit();
            const root = try buildExpandedElementTree(&ctx2, chunk, bin);
            try renderElementJson(chunk, root, ctx2.arena.allocator(), w);
        },
    }
}

// --- Context and template cache (IR) ---
pub const Context = struct {
    pub const DefKey = struct {
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
    const dst = try IRModule.irNewElement(alloc, src.name);
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
        .json => {
            const root = try buildExpandedElementTree(ctx, chunk, bin);
            try renderElementJson(chunk, root, ctx.arena.allocator(), w);
        },
        .jsonl => {
            const root = try buildExpandedElementTree(ctx, chunk, bin);
            try renderElementJson(chunk, root, ctx.arena.allocator(), w);
        },
    }
}

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
pub fn expandElementWithValues(src: *const IR.Element, values: []const TemplateValue, alloc: std.mem.Allocator) anyerror!*IR.Element {
    const dst = try IRModule.irNewElement(alloc, src.name);
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

fn parseInlineNameFlexibleIR(r: *Reader, alloc: std.mem.Allocator) !IR.Name {
    const nm = try readInlineNameDefFlexibleAlloc(r, alloc);
    return IR.Name{ .InlineUtf16 = .{ .bytes = nm.bytes, .num_chars = nm.num_chars } };
}

fn parseAttributeListIR(chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source, max_end: usize, chunk_base: usize) !std.ArrayList(IR.Attr) {
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
                // materialize name into InlineUtf16
                const off_usize: usize = @intCast(off);
                if (off_usize + 8 > chunk.len) return BinXmlError.UnexpectedEof;
                const num_chars = std.mem.readInt(u16, chunk[off_usize + 6 .. off_usize + 8][0..2], .little);
                const str_start = off_usize + 8;
                const byte_len = @as(usize, num_chars) * 2;
                if (str_start + byte_len > chunk.len) return BinXmlError.UnexpectedEof;
                var take_chars = num_chars;
                if (byte_len >= 2) {
                    const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
                    if (last == 0 and take_chars > 0) take_chars -= 1;
                }
                const buf = try allocator.alloc(u8, take_chars * 2);
                @memcpy(buf, chunk[str_start .. str_start + take_chars * 2]);
                name = IR.Name{ .InlineUtf16 = .{ .bytes = buf, .num_chars = take_chars } };
            },
            .def => {
                name = try parseDefNameIR(chunk, r, allocator, chunk_base);
            },
        }
        if (log.enabled(.trace)) {
            try logNameTrace(chunk, name, "attr");
        }
        // Collect attribute value tokens into IR
        var tokens = std.ArrayList(IR.Node).init(allocator);
        try collectValueTokensIRWithCtx(chunk, r, &tokens, src, list_end, allocator, chunk_base);
        try out.append(.{ .name = name, .value = tokens });
    }
    if (r.pos != list_end) r.pos = list_end;
    return out;
}

fn collectValueTokensIRWithCtx(chunk: []const u8, r: *Reader, out: *std.ArrayList(IR.Node), src: Source, end_pos: usize, allocator: std.mem.Allocator, chunk_base: usize) !void {
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
                const text = try r.readUnicodeTextStringBounded(end_pos);
                if (ENABLE_PLUS_PAD and text.len == 2 and text[0] == 0x2B and text[1] == 0x00) {
                    want_pad2 = true;
                    continue;
                }
                try out.append(.{ .tag = .Text, .text_utf16 = text, .text_num_chars = text.len / 2 });
            } else if (vtype == 0x02) {
                // Some manifests use ANSI string in value text; treat like 0x0e (len-prefixed) but decode as CP-1252 during rendering
                const payload = try r.readLenPrefixedBytes16Bounded(end_pos);
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = payload, .pad_width = if (want_pad2) 2 else 0 });
                want_pad2 = false;
            } else if (valueTypeFixedSize(vtype)) |sz| {
                const payload = try r.readFixedBytesBounded(sz, end_pos);
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = payload, .pad_width = if (want_pad2) 2 else 0 });
                want_pad2 = false;
            } else if (vtype == 0x0e) {
                const payload = try r.readLenPrefixedBytes16Bounded(end_pos);
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = payload, .pad_width = if (want_pad2) 2 else 0 });
                want_pad2 = false;
            } else if (vtype == 0x13) {
                const payload = try r.readSidBytesBounded(end_pos);
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
                    const off_usize: usize = @intCast(ent_name_off);
                    if (off_usize + 8 > chunk.len) return BinXmlError.UnexpectedEof;
                    const num_chars = std.mem.readInt(u16, chunk[off_usize + 6 .. off_usize + 8][0..2], .little);
                    const str_start = off_usize + 8;
                    const byte_len = @as(usize, num_chars) * 2;
                    if (str_start + byte_len > chunk.len) return BinXmlError.UnexpectedEof;
                    var take_chars = num_chars;
                    if (byte_len >= 2) {
                        const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
                        if (last == 0 and take_chars > 0) take_chars -= 1;
                    }
                    const buf = try allocator.alloc(u8, take_chars * 2);
                    @memcpy(buf, chunk[str_start .. str_start + take_chars * 2]);
                    nm = IR.Name{ .InlineUtf16 = .{ .bytes = buf, .num_chars = take_chars } };
                },
                .def => {
                    nm = try parseDefNameIR(chunk, r, allocator, chunk_base);
                },
            }
            try out.append(.{ .tag = .EntityRef, .entity_name = nm });
            continue;
        } else if (isToken(pk, TOK_CDATA)) {
            _ = try r.readU8();
            const data = try r.readUnicodeTextStringBounded(end_pos);
            try out.append(.{ .tag = .CData, .text_utf16 = data, .text_num_chars = data.len / 2 });
            continue;
        } else if (isToken(pk, TOK_PITARGET)) {
            _ = try r.readU8();
            var nm: IR.Name = undefined;
            switch (src) {
                .rec => {
                    if (r.pos + 4 > end_pos) return BinXmlError.UnexpectedEof;
                    const pi_off = try r.readU32le();
                    const off_usize: usize = @intCast(pi_off);
                    if (off_usize + 8 > chunk.len) return BinXmlError.UnexpectedEof;
                    const num_chars = std.mem.readInt(u16, chunk[off_usize + 6 .. off_usize + 8][0..2], .little);
                    const str_start = off_usize + 8;
                    const byte_len = @as(usize, num_chars) * 2;
                    if (str_start + byte_len > chunk.len) return BinXmlError.UnexpectedEof;
                    var take_chars = num_chars;
                    if (byte_len >= 2) {
                        const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
                        if (last == 0 and take_chars > 0) take_chars -= 1;
                    }
                    const buf = try allocator.alloc(u8, take_chars * 2);
                    @memcpy(buf, chunk[str_start .. str_start + take_chars * 2]);
                    nm = IR.Name{ .InlineUtf16 = .{ .bytes = buf, .num_chars = take_chars } };
                },
                .def => nm = try parseDefNameIR(chunk, r, allocator, chunk_base),
            }
            try out.append(.{ .tag = .PITarget, .pi_target = nm });
            continue;
        } else if (isToken(pk, TOK_PIDATA)) {
            _ = try r.readU8();
            const data = try r.readUnicodeTextStringBounded(end_pos);
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

fn parseElementIRBase(chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source, chunk_base: usize) !*IR.Element {
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
            const name_off = try r.readU32le();
            const off_usize: usize = @intCast(name_off);
            if (off_usize + 8 > chunk.len) return BinXmlError.UnexpectedEof;
            const num_chars = std.mem.readInt(u16, chunk[off_usize + 6 .. off_usize + 8][0..2], .little);
            const str_start = off_usize + 8;
            const byte_len = @as(usize, num_chars) * 2;
            if (str_start + byte_len > chunk.len) return BinXmlError.UnexpectedEof;
            var take_chars = num_chars;
            if (byte_len >= 2) {
                const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
                if (last == 0 and take_chars > 0) take_chars -= 1;
            }
            const buf = try allocator.alloc(u8, take_chars * 2);
            @memcpy(buf, chunk[str_start .. str_start + take_chars * 2]);
            name = IR.Name{ .InlineUtf16 = .{ .bytes = buf, .num_chars = take_chars } };
        },
        .def => {
            // Attempt with dependency_identifier first; rollback if resulting window is invalid
            const save0 = r.pos;
            var parsed_with_dep = false;
            if (r.rem() >= 2 + 4) {
                const save1 = r.pos;
                if (r.readU16le()) |_| {
                    if (r.readU32le()) |dsz| {
                        // Read name field (u32 offset or inline block)
                        if (log.enabled(.trace)) {
                            var tmpn: [24]u8 = undefined;
                            const take = @min(r.rem(), tmpn.len);
                            @memcpy(tmpn[0..take], r.buf[r.pos .. r.pos + take]);
                            log.trace("def pre-name (with dep) pos=0x{x} look: {s}", .{ r.pos, std.fmt.fmtSliceHexLower(tmpn[0..take]) });
                        }
                        if (parseDefNameIR(chunk, r, allocator, chunk_base)) |nm| {
                            // header does NOT include name offset; it is part of data_size per spec
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
                // header does NOT include name offset; it is part of data_size per spec
                header_len = 1 + 4;
                if (log.enabled(.trace)) {
                    var tmpn2: [24]u8 = undefined;
                    const take2 = @min(r.rem(), tmpn2.len);
                    @memcpy(tmpn2[0..take2], r.buf[r.pos .. r.pos + take2]);
                    log.trace("def pre-name (no dep) pos=0x{x} look: {s}", .{ r.pos, std.fmt.fmtSliceHexLower(tmpn2[0..take2]) });
                }
                name = try parseDefNameIR(chunk, r, allocator, chunk_base);
            }
            if (log.enabled(.trace)) log.trace("def hdr: data_size={d} header_len={d} pos=0x{x}", .{ data_size, header_len, r.pos });
        },
    }
    const element_end = element_start + header_len + @as(usize, data_size);
    if (element_end > r.buf.len or element_end < element_start) return BinXmlError.UnexpectedEof;
    const el = try IRModule.irNewElement(allocator, name);
    if (hasMore(start, TOK_OPEN_START)) {
        el.attrs = try parseAttributeListIR(chunk, r, allocator, src, element_end, chunk_base);
        // hints from attributes
        var ai_h: usize = 0;
        while (ai_h < el.attrs.items.len) : (ai_h += 1) {
            updateHintsFromNodes(el, el.attrs.items[ai_h].value.items, true);
        }
    }
    // Skip up to 4 bytes of zero padding after start header/attr list regardless of hasMore
    var pad: usize = 0;
    while (pad < 4 and r.pos < element_end and r.buf[r.pos] == 0) : (pad += 1) r.pos += 1;
    if (r.pos >= element_end or r.rem() == 0) return el;
    const prev_pos = r.pos;
    const nxt = try r.readU8();
    if (log.enabled(.trace)) log.trace("parseElementIR nxt=0x{x} pos=0x{x} end=0x{x}", .{ nxt, r.pos, element_end });
    if (isToken(nxt, TOK_CLOSE_EMPTY)) {
        return el;
    }
    if (!isToken(nxt, TOK_CLOSE_START)) {
        if (log.enabled(.trace)) {
            var tmp: [64]u8 = undefined;
            const win_start = if (prev_pos >= 16) prev_pos - 16 else 0;
            const win_end = @min(element_end, win_start + tmp.len);
            const take = win_end - win_start;
            @memcpy(tmp[0..take], r.buf[win_start .. win_start + take]);
            log.trace("unexpected nxt window [0x{x}..0x{x}): {s}", .{ win_start, win_end, std.fmt.fmtSliceHexLower(tmp[0..take]) });
        }
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
            const child = try parseElementIRBase(chunk, r, allocator, src, chunk_base);
            try el.children.append(.{ .tag = .Element, .elem = child });
            el.has_element_child = true;
        } else if (isToken(t, TOK_VALUE) or isToken(t, TOK_NORMAL_SUBST) or isToken(t, TOK_OPTIONAL_SUBST) or isToken(t, TOK_CDATA) or isToken(t, TOK_CHARREF) or isToken(t, TOK_ENTITYREF) or isToken(t, TOK_PITARGET) or isToken(t, TOK_PIDATA)) {
            var seq = std.ArrayList(IR.Node).init(allocator);
            try collectValueTokensIRWithCtx(chunk, r, &seq, src, element_end, allocator, chunk_base);
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

pub fn parseElementIR(chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source) !*IR.Element {
    return parseElementIRBase(chunk, r, allocator, src, 0);
}

pub fn attrNameIsSystemTime(name: IR.Name, chunk: []const u8) bool {
    return switch (name) {
        .NameOffset => |off| isNameSystemTimeFromOffset(chunk, off),
        .InlineUtf16 => |inl| utf16EqualsAscii(inl.bytes, inl.num_chars, "SystemTime"),
    };
}

pub fn appendEvtXmlPayloadChildrenIR(chunk: []const u8, data: []const u8, alloc: std.mem.Allocator, parent: *IR.Element) anyerror!void {
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
            const child_def = try parseElementIRBase(chunk, &def_r, alloc, .def, data_start);
            const expected = expectedValuesFromTemplate(child_def);
            const vals = try parseTemplateInstanceValuesExpected(&r, alloc, expected);
            const expanded_child = try expandElementWithValues(child_def, vals, alloc);
            try parent.children.append(.{ .tag = .Element, .elem = expanded_child });
        } else break;
    }
}

// --- Build a fully expanded IR element tree (no reader usage during render) ---

fn spliceEvtXmlAll(chunk: []const u8, el: *IR.Element, alloc: std.mem.Allocator) anyerror!void {
    // Splice any nested EvtXml payloads that appeared inside attribute value token streams
    var ai: usize = 0;
    while (ai < el.attrs.items.len) : (ai += 1) {
        const a = el.attrs.items[ai];
        var vi: usize = 0;
        while (vi < a.value.items.len) : (vi += 1) {
            const nd = a.value.items[vi];
            if (nd.tag == .Value and (nd.vtype & 0x7f) == 0x21 and nd.vbytes.len > 0) {
                try appendEvtXmlPayloadChildrenIR(chunk, nd.vbytes, alloc, el);
            }
        }
    }
    // Rebuild children, splicing Value 0x21 and recursing into elements
    var new_children = std.ArrayList(IR.Node).init(alloc);
    var ci: usize = 0;
    while (ci < el.children.items.len) : (ci += 1) {
        const nd = el.children.items[ci];
        switch (nd.tag) {
            .Element => {
                try spliceEvtXmlAll(chunk, nd.elem.?, alloc);
                try new_children.append(nd);
            },
            .Value => {
                if ((nd.vtype & 0x7f) == 0x21 and nd.vbytes.len > 0) {
                    try appendEvtXmlPayloadChildrenIR(chunk, nd.vbytes, alloc, el);
                    // drop this node
                } else {
                    try new_children.append(nd);
                }
            },
            else => try new_children.append(nd),
        }
    }
    el.children = new_children;
}

pub fn buildExpandedElementTree(ctx: *Context, chunk: []const u8, bin: []const u8) anyerror!*IR.Element {
    var r = Reader.init(bin);
    // Optional fragment header
    if (r.rem() >= 4 and r.buf[r.pos] == TOK_FRAGMENT_HEADER) {
        _ = try r.readU8(); // token
        _ = try r.readU8(); // major
        _ = try r.readU8(); // minor
        _ = try r.readU8(); // flags
    }
    if (r.rem() == 0) {
        // Build minimal <Event/> IR
        const bytes = try utf16FromAscii(ctx.arena.allocator(), "Event");
        const el = try IRModule.irNewElement(ctx.arena.allocator(), IR.Name{ .InlineUtf16 = .{ .bytes = bytes, .num_chars = 5 } });
        return el;
    }
    const first = try r.peekU8();
    if (first == TOK_TEMPLATE_INSTANCE) {
        _ = try r.readU8();
        if (r.rem() < 1 + 4 + 4) return BinXmlError.UnexpectedEof;
        _ = try r.readU8(); // unknown
        _ = try r.readU32le(); // template id (unused)
        const def_data_off = try r.readU32le();
        // Skip inline copy when def_data_off equals current record-relative cursor position
        if (def_data_off == @as(u32, @intCast(r.pos))) {
            if (r.rem() < 24) return BinXmlError.UnexpectedEof;
            _ = try r.readU32le();
            _ = try r.readGuid();
            const data_size_inline = try r.readU32le();
            if (r.rem() < data_size_inline) return BinXmlError.UnexpectedEof;
            r.pos += @as(usize, data_size_inline);
        }
        // Skip cached template defs inline
        while (r.rem() >= 28) {
            const data_size_peek = std.mem.readInt(u32, r.buf[r.pos + 20 .. r.pos + 24][0..4], .little);
            const block_end = r.pos + 24 + @as(usize, data_size_peek);
            if (block_end > r.buf.len) break;
            const payload_first = r.buf[r.pos + 24];
            if (payload_first != TOK_FRAGMENT_HEADER) break;
            r.pos = block_end;
        }
        // Parse def from chunk
        const def_off_usize: usize = @intCast(def_data_off);
        if (def_off_usize + 24 > chunk.len) return BinXmlError.OutOfBounds;
        const td_data_size = std.mem.readInt(u32, chunk[def_off_usize + 20 .. def_off_usize + 24][0..4], .little);
        const data_start = def_off_usize + 24;
        const data_end = data_start + @as(usize, td_data_size);
        if (data_end > chunk.len or data_start >= chunk.len) return BinXmlError.OutOfBounds;
        var def_r = Reader.init(chunk[data_start..data_end]);
        if (def_r.rem() >= 4 and def_r.buf[def_r.pos] == TOK_FRAGMENT_HEADER) {
            _ = try def_r.readU8();
            _ = try def_r.readU8();
            _ = try def_r.readU8();
            _ = try def_r.readU8();
        }
        const parsed_def = try parseElementIRBase(chunk, &def_r, ctx.arena.allocator(), .def, data_start);
        // Values
        const expected = expectedValuesFromTemplate(parsed_def);
        const values = try parseTemplateInstanceValuesExpected(&r, ctx.arena.allocator(), expected);
        // Cache def using GUID
        var guid: [16]u8 = undefined;
        std.mem.copyForwards(u8, guid[0..], chunk[def_off_usize + 4 .. def_off_usize + 20]);
        const key: Context.DefKey = .{ .def_data_off = def_data_off, .guid = guid };
        const got = try ctx.cache.getOrPut(key);
        if (!got.found_existing) got.value_ptr.* = parsed_def;
        // Expand
        const expanded = try expandElementWithValues(got.value_ptr.*, values, ctx.arena.allocator());
        // Splice nested payloads
        try spliceEvtXmlAll(chunk, expanded, ctx.arena.allocator());
        return expanded;
    }
    // Non-template record path
    const root = try parseElementIR(chunk, &r, ctx.arena.allocator(), .rec);
    const expanded_root = try expandElementWithValues(root, &[_]TemplateValue{}, ctx.arena.allocator());
    try spliceEvtXmlAll(chunk, expanded_root, ctx.arena.allocator());
    return expanded_root;
}
