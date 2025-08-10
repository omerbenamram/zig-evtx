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
const Reader = @import("reader.zig").Reader;
const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const irNewElement = IRModule.irNewElement;
const renderXmlWithContext = @import("render_xml.zig").renderXmlWithContext;
const renderElementJson = @import("render_json.zig").renderElementJson;
const BinXmlError = @import("err.zig").BinXmlError;
const NameCacheEntry = struct { bytes: []u8, num_chars: usize };

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
pub const RenderMode = enum { xml, json, jsonl };

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

// Skip a 4-byte fragment header token (0x0f) if present at the current reader position.
fn skipFragmentHeaderIfPresent(r: *Reader) !void {
    if (r.rem() >= 4 and r.buf[r.pos] == TOK_FRAGMENT_HEADER) {
        _ = try r.readU8(); // token
        _ = try r.readU8(); // major
        _ = try r.readU8(); // minor
        _ = try r.readU8(); // flags
    }
}

// Skip any inline-cached template definition blocks (header + payload starting with 0x0f) deterministically.
fn skipInlineCachedTemplateDefs(r: *Reader) void {
    while (r.rem() >= 28) {
        const data_size_peek = std.mem.readInt(u32, r.buf[r.pos + 20 .. r.pos + 24][0..4], .little);
        const block_end = r.pos + 24 + @as(usize, data_size_peek);
        if (block_end > r.buf.len) break;
        const payload_first = r.buf[r.pos + 24];
        if (payload_first != TOK_FRAGMENT_HEADER) break;
        r.pos = block_end;
    }
}

// Parse a template definition from a chunk using its record-relative data offset.
// Returns the parsed IR element and the absolute data_start for the def window.
fn parseTemplateDefFromChunk(ctx: *Context, chunk: []const u8, def_data_off: u32, allocator: std.mem.Allocator) !struct { def: *IR.Element, data_start: usize } {
    const def_off_usize: usize = @intCast(def_data_off);
    if (def_off_usize + 24 > chunk.len) return BinXmlError.OutOfBounds;
    const td_data_size = std.mem.readInt(u32, chunk[def_off_usize + 20 .. def_off_usize + 24][0..4], .little);
    const data_start = def_off_usize + 24;
    const data_end = data_start + @as(usize, td_data_size);
    if (data_end > chunk.len or data_start >= chunk.len) return BinXmlError.OutOfBounds;
    var def_r = Reader.init(chunk[data_start..data_end]);
    try skipFragmentHeaderIfPresent(&def_r);
    const parsed_def = try parseElementIRBase(ctx, chunk, &def_r, allocator, .def, data_start);
    return .{ .def = parsed_def, .data_start = data_start };
}

const Source = enum { rec, def };
fn materializeNameFromChunkOffset(ctx: *Context, chunk: []const u8, off_u32: u32) !IR.Name {
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
    if (ctx.name_cache.get(off_u32)) |entry| {
        return IR.Name{ .InlineUtf16 = .{ .bytes = entry.bytes, .num_chars = entry.num_chars } };
    }
    const buf = try ctx.arena.allocator().alloc(u8, take_chars * 2);
    @memcpy(buf, chunk[str_start .. str_start + take_chars * 2]);
    try ctx.name_cache.put(off_u32, NameCacheEntry{ .bytes = buf, .num_chars = take_chars });
    return IR.Name{ .InlineUtf16 = .{ .bytes = buf, .num_chars = take_chars } };
}

// (Cached via ctx)

fn parseDefNameIR(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, chunk_base: usize) !IR.Name {
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
    return materializeNameFromChunkOffset(ctx, chunk, name_off);
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

// Read a name according to source kind, respecting end bounds where applicable.
fn readNameIRBounded(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source, end_pos: usize, chunk_base: usize) !IR.Name {
    return switch (src) {
        .rec => blk: {
            if (r.pos + 4 > end_pos) break :blk BinXmlError.UnexpectedEof;
            const off = try r.readU32le();
            break :blk try materializeNameFromChunkOffset(ctx, chunk, off);
        },
        .def => try parseDefNameIR(ctx, chunk, r, allocator, chunk_base),
    };
}

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

// writeValueXml moved to value_writer.zig

const JoinerPolicy = enum { Attr, Text };

fn joinerFor(policy: JoinerPolicy, base: u8) []const u8 {
    return switch (policy) {
        .Attr => " ",
        .Text => if (base == 0x01 or base == 0x02) "," else " ",
    };
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
    var ctx = try Context.init(std.heap.c_allocator);
    defer ctx.deinit();
    switch (mode) {
        .xml => try renderXmlWithContext(&ctx, chunk, bin, w),
        .json => {
            var ctx2 = try Context.init(std.heap.c_allocator);
            defer ctx2.deinit();
            const root = try buildExpandedElementTree(&ctx2, chunk, bin);
            try renderElementJson(chunk, root, ctx2.arena.allocator(), w);
        },
        .jsonl => {
            var ctx2 = try Context.init(std.heap.c_allocator);
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
    name_cache: std.AutoHashMap(u32, NameCacheEntry),
    // Cached UTF-16 separators for joining arrays (arena-owned)
    sep_space_utf16: ?[]u8 = null,
    sep_comma_utf16: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator) !Context {
        return .{ .allocator = allocator, .arena = std.heap.ArenaAllocator.init(allocator), .cache = std.AutoHashMap(DefKey, *IR.Element).init(allocator), .verbose = false, .name_cache = std.AutoHashMap(u32, NameCacheEntry).init(allocator) };
    }

    pub fn deinit(self: *Context) void {
        self.cache.deinit();
        self.name_cache.deinit();
        self.arena.deinit();
    }

    pub fn resetPerChunk(self: *Context) void {
        // EVTX template definitions are chunk-local. Reset arena and clear cache buckets.
        self.cache.clearRetainingCapacity();
        self.name_cache.clearRetainingCapacity();
        // Invalidate any arena-backed cached slices
        self.sep_space_utf16 = null;
        self.sep_comma_utf16 = null;
        _ = self.arena.reset(.retain_capacity);
    }

    fn getSepUtf16(self: *Context, ascii: []const u8) !struct { bytes: []u8, num_chars: usize } {
        if (ascii.len == 0) return .{ .bytes = &[_]u8{}, .num_chars = 0 };
        if (ascii.len == 1 and ascii[0] == ' ') {
            if (self.sep_space_utf16 == null) {
                self.sep_space_utf16 = try utf16FromAscii(self.arena.allocator(), ascii);
            }
            return .{ .bytes = self.sep_space_utf16.?, .num_chars = 1 };
        }
        if (ascii.len == 1 and ascii[0] == ',') {
            if (self.sep_comma_utf16 == null) {
                self.sep_comma_utf16 = try utf16FromAscii(self.arena.allocator(), ascii);
            }
            return .{ .bytes = self.sep_comma_utf16.?, .num_chars = 1 };
        }
        // Fallback (should not happen with current joiner policy)
        const dyn = try utf16FromAscii(self.arena.allocator(), ascii);
        return .{ .bytes = dyn, .num_chars = ascii.len };
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
    // Pre-size attrs/children based on source sizes to reduce growth
    if (src.attrs.items.len > 0) try dst.attrs.ensureTotalCapacityPrecise(src.attrs.items.len);
    if (src.children.items.len > 0) try dst.children.ensureTotalCapacityPrecise(src.children.items.len);
    // clone attrs
    var ai: usize = 0;
    while (ai < src.attrs.items.len) : (ai += 1) {
        const a = src.attrs.items[ai];
        var vals = std.ArrayList(IR.Node).init(alloc);
        if (a.value.items.len > 0) try vals.ensureTotalCapacityPrecise(a.value.items.len);
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
fn cloneNodesReplacingSubstWithPolicy(ctx: *Context, policy: JoinerPolicy, alloc: std.mem.Allocator, nodes: []const IR.Node, values: []const TemplateValue) anyerror!std.ArrayList(IR.Node) {
    var out = std.ArrayList(IR.Node).init(alloc);
    if (nodes.len > 0) try out.ensureTotalCapacityPrecise(nodes.len);
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
                    // Compute the UTF-16 separator once via context arena and reuse its buffer
                    const sep_utf16_opt = blk: {
                        if (sep_ascii.len == 0) break :blk null;
                        const gg = try ctx.getSepUtf16(sep_ascii);
                        break :blk gg;
                    };
                    while (arrayItemNext(base, vv.t, vv.data, &idx)) |seg| {
                        if (!first) {
                            if (sep_utf16_opt) |sep| {
                                try out.append(.{ .tag = .Text, .text_utf16 = sep.bytes, .text_num_chars = sep.num_chars });
                            }
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
                const repl = try expandElementWithValues(ctx, child, eff_vals, alloc);
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
pub fn expandElementWithValues(ctx: *Context, src: *const IR.Element, values: []const TemplateValue, alloc: std.mem.Allocator) anyerror!*IR.Element {
    const dst = try IRModule.irNewElement(alloc, src.name);
    // Pre-size destination containers based on source sizes
    if (src.attrs.items.len > 0) try dst.attrs.ensureTotalCapacityPrecise(src.attrs.items.len);
    // attributes
    var ai: usize = 0;
    while (ai < src.attrs.items.len) : (ai += 1) {
        const a = src.attrs.items[ai];
        const expanded = try cloneNodesReplacingSubstWithPolicy(ctx, .Attr, alloc, a.value.items, values);
        try dst.attrs.append(.{ .name = a.name, .value = expanded });
    }
    // children
    const expanded_children = try cloneNodesReplacingSubstWithPolicy(ctx, .Text, alloc, src.children.items, values);
    if (expanded_children.items.len > 0) try dst.children.ensureTotalCapacityPrecise(expanded_children.items.len);
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

fn parseAttributeListIR(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source, max_end: usize, chunk_base: usize) !std.ArrayList(IR.Attr) {
    const list_size = try r.readU32le();
    const list_start = r.pos;
    const list_end = list_start + list_size;
    if (list_end > max_end or list_end < list_start) return BinXmlError.UnexpectedEof;
    var out = std.ArrayList(IR.Attr).init(allocator);
    // Estimate number of attributes: scan tokens to count 0x06 ATTRIBUTE headers
    var scan_pos = r.pos;
    var attr_count: usize = 0;
    while (scan_pos < list_end and scan_pos < r.buf.len and isToken(r.buf[scan_pos], TOK_ATTRIBUTE)) : (scan_pos += 1) {
        // Skip token byte
        // Name reading in def/rec branches varies; we can't safely skip full entry without parsing.
        // But counting headers still helps pre-size moderately.
        attr_count += 1;
        // We cannot advance correctly without parsing; break to avoid mis-sync
        break;
    }
    if (attr_count > 0) try out.ensureTotalCapacityPrecise(attr_count);
    while (r.pos < list_end and r.rem() > 0 and isToken(r.buf[r.pos], TOK_ATTRIBUTE)) {
        _ = try r.readU8();
        var name: IR.Name = undefined;
        name = try readNameIRBounded(ctx, chunk, r, allocator, src, list_end, chunk_base);
        if (log.enabled(.trace)) {
            try logNameTrace(chunk, name, "attr");
        }
        // Collect attribute value tokens into IR
        var tokens = std.ArrayList(IR.Node).init(allocator);
        try collectValueTokensIRWithCtx(ctx, chunk, r, &tokens, src, list_end, allocator, chunk_base);
        try out.append(.{ .name = name, .value = tokens });
    }
    if (r.pos != list_end) r.pos = list_end;
    return out;
}

fn collectValueTokensIRWithCtx(ctx: *Context, chunk: []const u8, r: *Reader, out: *std.ArrayList(IR.Node), src: Source, end_pos: usize, allocator: std.mem.Allocator, chunk_base: usize) !void {
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
            const nm = try readNameIRBounded(ctx, chunk, r, allocator, src, end_pos, chunk_base);
            try out.append(.{ .tag = .EntityRef, .entity_name = nm });
            continue;
        } else if (isToken(pk, TOK_CDATA)) {
            _ = try r.readU8();
            const data = try r.readUnicodeTextStringBounded(end_pos);
            try out.append(.{ .tag = .CData, .text_utf16 = data, .text_num_chars = data.len / 2 });
            continue;
        } else if (isToken(pk, TOK_PITARGET)) {
            _ = try r.readU8();
            const nm = try readNameIRBounded(ctx, chunk, r, allocator, src, end_pos, chunk_base);
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

const ElementHeader = struct { name: IR.Name, data_size: u32, header_len: usize };

fn parseRecElementHeader(ctx: *Context, chunk: []const u8, r: *Reader, _: std.mem.Allocator) !ElementHeader {
    _ = try r.readU16le(); // dependency id (required in records)
    const data_size = try r.readU32le();
    const header_len: usize = 1 + 2 + 4;
    const name_off = try r.readU32le();
    const name = try materializeNameFromChunkOffset(ctx, chunk, name_off);
    return .{ .name = name, .data_size = data_size, .header_len = header_len };
}

fn parseDefElementHeader(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, chunk_base: usize, element_start: usize) !ElementHeader {
    const save0 = r.pos;
    if (r.rem() >= 2 + 4) {
        const save1 = r.pos;
        if (r.readU16le()) |_| {
            if (r.readU32le()) |dsz| {
                if (log.enabled(.trace)) {
                    var tmpn: [24]u8 = undefined;
                    const take = @min(r.rem(), tmpn.len);
                    @memcpy(tmpn[0..take], r.buf[r.pos .. r.pos + take]);
                    log.trace("def pre-name (with dep) pos=0x{x} look: {s}", .{ r.pos, std.fmt.fmtSliceHexLower(tmpn[0..take]) });
                }
                if (parseDefNameIR(ctx, chunk, r, allocator, chunk_base)) |nm| {
                    const header_len_try: usize = 1 + 2 + 4;
                    const end_try = element_start + header_len_try + @as(usize, dsz);
                    if (end_try <= r.buf.len) {
                        return .{ .name = nm, .data_size = dsz, .header_len = header_len_try };
                    }
                    r.pos = save1;
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
    // Fallback: no dependency id
    r.pos = save0;
    const dsz2 = try r.readU32le();
    const header_len2: usize = 1 + 4;
    if (log.enabled(.trace)) {
        var tmpn2: [24]u8 = undefined;
        const take2 = @min(r.rem(), tmpn2.len);
        @memcpy(tmpn2[0..take2], r.buf[r.pos .. r.pos + take2]);
        log.trace("def pre-name (no dep) pos=0x{x} look: {s}", .{ r.pos, std.fmt.fmtSliceHexLower(tmpn2[0..take2]) });
    }
    const nm2 = try parseDefNameIR(ctx, chunk, r, allocator, chunk_base);
    return .{ .name = nm2, .data_size = dsz2, .header_len = header_len2 };
}

// Parse the start header of an element and compute the absolute end position for the element body.
fn parseElementHeaderAndEnd(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source, chunk_base: usize, element_start: usize) !struct { name: IR.Name, element_end: usize } {
    const hdr = switch (src) {
        .rec => try parseRecElementHeader(ctx, chunk, r, allocator),
        .def => try parseDefElementHeader(ctx, chunk, r, allocator, chunk_base, element_start),
    };
    const element_end = element_start + hdr.header_len + @as(usize, hdr.data_size);
    if (element_end > r.buf.len or element_end < element_start) return BinXmlError.UnexpectedEof;
    return .{ .name = hdr.name, .element_end = element_end };
}

fn parseElementIRBase(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source, chunk_base: usize) !*IR.Element {
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
    const hdr = try parseElementHeaderAndEnd(ctx, chunk, r, allocator, src, chunk_base, element_start);
    const name = hdr.name;
    const element_end = hdr.element_end;
    const el = try IRModule.irNewElement(allocator, name);
    if (hasMore(start, TOK_OPEN_START)) {
        el.attrs = try parseAttributeListIR(ctx, chunk, r, allocator, src, element_end, chunk_base);
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
            const child = try parseElementIRBase(ctx, chunk, r, allocator, src, chunk_base);
            try el.children.append(.{ .tag = .Element, .elem = child });
            el.has_element_child = true;
        } else if (isToken(t, TOK_VALUE) or isToken(t, TOK_NORMAL_SUBST) or isToken(t, TOK_OPTIONAL_SUBST) or isToken(t, TOK_CDATA) or isToken(t, TOK_CHARREF) or isToken(t, TOK_ENTITYREF) or isToken(t, TOK_PITARGET) or isToken(t, TOK_PIDATA)) {
            var seq = std.ArrayList(IR.Node).init(allocator);
            try collectValueTokensIRWithCtx(ctx, chunk, r, &seq, src, element_end, allocator, chunk_base);
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

pub fn parseElementIR(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source) !*IR.Element {
    return parseElementIRBase(ctx, chunk, r, allocator, src, 0);
}

pub fn attrNameIsSystemTime(name: IR.Name, chunk: []const u8) bool {
    return switch (name) {
        .NameOffset => |off| isNameSystemTimeFromOffset(chunk, off),
        .InlineUtf16 => |inl| utf16EqualsAscii(inl.bytes, inl.num_chars, "SystemTime"),
    };
}

pub fn appendEvtXmlPayloadChildrenIR(ctx: *Context, chunk: []const u8, data: []const u8, alloc: std.mem.Allocator, parent: *IR.Element) anyerror!void {
    if (data.len == 0) return;
    var r = Reader.init(data);
    try skipFragmentHeaderIfPresent(&r);
    while (r.rem() > 0) {
        const pk = r.buf[r.pos];
        if (pk == TOK_TEMPLATE_INSTANCE) {
            _ = try r.readU8();
            if (r.rem() < 1 + 4 + 4) break;
            _ = try r.readU8(); // unknown
            _ = try r.readU32le(); // template id
            const def_data_off = try r.readU32le();
            // Skip any inline cached template definition blocks deterministically
            skipInlineCachedTemplateDefs(&r);
            // Use chunk-stored definition to parse expected substitutions
            const parsed = try parseTemplateDefFromChunk(ctx, chunk, def_data_off, alloc);
            const child_def = parsed.def;
            const expected = expectedValuesFromTemplate(child_def);
            const vals = try parseTemplateInstanceValuesExpected(&r, alloc, expected);
            const expanded_child = try expandElementWithValues(ctx, child_def, vals, alloc);
            try parent.children.append(.{ .tag = .Element, .elem = expanded_child });
        } else break;
    }
}

// Collect EvtXml payload children as IR nodes into an output list (no mutation of parent during iteration)
fn collectEvtXmlPayloadChildren(ctx: *Context, chunk: []const u8, data: []const u8, alloc: std.mem.Allocator, out: *std.ArrayList(IR.Node)) anyerror!void {
    if (data.len == 0) return;
    var r = Reader.init(data);
    try skipFragmentHeaderIfPresent(&r);
    while (r.rem() > 0) {
        const pk = r.buf[r.pos];
        if (pk != TOK_TEMPLATE_INSTANCE) break;
        _ = try r.readU8();
        if (r.rem() < 1 + 4 + 4) break;
        _ = try r.readU8(); // unknown
        _ = try r.readU32le(); // template id
        const def_data_off = try r.readU32le();
        // Skip any inline cached template definition blocks deterministically
        skipInlineCachedTemplateDefs(&r);
        // Use chunk-stored definition to parse expected substitutions
        const parsed = try parseTemplateDefFromChunk(ctx, chunk, def_data_off, alloc);
        const child_def = parsed.def;
        const expected = expectedValuesFromTemplate(child_def);
        const vals = try parseTemplateInstanceValuesExpected(&r, alloc, expected);
        const expanded_child = try expandElementWithValues(ctx, child_def, vals, alloc);
        try out.append(.{ .tag = .Element, .elem = expanded_child });
    }
}

// --- Build a fully expanded IR element tree (no reader usage during render) ---

fn spliceEvtXmlAll(ctx: *Context, chunk: []const u8, el: *IR.Element, alloc: std.mem.Allocator) anyerror!void {
    // Stage any nested EvtXml payloads that appeared inside attribute value token streams
    var staged_attr_children = std.ArrayList(IR.Node).init(alloc);
    var ai: usize = 0;
    while (ai < el.attrs.items.len) : (ai += 1) {
        const a = el.attrs.items[ai];
        var vi: usize = 0;
        while (vi < a.value.items.len) : (vi += 1) {
            const nd = a.value.items[vi];
            if (nd.tag == .Value and (nd.vtype & 0x7f) == 0x21 and nd.vbytes.len > 0) {
                try collectEvtXmlPayloadChildren(ctx, chunk, nd.vbytes, alloc, &staged_attr_children);
            }
        }
    }
    // Rebuild children, splicing Value 0x21 and recursing into elements
    var new_children = std.ArrayList(IR.Node).init(alloc);
    if (el.children.items.len > 0) try new_children.ensureTotalCapacityPrecise(el.children.items.len + staged_attr_children.items.len);
    var ci: usize = 0;
    while (ci < el.children.items.len) : (ci += 1) {
        const nd = el.children.items[ci];
        switch (nd.tag) {
            .Element => {
                try spliceEvtXmlAll(ctx, chunk, nd.elem.?, alloc);
                try new_children.append(nd);
            },
            .Value => {
                if ((nd.vtype & 0x7f) == 0x21 and nd.vbytes.len > 0) {
                    // splice payload into the rebuilt list at this position
                    try collectEvtXmlPayloadChildren(ctx, chunk, nd.vbytes, alloc, &new_children);
                } else {
                    try new_children.append(nd);
                }
            },
            else => try new_children.append(nd),
        }
    }
    // Append any staged children discovered in attributes at the end (preserve previous behavior)
    var k: usize = 0;
    while (k < staged_attr_children.items.len) : (k += 1) try new_children.append(staged_attr_children.items[k]);
    el.children = new_children;
}

pub fn buildExpandedElementTree(ctx: *Context, chunk: []const u8, bin: []const u8) anyerror!*IR.Element {
    var r = Reader.init(bin);
    // Optional fragment header
    try skipFragmentHeaderIfPresent(&r);
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
        skipInlineCachedTemplateDefs(&r);
        // Parse def from chunk
        const parsed = try parseTemplateDefFromChunk(ctx, chunk, def_data_off, ctx.arena.allocator());
        const parsed_def = parsed.def;
        // Values
        const expected = expectedValuesFromTemplate(parsed_def);
        const values = try parseTemplateInstanceValuesExpected(&r, ctx.arena.allocator(), expected);
        // Cache def using GUID
        var guid: [16]u8 = undefined;
        const def_off_usize2: usize = @intCast(def_data_off);
        std.mem.copyForwards(u8, guid[0..], chunk[def_off_usize2 + 4 .. def_off_usize2 + 20]);
        const key: Context.DefKey = .{ .def_data_off = def_data_off, .guid = guid };
        const got = try ctx.cache.getOrPut(key);
        if (!got.found_existing) got.value_ptr.* = parsed_def;
        // Expand
        const expanded = try expandElementWithValues(ctx, got.value_ptr.*, values, ctx.arena.allocator());
        // Splice nested payloads
        try spliceEvtXmlAll(ctx, chunk, expanded, ctx.arena.allocator());
        return expanded;
    }
    // Non-template record path
    const root = try parseElementIR(ctx, chunk, &r, ctx.arena.allocator(), .rec);
    const expanded_root = try expandElementWithValues(ctx, root, &[_]TemplateValue{}, ctx.arena.allocator());
    try spliceEvtXmlAll(ctx, chunk, expanded_root, ctx.arena.allocator());
    return expanded_root;
}
