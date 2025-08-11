const std = @import("std");
const Reader = @import("../reader.zig").Reader;
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const Context = @import("context.zig").Context;
const types = @import("types.zig");
const BinXmlError = @import("../err.zig").BinXmlError;
const logger = @import("../../logger.zig");
const log = logger.scoped("binxml");
const tokens = @import("tokens.zig");
const util = @import("../util.zig");
const utf16EqualsAscii = util.utf16EqualsAscii;
const binxml_name = @import("name.zig");
const common = @import("common.zig");

// Temporary wrapper Parser that forwards to existing functions in binxml.zig.
// This allows incremental migration without breaking call sites or logs.

pub const Source = enum { rec, def };

pub const Parser = struct {
    ctx: *Context,
    allocator: std.mem.Allocator,

    pub fn init(ctx: *Context, allocator: std.mem.Allocator) Parser {
        return .{ .ctx = ctx, .allocator = allocator };
    }

    pub fn parseElementIR(self: *Parser, chunk: []const u8, r: *Reader, src: Source) !*IR.Element {
        return parseElementIRBase(self.ctx, chunk, r, self.allocator, src, 0);
    }

    pub fn parseElementIRWithBase(self: *Parser, chunk: []const u8, r: *Reader, src: Source, chunk_base: usize) !*IR.Element {
        return parseElementIRBase(self.ctx, chunk, r, self.allocator, src, chunk_base);
    }

    pub fn parseTemplateInstanceValues(self: *Parser, r: *Reader, expected: usize) ![]types.TemplateValue {
        _ = self;
        // Forward to core function for now
        return parseTemplateInstanceValuesExpected(r, std.heap.c_allocator, expected);
    }
};

// Pure helpers lifted from core for incremental migration

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

pub fn parseTemplateInstanceValuesExpected(r: *Reader, allocator: std.mem.Allocator, expected: usize) ![]types.TemplateValue {
    if (r.rem() < 4) return BinXmlError.UnexpectedEof;
    const declared_u32 = try r.readU32le();
    const declared: usize = @intCast(declared_u32);
    _ = expected; // trust declared count per spec (Rust behavior)
    if (log.enabled(.trace)) log.trace("tmpl values declared={d}", .{declared});
    if (declared == 0) return allocator.alloc(types.TemplateValue, 0);
    if (r.rem() < 4 * declared) return BinXmlError.UnexpectedEof;
    // Read descriptor table
    var sizes = try allocator.alloc(u16, declared);
    errdefer allocator.free(sizes);
    var vtypes = try allocator.alloc(u8, declared);
    errdefer allocator.free(vtypes);
    var reserved = try allocator.alloc(u8, declared);
    errdefer allocator.free(reserved);
    var i: usize = 0;
    while (i < declared) : (i += 1) {
        sizes[i] = try r.readU16le();
        vtypes[i] = try r.readU8();
        reserved[i] = try r.readU8();
        if (log.enabled(.trace)) log.trace("  desc[{d}]: size={d} type=0x{x} reserved={d}", .{ i, sizes[i], vtypes[i], reserved[i] });
    }
    // Payloads
    var values = try allocator.alloc(types.TemplateValue, declared);
    i = 0;
    while (i < declared) : (i += 1) {
        const need: usize = @intCast(sizes[i]);
        if (r.rem() < need) return BinXmlError.UnexpectedEof;
        const slice = r.buf[r.pos .. r.pos + need];
        r.pos += need;
        if (vtypes[i] == 0x00) {
            values[i] = .{ .t = 0x00, .data = &[_]u8{} };
        } else {
            values[i] = .{ .t = vtypes[i], .data = slice };
        }
        if (log.enabled(.trace)) log.trace("  payload[{d}]: t=0x{x} len={d}", .{ i, vtypes[i], need });
    }
    allocator.free(sizes);
    allocator.free(vtypes);
    allocator.free(reserved);
    return values;
}

// --- Parsing helpers (local copies for incremental migration) ---

// helpers moved to common.zig

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
    try ctx.name_cache.put(off_u32, @import("context.zig").NameCacheEntry{ .bytes = buf, .num_chars = take_chars });
    return IR.Name{ .InlineUtf16 = .{ .bytes = buf, .num_chars = take_chars } };
}

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
        if (r.rem() < 2) return BinXmlError.UnexpectedEof;
        const num = try r.readU16le();
        const bytes = @as(usize, num) * 2;
        if (log.enabled(.trace)) log.trace("inline name num={d} r.pos=0x{x}", .{ num, r.pos });
        if (r.rem() < bytes) return BinXmlError.UnexpectedEof;
        const slice_src = r.buf[r.pos .. r.pos + bytes];
        r.pos += bytes;
        const want_end = inl_start + 6 + @as(usize, num) * 2 + 4;
        if (log.enabled(.trace)) log.trace("inline name end want=0x{x} now=0x{x}", .{ want_end, r.pos });
        if (r.pos < want_end and want_end <= r.buf.len) r.pos = want_end;
        const buf = try allocator.alloc(u8, bytes);
        @memcpy(buf, slice_src);
        return IR.Name{ .InlineUtf16 = .{ .bytes = buf, .num_chars = @intCast(num) } };
    }
    return materializeNameFromChunkOffset(ctx, chunk, name_off);
}

fn readInlineNameDefFlexibleAlloc(r: *Reader, alloc: std.mem.Allocator) !struct { bytes: []u8, num_chars: usize } {
    if (r.rem() >= 4) {
        const saveA = r.pos;
        _ = try r.readU16le();
        const numA = try r.readU16le();
        const bytesA = @as(usize, numA) * 2;
        if (numA > 0 and r.rem() >= bytesA and r.pos + bytesA <= r.buf.len) {
            const sliceA_src = r.buf[r.pos .. r.pos + bytesA];
            r.pos += bytesA;
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
    if (r.rem() >= 2) {
        const saveB = r.pos;
        const numB = try r.readU16le();
        const bytesB = @as(usize, numB) * 2;
        if (numB > 0 and r.rem() >= bytesB and r.pos + bytesB <= r.buf.len) {
            const sliceB_src = r.buf[r.pos .. r.pos + bytesB];
            r.pos += bytesB;
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
    return BinXmlError.UnexpectedEof;
}

fn parseInlineNameFlexibleIR(r: *Reader, alloc: std.mem.Allocator) !IR.Name {
    const nm = try readInlineNameDefFlexibleAlloc(r, alloc);
    return IR.Name{ .InlineUtf16 = .{ .bytes = nm.bytes, .num_chars = nm.num_chars } };
}

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

const ElementHeader = struct { name: IR.Name, data_size: u32, header_len: usize };

fn parseRecElementHeader(ctx: *Context, chunk: []const u8, r: *Reader, _: std.mem.Allocator) !ElementHeader {
    _ = try r.readU16le();
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

fn parseElementHeaderAndEnd(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source, chunk_base: usize, element_start: usize) !struct { name: IR.Name, element_end: usize } {
    const hdr = switch (src) {
        .rec => try parseRecElementHeader(ctx, chunk, r, allocator),
        .def => try parseDefElementHeader(ctx, chunk, r, allocator, chunk_base, element_start),
    };
    const element_end = element_start + hdr.header_len + @as(usize, hdr.data_size);
    if (element_end > r.buf.len or element_end < element_start) return BinXmlError.UnexpectedEof;
    return .{ .name = hdr.name, .element_end = element_end };
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
                _ = is_arr;
            },
            else => {},
        }
    }
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
    if (!tokens.isToken(start, tokens.TOK_OPEN_START)) return BinXmlError.BadToken;
    const hdr = try parseElementHeaderAndEnd(ctx, chunk, r, allocator, src, chunk_base, element_start);
    const name = hdr.name;
    const element_end = hdr.element_end;
    const el = try IRModule.irNewElement(allocator, name);
    if (tokens.hasMore(start, tokens.TOK_OPEN_START)) {
        el.attrs = try parseAttributeListIR(ctx, chunk, r, allocator, src, element_end, chunk_base);
        var ai_h: usize = 0;
        while (ai_h < el.attrs.items.len) : (ai_h += 1) updateHintsFromNodes(el, el.attrs.items[ai_h].value.items, true);
    }
    var pad: usize = 0;
    while (pad < 4 and r.pos < element_end and r.buf[r.pos] == 0) : (pad += 1) r.pos += 1;
    if (r.pos >= element_end or r.rem() == 0) return el;
    const prev_pos = r.pos;
    const nxt = try r.readU8();
    if (log.enabled(.trace)) log.trace("parseElementIR nxt=0x{x} pos=0x{x} end=0x{x}", .{ nxt, r.pos, element_end });
    if (tokens.isToken(nxt, tokens.TOK_CLOSE_EMPTY)) return el;
    if (!tokens.isToken(nxt, tokens.TOK_CLOSE_START)) {
        if (log.enabled(.trace)) {
            var tmp2: [64]u8 = undefined;
            const win_start = if (prev_pos >= 16) prev_pos - 16 else 0;
            const win_end = @min(element_end, win_start + tmp2.len);
            const take2 = win_end - win_start;
            @memcpy(tmp2[0..take2], r.buf[win_start .. win_start + take2]);
            log.trace("unexpected nxt window [0x{x}..0x{x}): {s}", .{ win_start, win_end, std.fmt.fmtSliceHexLower(tmp2[0..take2]) });
        }
        log.err("expected CloseStart, got 0x{x} at 0x{x}", .{ nxt, r.pos - 1 });
        return BinXmlError.BadToken;
    }
    while (true) {
        if (r.pos >= element_end or r.rem() == 0) break;
        const t = r.buf[r.pos];
        if (log.enabled(.trace)) log.trace("content token 0x{x} at 0x{x}/0x{x}", .{ t, r.pos, element_end });
        if (tokens.isToken(t, tokens.TOK_END_ELEMENT)) {
            _ = try r.readU8();
            break;
        } else if (tokens.isToken(t, tokens.TOK_OPEN_START)) {
            const child = try parseElementIRBase(ctx, chunk, r, allocator, src, chunk_base);
            try el.children.append(.{ .tag = .Element, .elem = child });
            el.has_element_child = true;
        } else if (tokens.isToken(t, tokens.TOK_VALUE) or tokens.isToken(t, tokens.TOK_NORMAL_SUBST) or tokens.isToken(t, tokens.TOK_OPTIONAL_SUBST) or tokens.isToken(t, tokens.TOK_CDATA) or tokens.isToken(t, tokens.TOK_CHARREF) or tokens.isToken(t, tokens.TOK_ENTITYREF) or tokens.isToken(t, tokens.TOK_PITARGET) or tokens.isToken(t, tokens.TOK_PIDATA)) {
            var seq = std.ArrayList(IR.Node).init(allocator);
            try collectValueTokensIRWithCtx(ctx, chunk, r, &seq, src, element_end, allocator, chunk_base);
            if (r.pos > element_end) r.pos = element_end;
            for (seq.items) |nd| try el.children.append(nd);
            updateHintsFromNodes(el, seq.items, false);
        } else break;
        if (r.pos >= element_end) break;
    }
    return el;
}

fn parseAttributeListIR(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source, max_end: usize, chunk_base: usize) !std.ArrayList(IR.Attr) {
    const list_size = try r.readU32le();
    const list_start = r.pos;
    const list_end = list_start + list_size;
    if (list_end > max_end or list_end < list_start) return BinXmlError.UnexpectedEof;
    var out = std.ArrayList(IR.Attr).init(allocator);
    var scan_pos = r.pos;
    var attr_count: usize = 0;
    while (scan_pos < list_end and scan_pos < r.buf.len and tokens.isToken(r.buf[scan_pos], tokens.TOK_ATTRIBUTE)) : (scan_pos += 1) {
        attr_count += 1;
        break;
    }
    if (attr_count > 0) try out.ensureTotalCapacityPrecise(attr_count);
    while (r.pos < list_end and r.rem() > 0 and tokens.isToken(r.buf[r.pos], tokens.TOK_ATTRIBUTE)) {
        _ = try r.readU8();
        var name: IR.Name = undefined;
        name = try readNameIRBounded(ctx, chunk, r, allocator, src, list_end, chunk_base);
        if (log.enabled(.trace)) try binxml_name.logNameTrace(chunk, name, "attr");
        var value_tokens = std.ArrayList(IR.Node).init(allocator);
        try collectValueTokensIRWithCtx(ctx, chunk, r, &value_tokens, src, list_end, allocator, chunk_base);
        try out.append(.{ .name = name, .value = value_tokens });
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
        if (tokens.isToken(pk, tokens.TOK_ATTRIBUTE) or tokens.isToken(pk, tokens.TOK_CLOSE_START) or tokens.isToken(pk, tokens.TOK_CLOSE_EMPTY)) break;
        if (tokens.isToken(pk, tokens.TOK_VALUE)) {
            _ = try r.readU8();
            const vtype = try r.readU8();
            if (log.enabled(.trace)) log.trace("  vtype=0x{x}", .{vtype});
            if ((vtype & 0x7f) == 0x21) {
                if (r.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
                const blen = try r.readU16le();
                if (r.pos + @as(usize, blen) > end_pos) return BinXmlError.UnexpectedEof;
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = r.buf[r.pos .. r.pos + blen] });
                r.pos += blen;
            } else if (vtype == 0x01) {
                const text = try r.readUnicodeTextStringBounded(end_pos);
                try out.append(.{ .tag = .Text, .text_utf16 = text, .text_num_chars = text.len / 2 });
            } else if (vtype == 0x02) {
                const payload = try r.readLenPrefixedBytes16Bounded(end_pos);
                try out.append(.{ .tag = .Value, .vtype = vtype, .vbytes = payload, .pad_width = if (want_pad2) 2 else 0 });
                want_pad2 = false;
            } else if (types.valueTypeFixedSize(vtype)) |sz| {
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
        } else if (tokens.isToken(pk, tokens.TOK_NORMAL_SUBST) or tokens.isToken(pk, tokens.TOK_OPTIONAL_SUBST)) {
            const optional = tokens.isToken(pk, tokens.TOK_OPTIONAL_SUBST);
            _ = try r.readU8();
            if (r.pos + 2 + 1 > end_pos) return BinXmlError.UnexpectedEof;
            const id = try r.readU16le();
            const vtype = try r.readU8();
            try out.append(.{ .tag = .Subst, .subst_id = id, .subst_vtype = vtype, .subst_optional = optional, .pad_width = if (want_pad2) 2 else 0 });
            want_pad2 = false;
            continue;
        } else if (tokens.isToken(pk, tokens.TOK_CHARREF)) {
            _ = try r.readU8();
            if (r.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
            const v = try r.readU16le();
            try out.append(.{ .tag = .CharRef, .charref_value = v });
            continue;
        } else if (tokens.isToken(pk, tokens.TOK_ENTITYREF)) {
            _ = try r.readU8();
            const nm = try readNameIRBounded(ctx, chunk, r, allocator, src, end_pos, chunk_base);
            try out.append(.{ .tag = .EntityRef, .entity_name = nm });
            continue;
        } else if (tokens.isToken(pk, tokens.TOK_CDATA)) {
            _ = try r.readU8();
            const data = try r.readUnicodeTextStringBounded(end_pos);
            try out.append(.{ .tag = .CData, .text_utf16 = data, .text_num_chars = data.len / 2 });
            continue;
        } else if (tokens.isToken(pk, tokens.TOK_PITARGET)) {
            _ = try r.readU8();
            const nm = try readNameIRBounded(ctx, chunk, r, allocator, src, end_pos, chunk_base);
            try out.append(.{ .tag = .PITarget, .pi_target = nm });
            continue;
        } else if (tokens.isToken(pk, tokens.TOK_PIDATA)) {
            _ = try r.readU8();
            const data = try r.readUnicodeTextStringBounded(end_pos);
            try out.append(.{ .tag = .PIData, .text_utf16 = data, .text_num_chars = data.len / 2 });
            continue;
        } else break;
    }
}
