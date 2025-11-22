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

/// Defines the source context for parsing, whether we are parsing a record or a template definition.
pub const Source = enum {
    rec,
    def,
};

/// Parses an element and returns its IR representation.
/// This function is the entry point for parsing a BinXML element.
pub fn parseElementIR(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source) !*IR.Element {
    return parseElementIRBase(ctx, chunk, r, allocator, src, 0);
}

/// Parses an element with an explicit chunk base offset.
/// Useful when parsing elements that are relative to a specific chunk start.
pub fn parseElementIRWithBase(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, src: Source, chunk_base: usize) !*IR.Element {
    return parseElementIRBase(ctx, chunk, r, allocator, src, chunk_base);
}

// --- Template Instance Value Parsing ---

/// Parses the values for a template instance.
/// It reads the descriptor table first, then the value payloads.
pub fn parseTemplateInstanceValues(r: *Reader, allocator: std.mem.Allocator) ![]types.TemplateValue {
    if (r.rem() < 4) return BinXmlError.UnexpectedEof;

    const declared_u32 = try r.readU32le();
    const declared: usize = @intCast(declared_u32);

    if (log.enabled(.trace)) log.trace("tmpl values declared={d}", .{declared});

    if (declared == 0) return allocator.alloc(types.TemplateValue, 0);
    if (r.rem() < 4 * declared) return BinXmlError.UnexpectedEof;

    // Read descriptor table then payloads using small helpers for clarity
    const desc = try readTemplateValueDescriptorTable(r, allocator, declared);
    defer allocator.free(desc.sizes);
    defer allocator.free(desc.vtypes);
    defer allocator.free(desc.reserved);

    return try readTemplateValuesFromDescriptors(r, allocator, desc.sizes, desc.vtypes);
}

const TemplateDescriptors = struct {
    sizes: []u16,
    vtypes: []u8,
    reserved: []u8,
};

fn readTemplateValueDescriptorTable(r: *Reader, allocator: std.mem.Allocator, declared: usize) !TemplateDescriptors {
    var sizes = try allocator.alloc(u16, declared);
    errdefer allocator.free(sizes);
    var vtypes = try allocator.alloc(u8, declared);
    errdefer allocator.free(vtypes);
    var reserved = try allocator.alloc(u8, declared);
    errdefer allocator.free(reserved);

    var i: usize = 0;
    while (i < declared) : (i += 1) {
        const desc = try r.readStruct(types.ValueDescriptor);
        sizes[i] = desc.size;
        vtypes[i] = @intFromEnum(desc.value_type);
        reserved[i] = desc.unknown;
        if (log.enabled(.trace)) log.trace("  desc[{d}]: size={d} type=0x{x} reserved={d}", .{ i, sizes[i], vtypes[i], reserved[i] });
    }
    return .{ .sizes = sizes, .vtypes = vtypes, .reserved = reserved };
}

fn readTemplateValuesFromDescriptors(r: *Reader, allocator: std.mem.Allocator, sizes: []const u16, vtypes: []const u8) ![]types.TemplateValue {
    const declared = sizes.len;
    var values = try allocator.alloc(types.TemplateValue, declared);

    var i: usize = 0;
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
    return values;
}

// --- Core Parsing Logic ---

/// Parses an element in the Intermediate Representation (IR).
/// This is the recursive core of the parser.
fn parseElementIRBase(
    ctx: *Context,
    chunk: []const u8,
    r: *Reader,
    allocator: std.mem.Allocator,
    src: Source,
    chunk_base: usize,
) !*IR.Element {
    const element_start_pos = r.pos;

    if (log.enabled(.trace)) {
        logTraceContext("parseElementIR", src, r, null);
    }

    // 1. Validate OpenStart Token
    const start_token = try r.readU8();
    if (!tokens.isToken(start_token, tokens.TOK_OPEN_START)) {
        return BinXmlError.BadToken;
    }

    // 2. Parse Element Header (Name, DataSize, etc.)
    const header = try parseElementHeaderAndEnd(ctx, chunk, r, allocator, src, chunk_base, element_start_pos);
    const element_end_pos = header.element_end;

    // 3. Create IR Element
    const element = try IRModule.irNewElement(allocator, header.name);

    // 4. Parse Attributes (if present)
    if (tokens.hasMore(start_token, tokens.TOK_OPEN_START)) {
        element.attrs = try parseAttributeListIR(ctx, chunk, r, allocator, src, element_end_pos, chunk_base);

        // Update hints based on attribute values
        for (element.attrs.items) |attr| {
            updateHintsFromNodes(element, attr.value.items, true);
        }
    }

    // 5. Handle Optional Padding (usually null bytes)
    var pad: usize = 0;
    while (pad < 4 and r.pos < element_end_pos and (r.peekByte() catch 0) == 0) : (pad += 1) {
        r.pos += 1;
    }

    // Check for early exit (empty element or EOF)
    if (r.pos >= element_end_pos or r.rem() == 0) {
        return element;
    }

    const pos_before_close = r.pos;
    const close_token = try r.readU8();

    if (log.enabled(.trace)) {
        log.trace("parseElementIR nxt=0x{x} pos=0x{x} end=0x{x}", .{ close_token, r.pos, element_end_pos });
    }

    // 6. Check for CloseEmpty Token
    if (tokens.isToken(close_token, tokens.TOK_CLOSE_EMPTY)) {
        return element;
    }

    // 7. Expect CloseStart Token (start of content)
    if (!tokens.isToken(close_token, tokens.TOK_CLOSE_START)) {
        if (log.enabled(.trace)) {
            logTraceContext("unexpected nxt window", src, r, pos_before_close);
        }
        log.err("expected CloseStart, got 0x{x} at 0x{x}", .{ close_token, r.pos - 1 });
        return BinXmlError.BadToken;
    }

    // 8. Parse Content (Children, Text, Values, etc.)
    while (true) {
        if (r.pos >= element_end_pos or r.rem() == 0) break;

        const token = r.peekByte() catch break;
        if (log.enabled(.trace)) log.trace("content token 0x{x} at 0x{x}/0x{x}", .{ token, r.pos, element_end_pos });

        if (tokens.isToken(token, tokens.TOK_END_ELEMENT)) {
            _ = try r.readU8(); // Consume EndElement
            break;
        } else if (tokens.isToken(token, tokens.TOK_OPEN_START)) {
            // Recursive call for child element
            const child = try parseElementIRBase(ctx, chunk, r, allocator, src, chunk_base);
            try element.children.append(allocator, .{ .tag = .Element, .elem = child });
            element.has_element_child = true;
        } else if (isContentToken(token)) {
            // Accumulate sequence of value/text tokens
            var content_sequence = std.ArrayList(IR.Node).initCapacity(allocator, 0) catch unreachable;
            try collectValueTokensIRWithCtx(ctx, chunk, r, &content_sequence, src, element_end_pos, allocator, chunk_base);

            // Ensure we don't overshoot
            if (r.pos > element_end_pos) r.pos = element_end_pos;

            for (content_sequence.items) |node| {
                try element.children.append(allocator, node);
            }
            updateHintsFromNodes(element, content_sequence.items, false);
        } else {
            break;
        }

        if (r.pos >= element_end_pos) break;
    }

    return element;
}

fn isContentToken(t: u8) bool {
    return tokens.isToken(t, tokens.TOK_VALUE) or
        tokens.isToken(t, tokens.TOK_NORMAL_SUBST) or
        tokens.isToken(t, tokens.TOK_OPTIONAL_SUBST) or
        tokens.isToken(t, tokens.TOK_CDATA) or
        tokens.isToken(t, tokens.TOK_CHARREF) or
        tokens.isToken(t, tokens.TOK_ENTITYREF) or
        tokens.isToken(t, tokens.TOK_PITARGET) or
        tokens.isToken(t, tokens.TOK_PIDATA);
}

/// Parses the attribute list of an element.
fn parseAttributeListIR(
    ctx: *Context,
    chunk: []const u8,
    r: *Reader,
    allocator: std.mem.Allocator,
    src: Source,
    max_end: usize,
    chunk_base: usize,
) !std.ArrayList(IR.Attr) {
    const header = try r.readStruct(types.AttributeListHeader);
    const list_size = header.data_size;
    const list_start = r.pos;
    const list_end = list_start + list_size;

    if (log.enabled(.trace)) {
        log.trace("attr list_start=0x{x} size=0x{x} list_end=0x{x} max_end=0x{x} buf_len=0x{x}", .{ list_start, list_size, list_end, max_end, r.buf.len });
    }

    if (list_end > max_end or list_end < list_start) return BinXmlError.UnexpectedEof;

    var attributes = std.ArrayList(IR.Attr).initCapacity(allocator, 0) catch unreachable;

    // Pre-scan to estimate capacity (optional optimization)
    var scan_pos = r.pos;
    var attr_count: usize = 0;
    while (scan_pos < list_end and scan_pos < r.buf.len and tokens.isToken(r.buf[scan_pos], tokens.TOK_ATTRIBUTE)) : (scan_pos += 1) {
        attr_count += 1;
        break; // Just counting existence of list for now, or use a more robust loop if needed
    }
    if (attr_count > 0) try attributes.ensureTotalCapacityPrecise(allocator, attr_count);

    while (r.pos < list_end and r.rem() > 0 and tokens.isToken(r.peekByte() catch 0, tokens.TOK_ATTRIBUTE)) {
        _ = try r.readU8(); // Consume Attribute Token

        // Parse Attribute Name
        const name = try readNameIRBounded(ctx, chunk, r, allocator, src, list_end, chunk_base);
        if (log.enabled(.trace)) try binxml_name.logNameTrace(name, "attr");

        // Parse Attribute Value (sequence of tokens)
        var value_tokens = std.ArrayList(IR.Node).initCapacity(allocator, 0) catch unreachable;
        try collectValueTokensIRWithCtx(ctx, chunk, r, &value_tokens, src, list_end, allocator, chunk_base);

        try attributes.append(allocator, .{ .name = name, .value = value_tokens });
    }

    // Ensure we are exactly at the end of the list
    if (r.pos != list_end) r.pos = list_end;

    return attributes;
}

/// Collects a sequence of value tokens (Value, Subst, CharRef, etc.) into a list of IR Nodes.
fn collectValueTokensIRWithCtx(
    ctx: *Context,
    chunk: []const u8,
    r: *Reader,
    out: *std.ArrayList(IR.Node),
    src: Source,
    end_pos: usize,
    allocator: std.mem.Allocator,
    chunk_base: usize,
) !void {
    while (true) {
        if (r.rem() == 0 or r.pos >= end_pos) break;

        const pk = r.peekByte() catch break;
        if (log.enabled(.trace)) log.trace("valtok pk=0x{x} at 0x{x}", .{ pk, r.pos });

        // Stop if we hit a structural token
        if (tokens.isToken(pk, tokens.TOK_ATTRIBUTE) or
            tokens.isToken(pk, tokens.TOK_CLOSE_START) or
            tokens.isToken(pk, tokens.TOK_CLOSE_EMPTY))
        {
            break;
        }

        if (tokens.isToken(pk, tokens.TOK_VALUE)) {
            try parseValueToken(r, out, allocator, end_pos, src);
            continue;
        }

        if (tokens.isToken(pk, tokens.TOK_NORMAL_SUBST) or tokens.isToken(pk, tokens.TOK_OPTIONAL_SUBST)) {
            const h = try readHeaderChecked(r, types.SubstitutionHeader, end_pos);
            const optional = tokens.isToken(h.token, tokens.TOK_OPTIONAL_SUBST);
            try out.append(allocator, .{ .tag = .Subst, .subst_id = h.id, .subst_vtype = h.vtype, .subst_optional = optional });
            continue;
        }

        if (tokens.isToken(pk, tokens.TOK_CHARREF)) {
            const h = try readHeaderChecked(r, types.CharRefHeader, end_pos);
            try out.append(allocator, .{ .tag = .CharRef, .charref_value = h.value });
            continue;
        }

        if (tokens.isToken(pk, tokens.TOK_ENTITYREF)) {
            try parseNameToken(.EntityRef, "entity_name", ctx, chunk, r, out, allocator, src, end_pos, chunk_base);
            continue;
        }

        if (tokens.isToken(pk, tokens.TOK_CDATA)) {
            try parseStringToken(.CData, r, out, allocator, end_pos);
            continue;
        }

        if (tokens.isToken(pk, tokens.TOK_PITARGET)) {
            try parseNameToken(.PITarget, "pi_target", ctx, chunk, r, out, allocator, src, end_pos, chunk_base);
            continue;
        }

        if (tokens.isToken(pk, tokens.TOK_PIDATA)) {
            try parseStringToken(.PIData, r, out, allocator, end_pos);
            continue;
        }

        // If none matched, break loop
        break;
    }
}

// --- Individual Token Parsers ---

/// Helper to read a header struct after bounds checking.
fn readHeaderChecked(r: *Reader, comptime H: type, end_pos: usize) !H {
    if (r.pos + @sizeOf(H) > end_pos) return BinXmlError.UnexpectedEof;
    return r.readStruct(H);
}

/// Generic helper for tokens containing a simple Name payload (PITarget, EntityRef).
fn parseNameToken(
    comptime Tag: IR.NodeTag,
    comptime field_name: []const u8,
    ctx: *Context,
    chunk: []const u8,
    r: *Reader,
    out: *std.ArrayList(IR.Node),
    allocator: std.mem.Allocator,
    src: Source,
    end_pos: usize,
    chunk_base: usize,
) !void {
    // All these tokens start with a basic TokenHeader
    _ = try readHeaderChecked(r, types.TokenHeader, end_pos);
    const nm = try readNameIRBounded(ctx, chunk, r, allocator, src, end_pos, chunk_base);

    var node: IR.Node = undefined;
    node = .{ .tag = Tag };
    @field(node, field_name) = nm;
    try out.append(allocator, node);
}

/// Generic helper for tokens containing a string payload (CData, PIData).
fn parseStringToken(
    comptime Tag: IR.NodeTag,
    r: *Reader,
    out: *std.ArrayList(IR.Node),
    allocator: std.mem.Allocator,
    end_pos: usize,
) !void {
    _ = try readHeaderChecked(r, types.TokenHeader, end_pos);
    const data = try r.readLenPrefixedSlice(u16, 2, end_pos);
    try out.append(allocator, .{ .tag = Tag, .text_utf16 = data, .text_num_chars = data.len / 2 });
}

fn parseValueToken(r: *Reader, out: *std.ArrayList(IR.Node), allocator: std.mem.Allocator, end_pos: usize, src: Source) !void {
    const h = try readHeaderChecked(r, types.ValueTokenHeader, end_pos);
    const vtype = h.vtype;

    if (log.enabled(.trace)) log.trace("  vtype=0x{x}", .{vtype});

    // BinXML type (0x21)
    if ((vtype & 0x7f) == 0x21) {
        if (r.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
        const blen = try r.readU16le();
        if (r.pos + @as(usize, blen) > end_pos) return BinXmlError.UnexpectedEof;
        try out.append(allocator, .{ .tag = .Value, .vtype = vtype, .vbytes = r.buf[r.pos .. r.pos + blen] });
        r.pos += blen;
        return;
    }

    // String type (0x01)
    if (vtype == 0x01) {
        const text = try r.readLenPrefixedSlice(u16, 2, end_pos);
        try out.append(allocator, .{ .tag = .Text, .text_utf16 = text, .text_num_chars = text.len / 2 });
        return;
    }

    // Ansi String (0x02)
    if (vtype == 0x02) {
        const payload = try r.readLenPrefixedSlice(u16, 1, end_pos);
        try out.append(allocator, .{ .tag = .Value, .vtype = vtype, .vbytes = payload });
        return;
    }

    // Fixed size types
    if (types.valueTypeFixedSize(vtype)) |sz| {
        const payload = try r.readFixedBytesBounded(sz, end_pos);
        try out.append(allocator, .{ .tag = .Value, .vtype = vtype, .vbytes = payload });
        return;
    }

    // Binary type (0x0e)
    if (vtype == 0x0e) {
        const payload = try r.readLenPrefixedSlice(u16, 1, end_pos);
        try out.append(allocator, .{ .tag = .Value, .vtype = vtype, .vbytes = payload });
        return;
    }

    // SID (0x13)
    if (vtype == 0x13) {
        const payload = try r.readSidBytesBounded(end_pos);
        try out.append(allocator, .{ .tag = .Value, .vtype = vtype, .vbytes = payload });
        return;
    }

    log.err("unknown value vtype=0x{x} at pos=0x{x} src={s}", .{ vtype, r.pos, @tagName(src) });
    return BinXmlError.BadToken;
}

// --- Name Handling Helpers ---

fn readNameIRBounded(
    ctx: *Context,
    chunk: []const u8,
    r: *Reader,
    allocator: std.mem.Allocator,
    src: Source,
    end_pos: usize,
    chunk_base: usize,
) !IR.Name {
    return switch (src) {
        .rec => blk: {
            if (r.pos + 4 > end_pos) break :blk BinXmlError.UnexpectedEof;
            const h = try r.readStruct(types.NameOffsetHeader);
            break :blk try materializeNameFromChunkOffset(ctx, chunk, h.offset);
        },
        .def => try parseDefNameIR(ctx, chunk, r, allocator, chunk_base),
    };
}

fn materializeNameFromChunkOffset(ctx: *Context, chunk: []const u8, off_u32: u32) !IR.Name {
    const off_usize: usize = @intCast(off_u32);
    if (off_usize + 8 > chunk.len) return BinXmlError.UnexpectedEof;

    // Parse name length
    const num_chars = std.mem.readInt(u16, chunk[off_usize + 6 .. off_usize + 8][0..2], .little);
    const str_start = off_usize + 8;
    const byte_len = @as(usize, num_chars) * 2;

    if (str_start + byte_len > chunk.len) return BinXmlError.UnexpectedEof;

    // Adjust length for trailing nulls if necessary
    var take_chars = num_chars;
    if (byte_len >= 2) {
        const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
        if (last == 0 and take_chars > 0) take_chars -= 1;
    }

    // Check cache first
    if (ctx.name_cache.get(off_u32)) |entry| {
        return IR.Name{ .bytes = entry.bytes, .num_chars = entry.num_chars };
    }

    // Allocate and cache new name
    const buf = try ctx.arena.allocator().alloc(u8, take_chars * 2);
    @memcpy(buf, chunk[str_start .. str_start + take_chars * 2]);
    try ctx.name_cache.put(off_u32, @import("context.zig").NameCacheEntry{ .bytes = buf, .num_chars = take_chars });

    return IR.Name{ .bytes = buf, .num_chars = take_chars };
}

fn parseDefNameIR(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, chunk_base: usize) !IR.Name {
    const h = try r.readStruct(types.NameOffsetHeader);
    const name_off = h.offset;

    if (log.enabled(.trace)) log.trace("def name_off=0x{x} cur_after_off=0x{x}", .{ name_off, r.pos });

    const abs_after_off: usize = chunk_base + r.pos;

    // Check for inline name optimization (offset points to current position)
    if (name_off == @as(u32, @intCast(abs_after_off))) {
        const view = try r.readTemplateNameLinkInlineView();
        if (log.enabled(.trace)) log.trace("inline NameLink next+hash read inl_start to end; num={d}", .{view.num_chars});

        const bytes = view.utf16.len;
        const buf = try allocator.alloc(u8, bytes);
        @memcpy(buf, view.utf16);

        return IR.Name{ .bytes = buf, .num_chars = view.num_chars };
    }

    return materializeNameFromChunkOffset(ctx, chunk, name_off);
}

// --- Element Header Parsing ---

const ElementHeader = struct {
    name: IR.Name,
    data_size: u32,
    header_len: usize,
    element_end: usize,
};

fn parseElementHeaderAndEnd(
    ctx: *Context,
    chunk: []const u8,
    r: *Reader,
    allocator: std.mem.Allocator,
    src: Source,
    chunk_base: usize,
    element_start: usize,
) !ElementHeader {
    const hdr = switch (src) {
        .rec => try parseRecElementHeader(ctx, chunk, r, allocator),
        .def => try parseDefElementHeader(ctx, chunk, r, allocator, chunk_base, element_start),
    };

    const element_end = element_start + hdr.header_len + @as(usize, hdr.data_size);

    if (log.enabled(.trace)) {
        log.trace("elem hdr: start=0x{x} header_len=0x{x} data_size=0x{x} end=0x{x} buf_len=0x{x}", .{
            element_start, hdr.header_len, hdr.data_size, element_end, r.buf.len,
        });
    }

    if (element_end > r.buf.len or element_end < element_start) return BinXmlError.UnexpectedEof;

    return .{
        .name = hdr.name,
        .data_size = hdr.data_size,
        .header_len = hdr.header_len,
        .element_end = element_end,
    };
}

const PartialElementHeader = struct {
    name: IR.Name,
    data_size: u32,
    header_len: usize,
};

fn parseRecElementHeader(ctx: *Context, chunk: []const u8, r: *Reader, _: std.mem.Allocator) !PartialElementHeader {
    const h = try r.readStruct(types.ElementStartHeader);
    // Per spec: 1 byte token + 2 bytes dep_id + 4 bytes data_size
    const header_len: usize = 1 + 2 + 4;
    const h2 = try r.readStruct(types.NameOffsetHeader);
    const name_off = h2.offset;
    const name = try materializeNameFromChunkOffset(ctx, chunk, name_off);
    return .{ .name = name, .data_size = h.data_size, .header_len = header_len };
}

fn parseDefElementHeader(ctx: *Context, chunk: []const u8, r: *Reader, allocator: std.mem.Allocator, chunk_base: usize, element_start: usize) !PartialElementHeader {
    _ = element_start;
    const h = try r.readStruct(types.ElementStartHeader);

    if (log.enabled(.trace)) {
        logTraceContext("def pre-name (with dep)", .def, r, null);
    }

    const nm = try parseDefNameIR(ctx, chunk, r, allocator, chunk_base);
    // Per spec: 1 byte token + 2 bytes dep_id + 4 bytes data_size
    const header_len: usize = 1 + 2 + 4;
    return .{ .name = nm, .data_size = h.data_size, .header_len = header_len };
}

// --- Hints & Utils ---

fn updateHintsFromNodes(el: *IR.Element, nodes: []const IR.Node, include_attr: bool) void {
    for (nodes) |nd| {
        switch (nd.tag) {
            .Value => if ((nd.vtype & 0x7f) == 0x21 and nd.vbytes.len > 0) {
                el.has_evtxml_value_in_tree = true;
                if (include_attr) el.has_attr_evtxml_value = true;
            },
            .Subst => {
                const base = nd.subst_vtype & 0x7f;
                if (base == 0x21) {
                    el.has_evtxml_subst_in_tree = true;
                    if (include_attr) el.has_attr_evtxml_subst = true;
                }
            },
            else => {},
        }
    }
}

fn logTraceContext(msg: []const u8, src: Source, r: *Reader, pos_override: ?usize) void {
    const pos = pos_override orelse r.pos;
    var tmp: [24]u8 = undefined;
    const rem = if (pos < r.buf.len) r.buf.len - pos else 0;
    const take = @min(rem, tmp.len);
    @memcpy(tmp[0..take], r.buf[pos .. pos + take]);

    var hex_buf: [48]u8 = undefined;
    log.trace("{s} src={s} pos=0x{x} data: {s}", .{ msg, @tagName(src), pos, fmtHexSliceLower(tmp[0..take], &hex_buf) });
}

fn fmtHexSliceLower(buf: []const u8, out: []u8) []const u8 {
    const hex_chars = "0123456789abcdef";
    for (buf, 0..) |b, i| {
        if (i * 2 + 1 >= out.len) break;
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0xf];
    }
    return out[0..@min(buf.len * 2, out.len)];
}
