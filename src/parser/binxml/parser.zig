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

/// Bundles common parsing state to reduce function signature noise.
pub const ParseState = struct {
    ctx: *Context,
    chunk: []const u8,
    r: *Reader,
    src: Source,
    chunk_base: usize = 0,

    pub fn init(ctx: *Context, chunk: []const u8, r: *Reader, src: Source) ParseState {
        return .{ .ctx = ctx, .chunk = chunk, .r = r, .src = src };
    }

    pub fn withBase(ctx: *Context, chunk: []const u8, r: *Reader, src: Source, chunk_base: usize) ParseState {
        return .{ .ctx = ctx, .chunk = chunk, .r = r, .src = src, .chunk_base = chunk_base };
    }

    /// Returns the arena allocator for all chunk-local allocations.
    inline fn alloc(self: *const ParseState) std.mem.Allocator {
        return self.ctx.arena.allocator();
    }
};

/// Parses an element and returns its IR representation.
/// This function is the entry point for parsing a BinXML element.
/// All allocations use the context's arena allocator.
pub fn parseElementIR(ctx: *Context, chunk: []const u8, r: *Reader, src: Source) !*IR.Element {
    var ps = ParseState.init(ctx, chunk, r, src);
    return parseElementIRImpl(&ps);
}

/// Parses an element with an explicit chunk base offset.
/// Useful when parsing elements that are relative to a specific chunk start.
/// All allocations use the context's arena allocator.
pub fn parseElementIRWithBase(ctx: *Context, chunk: []const u8, r: *Reader, src: Source, chunk_base: usize) !*IR.Element {
    var ps = ParseState.withBase(ctx, chunk, r, src, chunk_base);
    return parseElementIRImpl(&ps);
}

// --- Template Instance Value Parsing ---

/// Parses the values for a template instance.
/// It reads the descriptor table first, then the value payloads.
pub fn parseTemplateInstanceValues(r: *Reader, allocator: std.mem.Allocator) ![]types.TemplateValue {
    if (r.rem() < 4) return BinXmlError.UnexpectedEof;

    const declared_u32 = try r.readInt(u32);
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

    for (0..declared) |i| {
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

    for (sizes, vtypes, 0..) |size, vtype, i| {
        const need: usize = @intCast(size);
        if (r.rem() < need) return BinXmlError.UnexpectedEof;

        const slice = r.buf[r.pos .. r.pos + need];
        r.pos += need;

        values[i] = if (vtype == 0x00)
            .{ .t = 0x00, .data = &[_]u8{} }
        else
            .{ .t = vtype, .data = slice };

        if (log.enabled(.trace)) log.trace("  payload[{d}]: t=0x{x} len={d}", .{ i, vtype, need });
    }
    return values;
}

// --- Core Parsing Logic ---

/// Parses an element in the Intermediate Representation (IR).
/// This is the recursive core of the parser.
fn parseElementIRImpl(ps: *ParseState) !*IR.Element {
    const element_start_pos = ps.r.pos;

    if (log.enabled(.trace)) {
        logTraceContext("parseElementIR", ps.src, ps.r, null);
    }

    // 1. Validate OpenStart Token
    const start_token = try ps.r.readInt(u8);
    if (!tokens.isToken(start_token, tokens.TOK_OPEN_START)) {
        return BinXmlError.BadToken;
    }

    // 2. Parse Element Header (Name, DataSize, etc.)
    const header = try parseElementHeaderAndEnd(ps, element_start_pos);
    const element_end_pos = header.element_end;

    // 3. Create IR Element
    const element = try IRModule.irNewElement(ps.alloc(), header.name);

    // 4. Parse Attributes (if present)
    if (tokens.hasMore(start_token, tokens.TOK_OPEN_START)) {
        element.attrs = try parseAttributeListIR(ps, element_end_pos);
    }

    // 5. Skip padding bytes (NUL bytes between header and content)
    // Bounded to max 4 bytes as per BinXML spec
    for (0..4) |_| {
        if (ps.r.pos >= element_end_pos) break;
        const byte = ps.r.peekByte() catch break;
        if (byte != 0) break;
        ps.r.pos += 1;
    }

    // Check for early exit (empty element or EOF)
    if (ps.r.pos >= element_end_pos or ps.r.rem() == 0) {
        return element;
    }

    const pos_before_close = ps.r.pos;
    const close_token = try ps.r.readInt(u8);

    if (log.enabled(.trace)) {
        log.trace("parseElementIR nxt=0x{x} pos=0x{x} end=0x{x}", .{ close_token, ps.r.pos, element_end_pos });
    }

    // 6. Check for CloseEmpty Token
    if (tokens.isToken(close_token, tokens.TOK_CLOSE_EMPTY)) {
        return element;
    }

    // 7. Expect CloseStart Token (start of content)
    if (!tokens.isToken(close_token, tokens.TOK_CLOSE_START)) {
        if (log.enabled(.trace)) {
            logTraceContext("unexpected nxt window", ps.src, ps.r, pos_before_close);
        }
        log.err("expected CloseStart, got 0x{x} at 0x{x}", .{ close_token, ps.r.pos - 1 });
        return BinXmlError.BadToken;
    }

    // 8. Parse Content (Children, Text, Values, etc.)
    while (ps.r.pos < element_end_pos and ps.r.rem() > 0) {
        const token = ps.r.peekByte() catch break;
        if (log.enabled(.trace)) log.trace("content token 0x{x} at 0x{x}/0x{x}", .{ token, ps.r.pos, element_end_pos });

        switch (token & 0x1f) {
            tokens.TOK_END_ELEMENT => {
                _ = try ps.r.readInt(u8); // Consume EndElement
                break;
            },
            tokens.TOK_OPEN_START => {
                // Recursive call for child element
                const child = try parseElementIRImpl(ps);
                try element.children.append(ps.alloc(), .{ .Element = child });
                element.has_element_child = true;
            },
            tokens.TOK_VALUE, tokens.TOK_NORMAL_SUBST, tokens.TOK_OPTIONAL_SUBST, tokens.TOK_CDATA, tokens.TOK_CHARREF, tokens.TOK_ENTITYREF, tokens.TOK_PITARGET, tokens.TOK_PIDATA => {
                // Accumulate sequence of value/text tokens
                var content_sequence: std.ArrayList(IR.Node) = .empty;
                try collectValueTokens(ps, &content_sequence, element_end_pos);

                // Ensure we don't overshoot
                if (ps.r.pos > element_end_pos) ps.r.pos = element_end_pos;

                for (content_sequence.items) |node| {
                    try element.children.append(ps.alloc(), node);
                }
            },
            else => break,
        }
    }

    return element;
}

/// Parses the attribute list of an element.
fn parseAttributeListIR(ps: *ParseState, max_end: usize) !std.ArrayList(IR.Attr) {
    const header = try ps.r.readStruct(types.AttributeListHeader);
    const list_size = header.data_size;
    const list_start = ps.r.pos;
    const list_end = list_start + list_size;

    if (log.enabled(.trace)) {
        log.trace("attr list_start=0x{x} size=0x{x} list_end=0x{x} max_end=0x{x} buf_len=0x{x}", .{ list_start, list_size, list_end, max_end, ps.r.buf.len });
    }

    if (list_end > max_end or list_end < list_start) return BinXmlError.UnexpectedEof;

    var attributes: std.ArrayList(IR.Attr) = .empty;

    // Pre-scan to estimate capacity (optional optimization)
    var scan_pos = ps.r.pos;
    var attr_count: usize = 0;
    while (scan_pos < list_end and scan_pos < ps.r.buf.len and tokens.isToken(ps.r.buf[scan_pos], tokens.TOK_ATTRIBUTE)) : (scan_pos += 1) {
        attr_count += 1;
        break; // Just counting existence of list for now, or use a more robust loop if needed
    }
    if (attr_count > 0) try attributes.ensureTotalCapacityPrecise(ps.alloc(), attr_count);

    while (ps.r.pos < list_end and ps.r.rem() > 0) {
        const maybe_attr = ps.r.peekByte() catch break;
        if (!tokens.isToken(maybe_attr, tokens.TOK_ATTRIBUTE)) break;
        _ = try ps.r.readInt(u8); // Consume Attribute Token

        // Parse Attribute Name
        const name = try readNameIRBounded(ps, list_end);
        if (log.enabled(.trace)) try binxml_name.logNameTrace(name, "attr");

        // Parse Attribute Value (sequence of tokens)
        var value_tokens: std.ArrayList(IR.Node) = .empty;
        try collectValueTokens(ps, &value_tokens, list_end);

        try attributes.append(ps.alloc(), .{ .name = name, .value = value_tokens });
    }

    // Ensure we are exactly at the end of the list
    if (ps.r.pos != list_end) ps.r.pos = list_end;

    return attributes;
}

/// Collects a sequence of value tokens (Value, Subst, CharRef, etc.) into a list of IR Nodes.
fn collectValueTokens(ps: *ParseState, out: *std.ArrayList(IR.Node), end_pos: usize) !void {
    while (ps.r.rem() > 0 and ps.r.pos < end_pos) {
        const pk = ps.r.peekByte() catch break;
        if (log.enabled(.trace)) log.trace("valtok pk=0x{x} at 0x{x}", .{ pk, ps.r.pos });

        switch (pk & 0x1f) {
            tokens.TOK_ATTRIBUTE, tokens.TOK_CLOSE_START, tokens.TOK_CLOSE_EMPTY => break,
            tokens.TOK_VALUE => {
                try parseValueToken(ps, out, end_pos);
            },
            tokens.TOK_NORMAL_SUBST, tokens.TOK_OPTIONAL_SUBST => {
                const h = try readHeaderChecked(ps.r, types.SubstitutionHeader, end_pos);
                const optional = tokens.isToken(h.token, tokens.TOK_OPTIONAL_SUBST);
                try out.append(ps.alloc(), .{ .Subst = .{ .id = h.id, .vtype = h.vtype, .optional = optional } });
            },
            tokens.TOK_CHARREF => {
                const h = try readHeaderChecked(ps.r, types.CharRefHeader, end_pos);
                try out.append(ps.alloc(), .{ .CharRef = h.value });
            },
            tokens.TOK_ENTITYREF => {
                try parseNameToken(.EntityRef, ps, out, end_pos);
            },
            tokens.TOK_CDATA => {
                try parseStringToken(.CData, ps.r, out, ps.alloc(), end_pos);
            },
            tokens.TOK_PITARGET => {
                try parseNameToken(.PITarget, ps, out, end_pos);
            },
            tokens.TOK_PIDATA => {
                try parseStringToken(.PIData, ps.r, out, ps.alloc(), end_pos);
            },
            else => break,
        }
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
    ps: *ParseState,
    out: *std.ArrayList(IR.Node),
    end_pos: usize,
) !void {
    // All these tokens start with a basic TokenHeader
    _ = try readHeaderChecked(ps.r, types.TokenHeader, end_pos);
    const nm = try readNameIRBounded(ps, end_pos);

    const node: IR.Node = switch (Tag) {
        .EntityRef => .{ .EntityRef = nm },
        .PITarget => .{ .PITarget = nm },
        else => @compileError("parseNameToken only supports EntityRef and PITarget"),
    };
    try out.append(ps.alloc(), node);
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
    const payload = IR.TextPayload{ .utf16 = data, .num_chars = data.len / 2 };
    const node: IR.Node = switch (Tag) {
        .CData => .{ .CData = payload },
        .PIData => .{ .PIData = payload },
        else => @compileError("parseStringToken only supports CData and PIData"),
    };
    try out.append(allocator, node);
}

fn parseValueToken(ps: *ParseState, out: *std.ArrayList(IR.Node), end_pos: usize) !void {
    const h = try readHeaderChecked(ps.r, types.ValueTokenHeader, end_pos);
    const vtype = h.vtype;

    if (log.enabled(.trace)) log.trace("  vtype=0x{x}", .{vtype});

    // BinXML type (0x21) or Array (0xA1)
    if ((vtype & 0x7f) == 0x21) {
        if (ps.r.pos + 2 > end_pos) return BinXmlError.UnexpectedEof;
        const blen = try ps.r.readInt(u16);
        if (ps.r.pos + @as(usize, blen) > end_pos) return BinXmlError.UnexpectedEof;
        try out.append(ps.alloc(), .{ .Value = .{ .vtype = vtype, .bytes = ps.r.buf[ps.r.pos .. ps.r.pos + blen] } });
        ps.r.pos += blen;
        return;
    }

    switch (vtype) {
        0x01 => { // String
            const text = try ps.r.readLenPrefixedSlice(u16, 2, end_pos);
            try out.append(ps.alloc(), .{ .Text = .{ .utf16 = text, .num_chars = text.len / 2 } });
        },
        0x02, 0x0e => { // Ansi String, Binary
            const payload = try ps.r.readLenPrefixedSlice(u16, 1, end_pos);
            try out.append(ps.alloc(), .{ .Value = .{ .vtype = vtype, .bytes = payload } });
        },
        0x13 => { // SID
            const payload = try ps.r.readSidBytesBounded(end_pos);
            try out.append(ps.alloc(), .{ .Value = .{ .vtype = vtype, .bytes = payload } });
        },
        else => {
            if (types.valueTypeFixedSize(vtype)) |sz| {
                const payload = try ps.r.readFixedBytesBounded(sz, end_pos);
                try out.append(ps.alloc(), .{ .Value = .{ .vtype = vtype, .bytes = payload } });
            } else {
                log.err("unknown value vtype=0x{x} at pos=0x{x} src={s}", .{ vtype, ps.r.pos, @tagName(ps.src) });
                return BinXmlError.BadToken;
            }
        },
    }
}

// --- Name Handling Helpers ---

fn readNameIRBounded(ps: *ParseState, end_pos: usize) !IR.Name {
    return switch (ps.src) {
        .rec => blk: {
            if (ps.r.pos + 4 > end_pos) break :blk BinXmlError.UnexpectedEof;
            const h = try ps.r.readStruct(types.NameOffsetHeader);
            break :blk try ps.ctx.getOrReadName(ps.chunk, h.offset);
        },
        .def => try parseDefNameIR(ps),
    };
}

fn parseDefNameIR(ps: *ParseState) !IR.Name {
    const h = try ps.r.readStruct(types.NameOffsetHeader);
    const name_off = h.offset;

    if (log.enabled(.trace)) log.trace("def name_off=0x{x} cur_after_off=0x{x}", .{ name_off, ps.r.pos });

    const abs_after_off: usize = ps.chunk_base + ps.r.pos;

    // Check for inline name optimization (offset points to current position)
    if (name_off == @as(u32, @intCast(abs_after_off))) {
        const view = try ps.r.readTemplateNameLinkInlineView();
        if (log.enabled(.trace)) log.trace("inline NameLink next+hash read inl_start to end; num={d}", .{view.num_chars});

        const bytes = view.utf16.len;
        const buf = try ps.alloc().alloc(u8, bytes);
        @memcpy(buf, view.utf16);

        return IR.Name{ .bytes = buf, .num_chars = view.num_chars };
    }

    return ps.ctx.getOrReadName(ps.chunk, name_off);
}

// --- Element Header Parsing ---

const ElementHeader = struct {
    name: IR.Name,
    data_size: u32,
    header_len: usize,
    element_end: usize,
};

fn parseElementHeaderAndEnd(ps: *ParseState, element_start: usize) !ElementHeader {
    const hdr = switch (ps.src) {
        .rec => try parseRecElementHeader(ps),
        .def => try parseDefElementHeader(ps),
    };

    const element_end = element_start + hdr.header_len + @as(usize, hdr.data_size);

    if (log.enabled(.trace)) {
        log.trace("elem hdr: start=0x{x} header_len=0x{x} data_size=0x{x} end=0x{x} buf_len=0x{x}", .{
            element_start, hdr.header_len, hdr.data_size, element_end, ps.r.buf.len,
        });
    }

    if (element_end > ps.r.buf.len or element_end < element_start) return BinXmlError.UnexpectedEof;

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

fn parseRecElementHeader(ps: *ParseState) !PartialElementHeader {
    const h = try ps.r.readStruct(types.ElementStartHeader);
    // Per spec: 1 byte token + 2 bytes dep_id + 4 bytes data_size
    const header_len: usize = 1 + 2 + 4;
    const h2 = try ps.r.readStruct(types.NameOffsetHeader);
    const name_off = h2.offset;
    const name = try ps.ctx.getOrReadName(ps.chunk, name_off);
    return .{ .name = name, .data_size = h.data_size, .header_len = header_len };
}

fn parseDefElementHeader(ps: *ParseState) !PartialElementHeader {
    const h = try ps.r.readStruct(types.ElementStartHeader);

    if (log.enabled(.trace)) {
        logTraceContext("def pre-name (with dep)", .def, ps.r, null);
    }

    const nm = try parseDefNameIR(ps);
    // Per spec: 1 byte token + 2 bytes dep_id + 4 bytes data_size
    const header_len: usize = 1 + 2 + 4;
    return .{ .name = nm, .data_size = h.data_size, .header_len = header_len };
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
