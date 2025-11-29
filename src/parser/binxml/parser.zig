const std = @import("std");
const Reader = @import("../reader.zig").Reader;
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const context_mod = @import("context.zig");
const Context = context_mod.Context;
const Template = context_mod.Template;
const ElementTree = context_mod.ElementTree;
const types = @import("types.zig");
const BinXmlError = @import("../err.zig").BinXmlError;
const logger = @import("../../logger.zig");
const log = logger.scoped("binxml");
const tokens = @import("tokens.zig");
const util = @import("../util.zig");
const utf16EqualsAscii = util.utf16EqualsAscii;
const binxml_name = @import("name.zig");
const common = @import("common.zig");

/// Context required for parsing BinXML elements.
///
/// BinXML element headers have two variations based on where they appear:
/// - **Template definitions**: headers include a dependency ID (2 bytes)
/// - **Direct elements**: headers omit the dependency ID
///
/// Additionally, element names can be stored inline or referenced by offset:
/// - **Inline**: name immediately follows the offset field (offset == current chunk position)
/// - **Offset-based**: name is stored elsewhere in the chunk
///
/// This context provides the information needed to handle both variations automatically.
pub const ElementContext = struct {
    /// Absolute offset where this BinXML data starts within the chunk.
    /// Used to determine if name offsets point to inline names (offset == chunk_base + reader.pos)
    /// or to names stored elsewhere in the chunk.
    chunk_base: usize,

    /// Whether element headers contain a dependency ID field.
    /// True for template definitions, false for direct record elements.
    has_dep_id: bool,

    /// Whether we're parsing a template definition (for caching).
    /// When true, substitution tokens become Placeholder nodes.
    /// When false, substitution tokens are an error (shouldn't appear outside templates).
    parsing_template_def: bool = false,
};

/// Bundles common parsing state to reduce function signature noise.
pub const ParseState = struct {
    ctx: *Context,
    chunk: []const u8,
    r: *Reader,
    chunk_base: usize,
    has_dep_id: bool,
    parsing_template_def: bool,

    pub fn init(ctx: *Context, chunk: []const u8, r: *Reader, elem_ctx: ElementContext) ParseState {
        return .{
            .ctx = ctx,
            .chunk = chunk,
            .r = r,
            .chunk_base = elem_ctx.chunk_base,
            .has_dep_id = elem_ctx.has_dep_id,
            .parsing_template_def = elem_ctx.parsing_template_def,
        };
    }

    /// Returns the arena allocator for all chunk-local allocations.
    inline fn alloc(self: *const ParseState) std.mem.Allocator {
        return self.ctx.arena.allocator();
    }
};

/// Parses an element and returns its IR representation.
/// This function is the entry point for parsing a BinXML element.
/// All allocations use the context's arena allocator.
pub fn parseElementIR(ctx: *Context, chunk: []const u8, r: *Reader, elem_ctx: ElementContext) !*IR.Element {
    var ps = ParseState.init(ctx, chunk, r, elem_ctx);
    return parseElementIRImpl(&ps);
}

// Comptime UTF-16LE literal for empty event creation
const event_name_utf16: []const u8 = &[_]u8{ 'E', 0, 'v', 0, 'e', 0, 'n', 0, 't', 0 };

/// Main entry point: parses a BinXML record into a fully resolved ElementTree.
///
/// This is the unified parsing function that handles both template instances
/// and direct elements. Template definitions are cached and instantiated.
///
/// Returns an ElementTree which is guaranteed to have no Placeholder nodes.
///
/// Arguments:
/// - `ctx`: Parser context with template cache and arena allocator
/// - `chunk`: The full 64KB chunk data (needed for offset-based lookups)
/// - `bin`: The specific slice containing this record's BinXML data
pub fn parseRecord(ctx: *Context, chunk: []const u8, bin: []const u8) !ElementTree {
    const allocator = ctx.arena.allocator();

    // Skip fragment header if present
    const start_offset = common.skipFragmentHeader(bin, 0);

    // Handle empty event case
    if (start_offset >= bin.len) {
        const el = try IRModule.irNewElement(allocator, IR.Name{ .bytes = event_name_utf16, .num_chars = 5 });
        return .{ .element = el };
    }

    // Check first token to determine path
    const first_token = bin[start_offset];

    if (tokens.isToken(first_token, tokens.TOK_TEMPLATE_INSTANCE)) {
        // Template instance - get cached template and instantiate
        return parseTemplateInstance(ctx, chunk, bin, start_offset);
    }

    // Direct element - parse without template context (no placeholders)
    const chunk_base = @intFromPtr(bin.ptr) - @intFromPtr(chunk.ptr);
    var r = Reader.init(bin);
    r.pos = start_offset;
    const el = try parseElementIR(ctx, chunk, &r, .{
        .chunk_base = chunk_base,
        .has_dep_id = false,
        .parsing_template_def = false,
    });
    return .{ .element = el };
}

// --- Template Instance Parsing ---

/// Parses a template instance by getting/caching the template and instantiating it.
///
/// This function handles the complete template instantiation flow:
/// 1. Read template instance header
/// 2. Calculate values offset (deterministic, no skipping)
/// 3. Parse substitution values
/// 4. Get or parse template definition (cached as Template with Placeholder nodes)
/// 5. Instantiate template with values to get ElementTree (all placeholders resolved)
///
/// Nested template instances (type 0x21 values containing templates) are
/// handled recursively during instantiation.
fn parseTemplateInstance(ctx: *Context, chunk: []const u8, bin: []const u8, start_offset: usize) !ElementTree {
    const allocator = ctx.arena.allocator();

    // Create a reader for the BinXML slice starting at the template instance
    var r = Reader.init(bin[start_offset..]);

    // Read template instance header using proper struct reading
    const header = try r.readStruct(types.TemplateInstanceStart);

    if ((header.token & 0x1f) != tokens.TOK_TEMPLATE_INSTANCE) {
        return error.BadToken;
    }

    // Calculate where substitution values start (deterministic)
    // chunk_base: where bin starts within chunk
    // r.pos: how many bytes we've read (the header size as determined by Reader)
    const chunk_base = @intFromPtr(bin.ptr) - @intFromPtr(chunk.ptr);
    const after_header = chunk_base + start_offset + r.pos;
    const values_offset = common.calcValuesOffset(chunk, after_header, header.def_data_off);

    if (values_offset >= chunk.len) {
        log.err("parseTemplateInstance: values_offset 0x{x} >= chunk.len 0x{x}", .{ values_offset, chunk.len });
        return error.OutOfBounds;
    }

    // Parse substitution values
    var values_r = Reader.init(chunk[values_offset..]);
    const values = try parseTemplateInstanceValues(&values_r, allocator);

    // Get or parse template definition (cached with Placeholder nodes)
    const template = try getOrCacheTemplate(ctx, chunk, header.def_data_off);

    // Instantiate template: clone and resolve all placeholders
    return template.instantiate(values, chunk, ctx);
}

/// Gets or parses and caches a template definition.
/// Returns a Template containing the parsed IR with Placeholder nodes for substitutions.
fn getOrCacheTemplate(ctx: *Context, chunk: []const u8, def_data_off: u32) !Template {
    const key = makeDefCacheKey(chunk, def_data_off);
    const got = try ctx.cache.getOrPut(key);

    if (!got.found_existing) {
        // Parse template definition with Placeholder nodes
        const off: usize = @intCast(def_data_off);
        if (off + @sizeOf(types.TemplateDefinitionHeader) > chunk.len) {
            return error.OutOfBounds;
        }

        const data_size = common.readTemplateDefSize(chunk, def_data_off);
        const data_start = off + 24; // Header is 24 bytes

        if (data_start + data_size > chunk.len) {
            return error.OutOfBounds;
        }

        // Parse template definition data
        const def_data = chunk[data_start .. data_start + data_size];
        var def_r = Reader.init(def_data);

        // Skip fragment header if present
        const frag_offset = common.skipFragmentHeader(def_data, 0);
        def_r.pos = frag_offset;

        // Parse with parsing_template_def=true so substitutions become Placeholder nodes
        const root = try parseElementIR(ctx, chunk, &def_r, .{
            .chunk_base = data_start,
            .has_dep_id = true, // Template definitions include dependency IDs
            .parsing_template_def = true,
        });

        got.value_ptr.* = .{ .root = root };
    }

    return got.value_ptr.*;
}

/// Creates a cache key for template definitions.
/// Uses offset + GUID to ensure uniqueness across different template definitions.
fn makeDefCacheKey(chunk: []const u8, def_data_off: u32) Context.DefKey {
    var guid: [16]u8 = undefined;
    const base: usize = @intCast(def_data_off);
    // GUID is at offset 4 in TemplateDefinitionHeader (after next_offset u32)
    const guid_slice = chunk[base + 4 .. base + 20];
    @memcpy(guid[0..], guid_slice);
    return .{ .def_data_off = def_data_off, .guid = guid };
}

// --- Template Instance Value Parsing ---

/// Parses the values for a template instance.
/// Single-pass: reads descriptor table to compute payload offset, then reads values directly.
/// This avoids allocating intermediate arrays for sizes/vtypes.
pub fn parseTemplateInstanceValues(r: *Reader, allocator: std.mem.Allocator) ![]types.TemplateValue {
    if (r.rem() < 4) return BinXmlError.UnexpectedEof;

    const declared_u32 = try r.readInt(u32);
    const declared: usize = @intCast(declared_u32);

    if (log.enabled(.trace)) log.trace("tmpl values declared={d}", .{declared});

    if (declared == 0) return allocator.alloc(types.TemplateValue, 0);

    // Descriptor table is 4 bytes per entry (2 size + 1 type + 1 reserved)
    const desc_table_size = declared * @sizeOf(types.ValueDescriptor);
    if (r.rem() < desc_table_size) return BinXmlError.UnexpectedEof;

    // Remember where descriptor table starts - we'll read from it while parsing values
    const desc_table_start = r.pos;

    // Skip past descriptor table to position at payloads
    r.pos += desc_table_size;

    // Allocate only the final values array
    var values = try allocator.alloc(types.TemplateValue, declared);
    errdefer allocator.free(values);

    // Single pass: for each value, read its descriptor from the table, then read payload
    for (0..declared) |i| {
        // Read descriptor from table (4 bytes each)
        const desc_offset = desc_table_start + i * @sizeOf(types.ValueDescriptor);
        const size = std.mem.readInt(u16, r.buf[desc_offset..][0..2], .little);
        const vtype = r.buf[desc_offset + 2];
        // Note: desc_offset + 3 is reserved/unused byte - we skip it entirely

        if (log.enabled(.trace)) log.trace("  desc[{d}]: size={d} type=0x{x}", .{ i, size, vtype });

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
        logTraceContext("parseElementIR", ps.r, null);
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
            logTraceContext("unexpected nxt window", ps.r, pos_before_close);
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
/// When parsing_template_def is true, substitution tokens become Placeholder nodes.
/// When parsing_template_def is false, substitution tokens are an error.
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

                if (ps.parsing_template_def) {
                    // Create Placeholder node for later resolution during instantiation
                    try out.append(ps.alloc(), .{
                        .Placeholder = .{ .id = h.id, .vtype = h.vtype, .optional = optional },
                    });
                } else {
                    // Substitution token outside template definition - shouldn't happen
                    log.err("substitution token outside template definition at 0x{x}", .{ps.r.pos});
                    return BinXmlError.BadToken;
                }
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

/// Parses nested BinXML (type 0x21) during template instantiation.
/// Called from context.zig during Placeholder resolution.
///
/// Returns resolved elements (no Placeholder nodes) by recursively
/// calling parseRecord for template instances.
pub fn parseNestedBinXmlIntoResolved(
    chunk: []const u8,
    binxml_data: []const u8,
    ctx: *Context,
    allocator: std.mem.Allocator,
    out: *std.ArrayList(IR.Node),
) anyerror!void {
    if (binxml_data.len == 0) return;

    // Skip fragment header if present
    const start_offset = common.skipFragmentHeader(binxml_data, 0);
    if (start_offset >= binxml_data.len) return;

    // Check if this is a template instance or direct element
    const first_byte = binxml_data[start_offset];

    if (tokens.isToken(first_byte, tokens.TOK_TEMPLATE_INSTANCE)) {
        // Nested template instance - parse and instantiate recursively
        const tree = try parseTemplateInstance(ctx, chunk, binxml_data, start_offset);
        try out.append(allocator, .{ .Element = tree.element });
    } else if (tokens.isToken(first_byte, tokens.TOK_OPEN_START)) {
        // Direct element - parse without template context (no placeholders)
        var nested_r = Reader.init(binxml_data);
        nested_r.pos = start_offset;
        const chunk_base = @intFromPtr(binxml_data.ptr) - @intFromPtr(chunk.ptr);
        const elem = try parseElementIR(ctx, chunk, &nested_r, .{
            .chunk_base = chunk_base,
            .has_dep_id = false,
            .parsing_template_def = false,
        });
        try out.append(allocator, .{ .Element = elem });
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
            if (types.ValueType.fixedSizeFromRaw(vtype)) |sz| {
                const payload = try ps.r.readFixedBytesBounded(sz, end_pos);
                try out.append(ps.alloc(), .{ .Value = .{ .vtype = vtype, .bytes = payload } });
            } else {
                log.err("unknown value vtype=0x{x} at pos=0x{x} has_dep_id={}", .{ vtype, ps.r.pos, ps.has_dep_id });
                return BinXmlError.BadToken;
            }
        },
    }
}

// --- Unified Name Resolution ---

/// Resolves a name from a name offset.
/// Automatically handles inline names (when offset == current chunk position)
/// vs offset-based names (when offset points elsewhere in the chunk).
fn resolveName(ps: *ParseState, name_offset: u32) !IR.Name {
    const current_chunk_pos = ps.chunk_base + ps.r.pos;

    if (log.enabled(.trace)) {
        log.trace("resolveName: name_off=0x{x} current_chunk_pos=0x{x} chunk_base=0x{x}", .{ name_offset, current_chunk_pos, ps.chunk_base });
    }

    // If offset points to current position, name is inline
    if (name_offset == @as(u32, @intCast(current_chunk_pos))) {
        return readNameInline(ps);
    }

    // Otherwise, name is stored elsewhere in the chunk
    return ps.ctx.getOrReadName(ps.chunk, name_offset);
}

/// Reads a name that is stored inline at the current reader position.
/// The name format is: NameHeader (8 bytes) + UTF-16 string + null terminator (2 bytes)
fn readNameInline(ps: *ParseState) !IR.Name {
    const name_block_start = ps.r.pos;
    const hdr = try ps.r.readStruct(types.NameHeader);
    const num_chars = hdr.num_chars;
    const byte_len = @as(usize, num_chars) * 2;

    if (log.enabled(.debug)) {
        log.debug("readNameInline: next_off=0x{x} hash=0x{x} num_chars={d}", .{ hdr.next_offset, hdr.hash, num_chars });
    }

    if (ps.r.rem() < byte_len) return BinXmlError.UnexpectedEof;
    const str_start = ps.r.pos;
    const slice = ps.r.buf[str_start .. str_start + byte_len];
    ps.r.pos += byte_len;

    // Allocate and copy name (names persist beyond chunk processing)
    const buf = try ps.alloc().alloc(u8, byte_len);
    @memcpy(buf, slice);

    // Skip null terminator (2 bytes for UTF-16).
    // Name block: NameHeader (8) + string (byte_len) + null (2)
    const name_block_size = 8 + byte_len + 2;
    const name_block_end = name_block_start + name_block_size;

    if (log.enabled(.debug)) {
        log.debug("readNameInline: block_size={d} block_start=0x{x} block_end=0x{x}", .{ name_block_size, name_block_start, name_block_end });
    }

    // Position reader at end of name block
    if (name_block_end <= ps.r.buf.len) {
        ps.r.pos = name_block_end;
    }

    return IR.Name{ .bytes = buf, .num_chars = num_chars };
}

/// Reads a name offset and resolves it, with bounds checking.
fn readNameIRBounded(ps: *ParseState, end_pos: usize) !IR.Name {
    if (ps.r.pos + 4 > end_pos) return BinXmlError.UnexpectedEof;
    const h = try ps.r.readStruct(types.NameOffsetHeader);
    return resolveName(ps, h.offset);
}

// --- Element Header Parsing ---

const ElementHeader = struct {
    name: IR.Name,
    data_size: u32,
    header_len: usize,
    element_end: usize,
};

fn parseElementHeaderAndEnd(ps: *ParseState, element_start: usize) !ElementHeader {
    const hdr = try parseElementHeader(ps);

    const element_end = element_start + hdr.header_len + @as(usize, hdr.data_size);

    if (log.enabled(.trace)) {
        log.trace("elem hdr: start=0x{x} header_len=0x{x} data_size=0x{x} end=0x{x} buf_len=0x{x}", .{
            element_start, hdr.header_len, hdr.data_size, element_end, ps.r.buf.len,
        });
    }

    if (element_end > ps.r.buf.len or element_end < element_start) {
        log.err("parseElementHeaderAndEnd: bounds check failed! start=0x{x} header_len=0x{x} data_size=0x{x} end=0x{x} buf_len=0x{x}", .{
            element_start, hdr.header_len, hdr.data_size, element_end, ps.r.buf.len,
        });
        return BinXmlError.UnexpectedEof;
    }

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

/// Parses an element header (after the OpenStart token).
/// Handles both formats:
/// - Template definitions: dep_id (2 bytes) + data_size (4 bytes) + name_offset (4 bytes)
/// - Direct elements: data_size (4 bytes) + name_offset (4 bytes)
fn parseElementHeader(ps: *ParseState) !PartialElementHeader {
    const pos_before = ps.r.pos;

    // Template definitions have a dependency ID, direct elements don't
    if (ps.has_dep_id) {
        _ = try ps.r.readInt(u16); // Read and discard dep_id
    }

    const data_size = try ps.r.readInt(u32);

    if (log.enabled(.debug)) {
        log.debug("parseElementHeader: pos=0x{x} has_dep_id={} data_size=0x{x} ({d})", .{ pos_before, ps.has_dep_id, data_size, data_size });
    }

    // Read name offset and resolve name (inline or from chunk)
    const name_offset_header = try ps.r.readStruct(types.NameOffsetHeader);
    const name = try resolveName(ps, name_offset_header.offset);

    // Header length: 1 byte token + optional 2 bytes dep_id + 4 bytes data_size
    const header_len: usize = 1 + (if (ps.has_dep_id) @as(usize, 2) else 0) + 4;

    return .{ .name = name, .data_size = data_size, .header_len = header_len };
}

fn logTraceContext(msg: []const u8, r: *Reader, pos_override: ?usize) void {
    const pos = pos_override orelse r.pos;
    var tmp: [24]u8 = undefined;
    const rem = if (pos < r.buf.len) r.buf.len - pos else 0;
    const take = @min(rem, tmp.len);
    @memcpy(tmp[0..take], r.buf[pos .. pos + take]);

    var hex_buf: [48]u8 = undefined;
    log.trace("{s} pos=0x{x} data: {s}", .{ msg, pos, fmtHexSliceLower(tmp[0..take], &hex_buf) });
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
