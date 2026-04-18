const std = @import("std");
const Reader = @import("../reader.zig").Reader;
const value_reader = @import("../reader.zig");
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const context_mod = @import("context.zig");
const Context = context_mod.Context;
const Template = context_mod.Template;
const ElementTree = context_mod.ElementTree;
const types = @import("types.zig");
const err = @import("../err.zig");
const BinXmlError = err.BinXmlError;
const ParseError = err.ParseError;

const logger = @import("../../logger.zig");
const log = logger.scoped("binxml");
const tokens = @import("tokens.zig");
const util = @import("../util.zig");
const util_string = @import("../util_string.zig");

/// Context required for parsing BinXML elements.
///
/// BinXML element headers have two variations based on where they appear:
/// - **Template definitions**: headers include a dependency ID (2 bytes), substitutions become Placeholders
/// - **Direct elements**: headers omit the dependency ID, substitutions are an error
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
    /// True for template definitions (substitutions become Placeholder nodes),
    /// false for direct record elements (substitutions are an error).
    has_dep_id: bool,
};

/// Bundles common parsing state to reduce function signature noise.
pub const ParseState = struct {
    ctx: *Context,
    chunk: []const u8,
    r: *Reader,
    chunk_base: usize,
    has_dep_id: bool,

    pub fn init(ctx: *Context, chunk: []const u8, r: *Reader, elem_ctx: ElementContext) ParseState {
        return .{
            .ctx = ctx,
            .chunk = chunk,
            .r = r,
            .chunk_base = elem_ctx.chunk_base,
            .has_dep_id = elem_ctx.has_dep_id,
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
pub fn parseElementIR(ctx: *Context, chunk: []const u8, r: *Reader, elem_ctx: ElementContext) ParseError!*IR.Element {
    var ps = ParseState.init(ctx, chunk, r, elem_ctx);
    return parseElementIRImpl(&ps);
}

// Comptime UTF-8 literal for empty event creation
const event_name_utf8: []const u8 = "Event";

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
pub fn parseRecord(ctx: *Context, chunk: []const u8, bin: []const u8) ParseError!ElementTree {
    const allocator = ctx.arena.allocator();

    // Skip fragment header if present
    const start_offset = skipFragmentHeader(bin, 0);

    // Handle empty event case
    if (start_offset >= bin.len) {
        const el = try IRModule.irNewElement(allocator, IR.Name{ .utf8 = event_name_utf8 });
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
    });
    return .{ .element = el };
}

// --- Template Instance Parsing ---

/// Returns offset after fragment header if present, otherwise same offset.
fn skipFragmentHeader(data: []const u8, offset: usize) usize {
    if (offset + @sizeOf(types.FragmentHeader) <= data.len and data[offset] == tokens.TOK_FRAGMENT_HEADER) {
        return offset + @sizeOf(types.FragmentHeader);
    }
    return offset;
}

/// Calculates where substitution values start within a template instance.
///
/// Template instances have this structure:
/// - TemplateInstanceStart header (10 bytes)
/// - Inline template definitions (if def_data_off == position after header)
/// - Substitution values
///
/// If the template definition is inline, we follow the chain of definitions
/// (via next_offset) to find where substitution values begin.
///
/// Returns the chunk offset where substitution values start.
fn calcValuesOffset(chunk: []const u8, after_header: usize, def_data_off: u32) usize {
    // If definition is NOT inline (stored elsewhere in chunk), values start immediately
    if (def_data_off != after_header) return after_header;

    // Definition is inline - skip past it (and any chained definitions)
    var offset = after_header;
    while (offset + types.TemplateDefinitionHeader.binary_size <= chunk.len) {
        // Safe: the loop condition guarantees offset + 24 <= chunk.len, so
        // both 4-byte reads stay in range without a runtime bounds check.
        const next_off = std.mem.readInt(u32, chunk[offset..][0..4], .little);
        const data_size = std.mem.readInt(u32, chunk[offset + 20 ..][0..4], .little);
        const data_end = offset + types.TemplateDefinitionHeader.binary_size + data_size;

        if (data_end > chunk.len) break;
        offset = data_end;

        // next_offset == 0 means no more chained definitions
        // next_offset pointing elsewhere means we're done with inline defs
        if (next_off == 0 or next_off != offset) break;
    }

    return offset;
}

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
fn parseTemplateInstance(ctx: *Context, chunk: []const u8, bin: []const u8, start_offset: usize) ParseError!ElementTree {
    const allocator = ctx.arena.allocator();

    // Create a reader for the BinXML slice starting at the template instance
    var r = Reader.init(bin[start_offset..]);

    // Read template instance header using proper struct reading
    const header = try r.readStruct(types.TemplateInstanceStart);

    if (tokens.baseToken(header.token) != tokens.TOK_TEMPLATE_INSTANCE) {
        return error.BadToken;
    }

    // Calculate where substitution values start (deterministic)
    // chunk_base: where bin starts within chunk
    // r.pos: how many bytes we've read (the header size as determined by Reader)
    const chunk_base = @intFromPtr(bin.ptr) - @intFromPtr(chunk.ptr);
    const after_header = chunk_base + start_offset + r.pos;
    const values_offset = calcValuesOffset(chunk, after_header, header.def_data_off);

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
/// Templates are cached by their GUID, which uniquely identifies them.
fn getOrCacheTemplate(ctx: *Context, chunk: []const u8, def_data_off: u32) ParseError!Template {
    const off: usize = @intCast(def_data_off);
    if (off + types.TemplateDefinitionHeader.binary_size > chunk.len) {
        return error.OutOfBounds;
    }

    const next_offset = value_reader.readValue(u32, chunk[off..]) orelse return BinXmlError.UnexpectedEof;
    const guid = chunk[off + 4 ..][0..16].*;
    const data_size = value_reader.readValue(u32, chunk[off + 20 ..]) orelse return BinXmlError.UnexpectedEof;
    const def_header = types.TemplateDefinitionHeader{
        .next_offset = next_offset,
        .guid = guid,
        .data_size = data_size,
    };

    // Cache by GUID - the unique identifier for template definitions
    if (ctx.cache.get(def_header.guid)) |cached| {
        return cached;
    }

    const data_start = off + types.TemplateDefinitionHeader.binary_size;

    if (data_start + def_header.data_size > chunk.len) {
        return error.OutOfBounds;
    }

    // Parse template definition data
    const def_data = chunk[data_start .. data_start + def_header.data_size];
    var def_r = Reader.init(def_data);

    // Skip fragment header if present
    const frag_offset = skipFragmentHeader(def_data, 0);
    def_r.pos = frag_offset;

    // Parse with has_dep_id=true so substitutions become Placeholder nodes
    const root = try parseElementIR(ctx, chunk, &def_r, .{
        .chunk_base = data_start,
        .has_dep_id = true, // Template definitions include dependency IDs
    });

    // Cache by GUID on success
    const template = Template{ .root = root };
    try ctx.cache.put(def_header.guid, template);
    return template;
}

// --- Template Instance Value Parsing ---

/// Parses the values for a template instance.
/// Single-pass: reads descriptor table to compute payload offset, then reads values directly.
/// This avoids allocating intermediate arrays for sizes/vtypes.
pub fn parseTemplateInstanceValues(r: *Reader, allocator: std.mem.Allocator) ParseError![]types.TemplateValue {
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
        const size = value_reader.readValue(u16, r.buf[desc_offset..]) orelse return BinXmlError.UnexpectedEof;
        const vtype = r.buf[desc_offset + 2];
        // Note: desc_offset + 3 is reserved/unused byte - we skip it entirely

        if (log.enabled(.trace)) log.trace("  desc[{d}]: size={d} type=0x{x}", .{ i, size, vtype });

        const need: usize = @intCast(size);
        if (r.rem() < need) return BinXmlError.UnexpectedEof;

        const slice = r.buf[r.pos .. r.pos + need];
        r.pos += need;

        values[i] = if (types.ValueType.isNull(vtype))
            .{ .t = @intFromEnum(types.ValueType.null), .data = &[_]u8{} }
        else
            .{ .t = vtype, .data = slice };

        if (log.enabled(.trace)) log.trace("  payload[{d}]: t=0x{x} len={d}", .{ i, vtype, need });
    }

    return values;
}

// --- Core Parsing Logic ---

/// Parses an element in the Intermediate Representation (IR).
/// This is the recursive core of the parser.
fn parseElementIRImpl(ps: *ParseState) ParseError!*IR.Element {
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
    const header = try parseElementHeader(ps, element_start_pos);
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

        switch (tokens.baseToken(token)) {
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
fn parseAttributeListIR(ps: *ParseState, max_end: usize) ParseError!std.ArrayList(IR.Attr) {
    const header = try ps.r.readStruct(types.AttributeListHeader);
    const list_size = header.data_size;
    const list_start = ps.r.pos;
    const list_end = list_start + list_size;

    if (log.enabled(.trace)) {
        log.trace("attr list_start=0x{x} size=0x{x} list_end=0x{x} max_end=0x{x} buf_len=0x{x}", .{ list_start, list_size, list_end, max_end, ps.r.buf.len });
    }

    if (list_end > max_end or list_end < list_start) return BinXmlError.UnexpectedEof;

    var attributes: std.ArrayList(IR.Attr) = .empty;

    while (ps.r.pos < list_end and ps.r.rem() > 0) {
        const maybe_attr = ps.r.peekByte() catch break;
        if (!tokens.isToken(maybe_attr, tokens.TOK_ATTRIBUTE)) break;
        _ = try ps.r.readInt(u8); // Consume Attribute Token

        // Parse Attribute Name
        const name = try readNameIRBounded(ps, list_end);

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
/// When has_dep_id is true (template definition), substitution tokens become Placeholder nodes.
/// When has_dep_id is false, substitution tokens are an error.
fn collectValueTokens(ps: *ParseState, out: *std.ArrayList(IR.Node), end_pos: usize) ParseError!void {
    while (ps.r.rem() > 0 and ps.r.pos < end_pos) {
        const pk = ps.r.peekByte() catch break;
        if (log.enabled(.trace)) log.trace("valtok pk=0x{x} at 0x{x}", .{ pk, ps.r.pos });

        switch (tokens.baseToken(pk)) {
            tokens.TOK_ATTRIBUTE, tokens.TOK_CLOSE_START, tokens.TOK_CLOSE_EMPTY => break,
            tokens.TOK_VALUE => {
                try parseValueToken(ps, out, end_pos);
            },
            tokens.TOK_NORMAL_SUBST, tokens.TOK_OPTIONAL_SUBST => {
                const h = try ps.r.readStructBounded(types.SubstitutionHeader, end_pos);
                const optional = tokens.isToken(h.token, tokens.TOK_OPTIONAL_SUBST);

                if (ps.has_dep_id) {
                    // Template definition: substitutions become Placeholder nodes for later resolution
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
                const h = try ps.r.readStructBounded(types.CharRefHeader, end_pos);
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
) ParseError!void {
    if (binxml_data.len == 0) return;

    // Skip fragment header if present
    const start_offset = skipFragmentHeader(binxml_data, 0);
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
        });
        try out.append(allocator, .{ .Element = elem });
    }
}

// --- Individual Token Parsers ---

/// Generic helper for tokens containing a simple Name payload (PITarget, EntityRef).
fn parseNameToken(
    comptime Tag: IR.NodeTag,
    ps: *ParseState,
    out: *std.ArrayList(IR.Node),
    end_pos: usize,
) ParseError!void {
    // All these tokens start with a basic TokenHeader
    _ = try ps.r.readStructBounded(types.TokenHeader, end_pos);
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
) ParseError!void {
    _ = try r.readStructBounded(types.TokenHeader, end_pos);
    const data = try r.readLenPrefixedSlice(u16, 2, end_pos);
    const payload = IR.TextPayload{ .utf16 = data, .num_chars = data.len / 2 };
    const node: IR.Node = switch (Tag) {
        .CData => .{ .CData = payload },
        .PIData => .{ .PIData = payload },
        else => @compileError("parseStringToken only supports CData and PIData"),
    };
    try out.append(allocator, node);
}

fn parseValueToken(ps: *ParseState, out: *std.ArrayList(IR.Node), end_pos: usize) ParseError!void {
    const h = try ps.r.readStructBounded(types.ValueTokenHeader, end_pos);

    if (log.enabled(.trace)) log.trace("  vtype=0x{x}", .{h.vtype});

    // BinXML type (or array of BinXML)
    if (h.isBinXml()) {
        const blen = try ps.r.readIntBounded(u16, end_pos);
        const payload = try ps.r.readSliceBounded(blen, end_pos);
        try out.append(ps.alloc(), .{ .Value = .{ .vtype = h.vtype, .bytes = payload } });
        return;
    }

    // Convert raw vtype to enum for semantic switching
    const base_type = h.valueType() orelse {
        log.err("unknown value vtype=0x{x} at pos=0x{x} has_dep_id={}", .{ h.vtype, ps.r.pos, ps.has_dep_id });
        return BinXmlError.BadToken;
    };

    switch (base_type) {
        .string => {
            const text = try ps.r.readLenPrefixedSlice(u16, 2, end_pos);
            try out.append(ps.alloc(), .{ .Text = .{ .utf16 = text, .num_chars = text.len / 2 } });
        },
        .ansi_string, .binary => {
            const payload = try ps.r.readLenPrefixedSlice(u16, 1, end_pos);
            try out.append(ps.alloc(), .{ .Value = .{ .vtype = h.vtype, .bytes = payload } });
        },
        .sid => {
            const payload = try ps.r.readSidBytesBounded(end_pos);
            try out.append(ps.alloc(), .{ .Value = .{ .vtype = h.vtype, .bytes = payload } });
        },
        else => {
            if (base_type.fixedSize()) |sz| {
                const payload = try ps.r.readFixedBytesBounded(sz, end_pos);
                try out.append(ps.alloc(), .{ .Value = .{ .vtype = h.vtype, .bytes = payload } });
            } else {
                log.err("unhandled variable-length vtype=0x{x} at pos=0x{x}", .{ h.vtype, ps.r.pos });
                return BinXmlError.BadToken;
            }
        },
    }
}

// --- Unified Name Resolution ---

/// Resolves a name from a name offset.
/// Automatically handles inline names (when offset == current chunk position)
/// vs offset-based names (when offset points elsewhere in the chunk).
fn resolveName(ps: *ParseState, name_offset: u32) ParseError!IR.Name {
    const current_chunk_pos = ps.chunk_base + ps.r.pos;

    if (log.enabled(.trace)) {
        log.trace("resolveName: name_off=0x{x} current_chunk_pos=0x{x} chunk_base=0x{x}", .{ name_offset, current_chunk_pos, ps.chunk_base });
    }

    // If offset points to current position, name is inline. Compare in
    // usize space so we don't lose information when chunk positions exceed
    // u32 (which they cannot today, but the cast was load-bearing only by
    // accident).
    if (@as(usize, name_offset) == current_chunk_pos) {
        return readNameInline(ps);
    }

    // Otherwise, name is stored elsewhere in the chunk
    return ps.ctx.getOrReadName(ps.chunk, name_offset);
}

/// Reads a name that is stored inline at the current reader position.
/// The name format is: NameHeader (8 bytes) + UTF-16 string + null terminator (2 bytes)
fn readNameInline(ps: *ParseState) ParseError!IR.Name {
    const name_block_start = ps.r.pos;
    const hdr = try ps.r.readStruct(types.NameHeader);
    const num_chars = hdr.num_chars;
    const byte_len = @as(usize, num_chars) * 2;

    if (log.enabled(.debug)) {
        log.debug("readNameInline: next_off=0x{x} hash=0x{x} num_chars={d}", .{ hdr.next_offset, hdr.hash, num_chars });
    }

    if (ps.r.rem() < byte_len) return BinXmlError.UnexpectedEof;
    const str_start = ps.r.pos;
    const utf16_slice = ps.r.buf[str_start .. str_start + byte_len];
    ps.r.pos += byte_len;

    // Convert UTF-16LE to UTF-8 once at parse time
    const utf8 = try util_string.convertUtf16ToUtf8(ps.alloc(), utf16_slice, num_chars);

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

    return IR.Name{ .utf8 = utf8 };
}

/// Reads a name offset and resolves it, with bounds checking.
fn readNameIRBounded(ps: *ParseState, end_pos: usize) ParseError!IR.Name {
    if (ps.r.pos + 4 > end_pos) return BinXmlError.UnexpectedEof;
    const h = try ps.r.readStruct(types.NameOffsetHeader);
    return resolveName(ps, h.offset);
}

// --- Element Header Parsing ---

const ElementHeader = struct {
    name: IR.Name,
    element_end: usize,
};

/// Parses an element header (after the OpenStart token) and computes element bounds.
/// Handles both formats:
/// - Template definitions: dep_id (2 bytes) + data_size (4 bytes) + name_offset (4 bytes)
/// - Direct elements: data_size (4 bytes) + name_offset (4 bytes)
fn parseElementHeader(ps: *ParseState, element_start: usize) ParseError!ElementHeader {
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
    const element_end = element_start + header_len + @as(usize, data_size);

    if (log.enabled(.trace)) {
        log.trace("elem hdr: start=0x{x} header_len=0x{x} data_size=0x{x} end=0x{x} buf_len=0x{x}", .{
            element_start, header_len, data_size, element_end, ps.r.buf.len,
        });
    }

    if (element_end > ps.r.buf.len or element_end < element_start) {
        log.err("parseElementHeader: bounds check failed! start=0x{x} header_len=0x{x} data_size=0x{x} end=0x{x} buf_len=0x{x}", .{
            element_start, header_len, data_size, element_end, ps.r.buf.len,
        });
        return BinXmlError.UnexpectedEof;
    }

    return .{ .name = name, .element_end = element_end };
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
