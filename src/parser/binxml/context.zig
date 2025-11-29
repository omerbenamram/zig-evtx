//! Context and template cache for BinXML parsing.
//!
//! This module provides the shared state used during parsing, including:
//! - Template definition cache (per-chunk) - stores parsed Template structures
//! - Name cache for string deduplication
//! - Arena allocator for chunk-scoped allocations
//!
//! Type-safe wrapper types ensure output IR is always resolved:
//! - `Template`: Cached template definition, may contain Placeholder nodes
//! - `ElementTree`: Resolved element tree, guaranteed no Placeholder nodes
//!
//! Keep this file renderer-free to avoid cycles.

const std = @import("std");
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const types = @import("types.zig");
const BinXmlError = @import("../err.zig").BinXmlError;
const Reader = @import("../reader.zig").Reader;
const util_string = @import("../util_string.zig");
const logger = @import("../../logger.zig");
const log = logger.scoped("binxml");

/// Cached name entry - pre-converted UTF-8, ready for direct output.
pub const NameCacheEntry = []u8;

/// Resolved element tree - guaranteed to have no Placeholder nodes.
/// This is the ONLY type renderers should accept.
///
/// Wraps an IR.Element pointer to provide type-level guarantee that
/// all substitutions have been resolved.
pub const ElementTree = struct {
    element: *IR.Element,
};

/// Cached template definition - may contain Placeholder nodes.
///
/// Template definitions are parsed once and cached. When instantiated with
/// substitution values, they produce an ElementTree with all placeholders resolved.
pub const Template = struct {
    root: *IR.Element,

    /// Clone this template and resolve all Placeholder nodes with the given values.
    /// Returns an ElementTree guaranteed to have no Placeholder nodes.
    ///
    /// This is the only way to get an ElementTree from a Template.
    pub fn instantiate(
        self: *const Template,
        values: []const types.TemplateValue,
        chunk: []const u8,
        ctx: *Context,
    ) !ElementTree {
        const allocator = ctx.arena.allocator();
        const resolved = try cloneAndResolve(self.root, values, chunk, ctx, allocator);
        return .{ .element = resolved };
    }
};

/// Recursively clones an element tree, resolving all Placeholder nodes.
fn cloneAndResolve(
    src: *const IR.Element,
    values: []const types.TemplateValue,
    chunk: []const u8,
    ctx: *Context,
    allocator: std.mem.Allocator,
) anyerror!*IR.Element {
    const el = try allocator.create(IR.Element);
    el.* = .{
        .name = src.name,
        .attrs = .empty,
        .children = .empty,
        .has_element_child = src.has_element_child,
    };

    // Clone attributes with placeholder resolution
    if (src.attrs.items.len > 0) {
        try el.attrs.ensureTotalCapacityPrecise(allocator, src.attrs.items.len);
        for (src.attrs.items) |attr| {
            var new_attr = IR.Attr{ .name = attr.name, .value = .empty };
            if (attr.value.items.len > 0) {
                try new_attr.value.ensureTotalCapacityPrecise(allocator, attr.value.items.len);
                for (attr.value.items) |node| {
                    try resolveNodeInto(node, values, chunk, ctx, allocator, &new_attr.value);
                }
            }
            try el.attrs.append(allocator, new_attr);
        }
    }

    // Clone children with placeholder resolution
    if (src.children.items.len > 0) {
        try el.children.ensureTotalCapacityPrecise(allocator, src.children.items.len);
        for (src.children.items) |node| {
            const before = el.children.items.len;
            try resolveNodeInto(node, values, chunk, ctx, allocator, &el.children);
            // Check if any newly added children are elements - update has_element_child
            // This is necessary because Placeholder nodes resolve to Elements at instantiation time
            for (el.children.items[before..]) |child| {
                if (child == .Element) {
                    el.has_element_child = true;
                    break;
                }
            }
        }
    }

    return el;
}

/// Resolves a single node, appending result(s) to the output list.
/// Placeholder nodes are resolved to their actual values (may expand to multiple nodes).
/// Other nodes are cloned as-is (with recursive resolution for Element children).
fn resolveNodeInto(
    node: IR.Node,
    values: []const types.TemplateValue,
    chunk: []const u8,
    ctx: *Context,
    allocator: std.mem.Allocator,
    out: *std.ArrayList(IR.Node),
) !void {
    switch (node) {
        .Placeholder => |ph| {
            try resolvePlaceholder(ph, values, chunk, ctx, allocator, out);
        },
        .Element => |el| {
            const cloned = try cloneAndResolve(el, values, chunk, ctx, allocator);
            try out.append(allocator, .{ .Element = cloned });
        },
        // All other node types are immutable data, just copy them
        .Text, .Value, .CharRef, .EntityRef, .CData, .PITarget, .PIData => {
            try out.append(allocator, node);
        },
    }
}

/// Resolves a Placeholder to its actual value(s).
fn resolvePlaceholder(
    ph: IR.PlaceholderPayload,
    values: []const types.TemplateValue,
    chunk: []const u8,
    ctx: *Context,
    allocator: std.mem.Allocator,
    out: *std.ArrayList(IR.Node),
) !void {
    if (ph.id >= values.len) return; // Out of bounds, skip

    const val = values[ph.id];

    // Skip optional empty substitutions
    if (ph.optional and (types.ValueType.isNull(val.t) or val.data.len == 0)) {
        return;
    }

    const is_array = types.ValueType.isArray(ph.vtype);
    const base_type = types.ValueType.baseType(ph.vtype);

    if (is_array) {
        try resolveArrayValue(base_type, val, allocator, out);
    } else {
        try resolveSingleValue(base_type, val, chunk, ctx, allocator, out);
    }
}

/// Resolves a single (non-array) substitution value.
fn resolveSingleValue(
    base_type: u8,
    val: types.TemplateValue,
    chunk: []const u8,
    ctx: *Context,
    allocator: std.mem.Allocator,
    out: *std.ArrayList(IR.Node),
) !void {
    // Nested BinXML - recursively parse and splice
    if (types.ValueType.isBinXml(val.t) and val.data.len > 0) {
        // Import parser module for nested parsing
        const parser = @import("parser.zig");
        try parser.parseNestedBinXmlIntoResolved(chunk, val.data, ctx, allocator, out);
        return;
    }

    // String types (0x01) become Text nodes for proper XML escaping
    if (base_type == @intFromEnum(types.ValueType.string)) {
        var num_chars = val.data.len / 2;
        // Remove null terminator
        if (num_chars > 0) {
            const last_char = std.mem.readInt(u16, val.data[val.data.len - 2 .. val.data.len][0..2], .little);
            if (last_char == 0) num_chars -= 1;
        }
        // Trim trailing spaces (0x0020 in UTF-16LE) to match Rust evtx_dump behavior
        while (num_chars > 0) {
            const pos = (num_chars - 1) * 2;
            const ch = std.mem.readInt(u16, val.data[pos..][0..2], .little);
            if (ch != 0x0020) break;
            num_chars -= 1;
        }
        if (num_chars > 0) {
            try out.append(allocator, .{
                .Text = .{ .utf16 = val.data[0 .. num_chars * 2], .num_chars = num_chars },
            });
        }
        return;
    }

    // All other types become Value nodes
    try out.append(allocator, .{ .Value = .{ .vtype = val.t, .bytes = val.data } });
}

/// Resolves an array substitution value by expanding it into multiple Value nodes.
fn resolveArrayValue(
    base_type: u8,
    val: types.TemplateValue,
    allocator: std.mem.Allocator,
    out: *std.ArrayList(IR.Node),
) !void {
    const elem_size = types.ValueType.fixedSizeFromRaw(base_type) orelse {
        // Variable-size array elements - treat as single value
        try out.append(allocator, .{ .Value = .{ .vtype = val.t, .bytes = val.data } });
        return;
    };

    if (elem_size == 0 or val.data.len == 0) return;

    const num_elems = val.data.len / elem_size;
    for (0..num_elems) |i| {
        const start = i * elem_size;
        const end = start + elem_size;
        if (end > val.data.len) break;
        try out.append(allocator, .{ .Value = .{ .vtype = base_type, .bytes = val.data[start..end] } });
    }
}

/// Shared parsing context for BinXML processing.
///
/// Manages per-chunk state including template caches, name caches, and a scoped
/// arena allocator. All chunk-scoped allocations use the arena, which is reset
/// atomically between chunks via `resetPerChunk()`.
pub const Context = struct {
    /// Backing allocator for long-lived allocations (cache hash maps).
    allocator: std.mem.Allocator,
    /// Arena for chunk-scoped allocations (IR elements, names, etc.).
    arena: std.heap.ArenaAllocator,
    /// Template definition cache: GUID -> parsed Template with Placeholder nodes.
    /// The GUID uniquely identifies each template definition.
    cache: std.AutoHashMap([16]u8, Template),
    /// Name cache: offset -> pre-converted UTF-8 string.
    name_cache: std.AutoHashMap(u32, NameCacheEntry),

    /// Creates a new context with the given backing allocator.
    pub fn init(allocator: std.mem.Allocator) !Context {
        return .{
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .cache = std.AutoHashMap([16]u8, Template).init(allocator),
            .name_cache = std.AutoHashMap(u32, NameCacheEntry).init(allocator),
        };
    }

    /// Releases all resources held by this context.
    pub fn deinit(self: *Context) void {
        self.cache.deinit();
        self.name_cache.deinit();
        self.arena.deinit();
    }

    /// Resets chunk-local state for processing a new chunk.
    ///
    /// Clears all caches and resets the arena allocator while retaining
    /// hash map capacity to avoid repeated allocations.
    pub fn resetPerChunk(self: *Context) void {
        self.cache.clearRetainingCapacity();
        self.name_cache.clearRetainingCapacity();
        _ = self.arena.reset(.retain_capacity);
    }

    pub fn getOrReadName(self: *Context, chunk: []const u8, off_u32: u32) !IR.Name {
        // Check cache first - returns pre-converted UTF-8
        if (self.name_cache.get(off_u32)) |utf8| {
            return IR.Name{ .utf8 = utf8 };
        }

        if (off_u32 >= chunk.len) return BinXmlError.UnexpectedEof;

        var r = Reader.init(chunk);
        r.pos = off_u32;

        const h = try r.readStruct(types.NameHeader);
        const num_chars = h.num_chars;
        const byte_len = @as(usize, num_chars) * 2;

        if (r.rem() < byte_len) return BinXmlError.UnexpectedEof;
        const str_start = r.pos;

        // Adjust length for trailing nulls if necessary
        var take_chars = num_chars;
        if (byte_len >= 2) {
            const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
            if (last == 0 and take_chars > 0) take_chars -= 1;
        }

        const utf16_slice = chunk[str_start .. str_start + take_chars * 2];

        // Convert UTF-16LE to UTF-8 once at cache time.
        // No escaping needed: names follow XML NCName rules (safe chars only).
        const utf8 = try util_string.convertUtf16ToUtf8(self.arena.allocator(), utf16_slice, take_chars);
        try self.name_cache.put(off_u32, utf8);

        return IR.Name{ .utf8 = utf8 };
    }

    /// Pre-populates the name cache using offsets from the chunk header.
    ///
    /// This is a best-effort optimization that avoids repeated lookups during parsing.
    /// Invalid offsets or malformed names are silently skipped since this is optional
    /// pre-warming - the actual parsing will handle errors properly if encountered.
    pub fn preCacheFromChunkHeader(self: *Context, chunk: []const u8, offsets: []const u32) void {
        for (offsets) |off| {
            // Skip null offsets and out-of-bounds
            if (off == 0 or off >= chunk.len) continue;
            // Best-effort: errors during pre-caching are non-fatal
            _ = self.getOrReadName(chunk, off) catch continue;
        }
    }
};
