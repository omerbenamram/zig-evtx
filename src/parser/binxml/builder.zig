//! BinXML Builder - Entry point for parsing Windows Event Log binary XML.
//!
//! ## Architecture
//!
//! The Builder is the main entry point for converting BinXML data into an IR (Intermediate
//! Representation) element tree. It handles two distinct parsing paths:
//!
//! ```
//! Builder.build()
//!     ├── buildElement()   - Direct element parsing (no template)
//!     └── buildTemplate()  - Template instance parsing
//!             ├── parseTemplateInstanceValues()  (from parser.zig)
//!             └── instantiate()                  - Single-pass expansion
//! ```
//!
//! ## Template Instantiation
//!
//! Most Windows events use templates - reusable element structures with placeholder
//! substitution nodes. The flow is:
//!
//! 1. Parse or retrieve cached template definition (contains `Subst` placeholder nodes)
//! 2. Parse the substitution values from the event data
//! 3. `instantiate()` the template: clone the definition, replacing `Subst` nodes with
//!    resolved values, and handling nested BinXML (type 0x21) inline
//!
//! Template definitions are cached per-chunk using offset+GUID as the key, since the same
//! template may be referenced by multiple events within a chunk.
//!
//! ## Nested BinXML
//!
//! Some substitution values contain embedded BinXML (value type 0x21, aka EVT_XML).
//! These are recursively parsed during instantiation - when we resolve a substitution
//! that yields type 0x21, we immediately call `buildTemplate()` to parse it, rather
//! than deferring to a separate tree walk. This handles arbitrary nesting naturally.
//!
//! ## Non-Template Elements
//!
//! Rarely, events may contain direct elements without a template wrapper. These are
//! handled by `buildElement()`, which parses the element and scans for any nested
//! BinXML values that need recursive parsing.

const std = @import("std");
const Reader = @import("../reader.zig").Reader;
const IRMod = @import("../ir.zig");
const IR = IRMod.IR;
const Context = @import("context.zig").Context;
const binxml_parser = @import("parser.zig");
const types = @import("types.zig");
const tokens = @import("tokens.zig");
const common = @import("common.zig");
const util = @import("../util.zig");
const value_reader = @import("value_reader.zig");
const logger = @import("../../logger.zig");
const log = logger.scoped("binxml");

/// Policy for joining array elements when rendering.
/// Attributes use space separator, text content uses comma for strings.
const JoinerPolicy = enum { Attr, Text };

pub const Builder = struct {
    ctx: *Context,

    pub fn init(ctx: *Context) Builder {
        return .{ .ctx = ctx };
    }

    /// Returns the arena allocator for all chunk-local allocations.
    /// All IR elements, names, and template data are allocated here and
    /// freed atomically when resetPerChunk() is called.
    inline fn alloc(self: *const Builder) std.mem.Allocator {
        return self.ctx.arena.allocator();
    }

    /// Builds a fully expanded IR element tree from a BinXML chunk.
    /// This is the main entry point for processing an event.
    ///
    /// Arguments:
    /// - `chunk`: The full chunk data (needed for offset-based lookups).
    /// - `bin`: The specific slice of the chunk containing the event data.
    pub fn build(self: *Builder, chunk: []const u8, bin: []const u8) !*IR.Element {
        var r = Reader.init(bin);
        try common.skipFragmentHeaderIfPresent(&r);

        // Handle empty event case (rare but possible)
        if (r.rem() == 0) {
            return self.buildEmpty();
        }

        // Dispatch based on whether this is a template instance or direct element
        if (try self.isTemplateInstance(&r)) {
            return self.buildTemplate(chunk, &r);
        }

        return self.buildElement(chunk, &r);
    }

    /// Creates a minimal <Event/> element for empty records.
    fn buildEmpty(self: *Builder) !*IR.Element {
        const bytes: []u8 = try util.utf16FromAscii(self.alloc(), "Event");
        return IRMod.irNewElement(self.alloc(), IR.Name{ .bytes = bytes, .num_chars = 5 });
    }

    /// Checks if the next token indicates a template instance.
    fn isTemplateInstance(_: *Builder, r: *Reader) !bool {
        if (r.rem() == 0) return false;
        const first = try r.peekByte();
        return first == tokens.TOK_TEMPLATE_INSTANCE;
    }

    // =========================================================================
    // Direct Element Parsing (no template)
    // =========================================================================

    /// Parses a direct BinXML element (not wrapped in a template).
    /// After parsing, scans for any nested BinXML values that need recursive parsing.
    fn buildElement(self: *Builder, chunk: []const u8, r: *Reader) !*IR.Element {
        const root = try binxml_parser.parseElementIR(self.ctx, chunk, r, .rec);

        // Scan for nested BinXML (type 0x21) and parse recursively
        try self.scanAndExpandNestedBinXml(chunk, root);

        return root;
    }

    /// Scans an element tree for nested BinXML values and expands them in-place.
    /// Used for non-template elements where there are no substitutions to resolve.
    fn scanAndExpandNestedBinXml(self: *Builder, chunk: []const u8, el: *IR.Element) anyerror!void {
        var needs_rebuild = false;

        // Recurse into child elements first
        for (el.children.items) |node| {
            switch (node) {
                .Element => |child| try self.scanAndExpandNestedBinXml(chunk, child),
                .Value => |val| {
                    if (isNestedBinXml(val)) needs_rebuild = true;
                },
                else => {},
            }
        }

        // Check attributes for nested BinXML
        if (!needs_rebuild) {
            for (el.attrs.items) |attr| {
                for (attr.value.items) |node| {
                    if (node == .Value and isNestedBinXml(node.Value)) {
                        needs_rebuild = true;
                        break;
                    }
                }
                if (needs_rebuild) break;
            }
        }

        if (!needs_rebuild) return;

        // Rebuild children list, expanding nested BinXML
        var new_children = try std.ArrayList(IR.Node).initCapacity(self.alloc(), el.children.items.len + 4);

        for (el.children.items) |node| {
            switch (node) {
                .Value => |val| {
                    if (isNestedBinXml(val)) {
                        try self.parseNestedBinXmlInto(chunk, val.bytes, &new_children);
                    } else {
                        try new_children.append(self.alloc(), node);
                    }
                },
                else => try new_children.append(self.alloc(), node),
            }
        }

        // Also check attributes for nested BinXML (rare but possible)
        for (el.attrs.items) |attr| {
            for (attr.value.items) |node| {
                if (node == .Value and isNestedBinXml(node.Value)) {
                    try self.parseNestedBinXmlInto(chunk, node.Value.bytes, &new_children);
                }
            }
        }

        el.children = new_children;
        el.has_element_child = true;
    }

    // =========================================================================
    // Template Instance Parsing
    // =========================================================================

    /// Parses a template instance: reads the header, retrieves/parses the definition,
    /// parses substitution values, and instantiates the template.
    fn buildTemplate(self: *Builder, chunk: []const u8, r: *Reader) !*IR.Element {
        const header = try r.readStruct(types.TemplateInstanceStart);
        if ((header.token & 0x1f) != tokens.TOK_TEMPLATE_INSTANCE) {
            return error.BadToken;
        }

        // Handle inline definition if present (skip over it, we'll read via offset)
        try common.skipInlineTemplateDefinition(r, header.def_data_off);
        common.skipInlineCachedTemplateDefs(r);

        // Retrieve template definition (cached or parsed)
        const def_ptr = try self.getOrParseTemplateDef(chunk, header.def_data_off);
        const def = def_ptr.*;

        // Parse substitution values
        const values = try binxml_parser.parseTemplateInstanceValues(r, self.alloc());

        // Instantiate template: clone definition, resolve substitutions, handle nested BinXML
        return self.instantiate(chunk, def, values);
    }

    /// Gets a template definition from cache or parses it from the chunk.
    fn getOrParseTemplateDef(self: *Builder, chunk: []const u8, def_data_off: u32) !**IR.Element {
        const key = self.makeDefCacheKey(chunk, def_data_off);
        const got = try self.ctx.cache.getOrPut(key);

        if (!got.found_existing) {
            const parsed = try self.parseTemplateDef(chunk, def_data_off);
            got.value_ptr.* = parsed;
        }

        return got.value_ptr;
    }

    /// Generates a cache key for a template definition.
    fn makeDefCacheKey(_: *Builder, chunk: []const u8, def_data_off: u32) Context.DefKey {
        var guid: [16]u8 = undefined;
        const base: usize = @intCast(def_data_off);
        // GUID is at offset 4 in TemplateDefinitionHeader (after next_offset u32)
        const guid_slice = chunk[base + 4 .. base + 20];
        @memcpy(guid[0..], guid_slice);
        return .{ .def_data_off = def_data_off, .guid = guid };
    }

    /// Parses a template definition from the chunk at the specified offset.
    fn parseTemplateDef(self: *Builder, chunk: []const u8, def_data_off: u32) !*IR.Element {
        const def_off: usize = @intCast(def_data_off);
        if (def_off + @sizeOf(types.TemplateDefinitionHeader) > chunk.len) {
            return error.OutOfBounds;
        }

        // TemplateDefinitionHeader is 24 bytes. data_size is at offset 20.
        const size_slice = chunk[def_off + 20 .. def_off + 24];
        const data_size = std.mem.readInt(u32, size_slice[0..4], .little);

        if (log.enabled(.trace)) {
            log.trace("parseTemplateDef: off=0x{x} size=0x{x}", .{ def_data_off, data_size });
        }

        const data_start = def_off + 24;
        const data_end = data_start + @as(usize, data_size);

        if (data_end > chunk.len) return error.OutOfBounds;

        var def_r = Reader.init(chunk[data_start..data_end]);
        try common.skipFragmentHeaderIfPresent(&def_r);

        // .def source mode handles specific name parsing rules for templates
        return binxml_parser.parseElementIRWithBase(self.ctx, chunk, &def_r, .def, data_start);
    }

    // =========================================================================
    // Template Instantiation
    // =========================================================================

    /// Instantiates a template definition with the provided substitution values.
    ///
    /// This is a single-pass operation that:
    /// 1. Clones the element structure from the template definition
    /// 2. Resolves `Subst` nodes by looking up values and creating appropriate IR nodes
    /// 3. Handles nested BinXML (type 0x21) inline by recursively calling `buildTemplate()`
    ///
    /// The result is a fully expanded element tree with no remaining substitution placeholders.
    fn instantiate(self: *Builder, chunk: []const u8, def: *const IR.Element, values: []const types.TemplateValue) anyerror!*IR.Element {
        const el = try IRMod.irNewElement(self.alloc(), def.name);

        // Pre-size containers
        if (def.attrs.items.len > 0) {
            try el.attrs.ensureTotalCapacityPrecise(self.alloc(), def.attrs.items.len);
        }

        // Instantiate attributes
        for (def.attrs.items) |attr| {
            const expanded_value = try self.instantiateNodes(chunk, attr.value.items, values, .Attr);
            try el.attrs.append(self.alloc(), .{ .name = attr.name, .value = expanded_value });
        }

        // Instantiate children
        const expanded_children = try self.instantiateNodes(chunk, def.children.items, values, .Text);
        if (expanded_children.items.len > 0) {
            try el.children.ensureTotalCapacityPrecise(self.alloc(), expanded_children.items.len);
        }
        for (expanded_children.items) |child| {
            try el.children.append(self.alloc(), child);
        }

        el.has_element_child = def.has_element_child;

        return el;
    }

    /// Instantiates a list of nodes, resolving substitutions and recursing into child elements.
    fn instantiateNodes(
        self: *Builder,
        chunk: []const u8,
        nodes: []const IR.Node,
        values: []const types.TemplateValue,
        policy: JoinerPolicy,
    ) anyerror!std.ArrayList(IR.Node) {
        var out: std.ArrayList(IR.Node) = .empty;
        if (nodes.len > 0) {
            try out.ensureTotalCapacityPrecise(self.alloc(), nodes.len);
        }

        for (nodes) |node| {
            switch (node) {
                .Subst => |subst| try self.resolveSubstitution(chunk, subst, values, policy, &out),
                .Element => |child_def| {
                    // Recursively instantiate child elements
                    const child = try self.instantiate(chunk, child_def, values);
                    try out.append(self.alloc(), .{ .Element = child });
                },
                else => try out.append(self.alloc(), node),
            }
        }

        return out;
    }

    /// Resolves a substitution placeholder with its actual value.
    fn resolveSubstitution(
        self: *Builder,
        chunk: []const u8,
        subst: IR.SubstPayload,
        values: []const types.TemplateValue,
        policy: JoinerPolicy,
        out: *std.ArrayList(IR.Node),
    ) anyerror!void {
        if (subst.id >= values.len) return; // Out of bounds, ignore

        const val = values[subst.id];

        // Skip optional empty substitutions
        if (subst.optional and (val.t == 0x00 or val.data.len == 0)) {
            return;
        }

        const is_array = (subst.vtype & types.ValueType.ARRAY_FLAG) != 0;
        const base_type = subst.vtype & 0x7f;

        if (is_array) {
            try self.resolveArrayValue(chunk, base_type, val, policy, out);
        } else {
            try self.resolveSingleValue(chunk, base_type, val, out);
        }
    }

    /// Resolves a single (non-array) substitution value.
    fn resolveSingleValue(
        self: *Builder,
        chunk: []const u8,
        base_type: u8,
        val: types.TemplateValue,
        out: *std.ArrayList(IR.Node),
    ) anyerror!void {
        // Nested BinXML (type 0x21) - recursively parse and splice
        // Note: we check val.t (actual type), not base_type (template's expected type)
        if ((val.t & 0x7f) == 0x21 and val.data.len > 0) {
            try self.parseNestedBinXmlInto(chunk, val.data, out);
            return;
        }

        // String types (0x01) become Text nodes for proper XML escaping
        if (base_type == @intFromEnum(types.ValueType.string)) {
            var num_chars = val.data.len / 2;
            if (num_chars > 0) {
                const last_char = std.mem.readInt(u16, val.data[val.data.len - 2 .. val.data.len][0..2], .little);
                if (last_char == 0) num_chars -= 1;
            }
            try out.append(self.alloc(), .{
                .Text = .{ .utf16 = val.data[0 .. num_chars * 2], .num_chars = num_chars },
            });
            return;
        }

        // All other types become Value nodes
        try out.append(self.alloc(), .{
            .Value = .{ .vtype = val.t, .bytes = val.data },
        });
    }

    /// Resolves an array substitution value, joining elements with appropriate separator.
    fn resolveArrayValue(
        self: *Builder,
        chunk: []const u8,
        base_type: u8,
        val: types.TemplateValue,
        policy: JoinerPolicy,
        out: *std.ArrayList(IR.Node),
    ) anyerror!void {
        var iter = ArrayIterator{
            .data = val.data,
            .base_type = base_type,
            .backing_type = val.t,
        };

        var first = true;
        const sep = self.ctx.getSepUtf16(joinerFor(policy, base_type));

        while (iter.next()) |item_bytes| {
            if (!first and sep.num_chars > 0) {
                try out.append(self.alloc(), .{ .Text = .{ .utf16 = sep.bytes, .num_chars = sep.num_chars } });
            }
            first = false;

            const item_val = types.TemplateValue{ .t = base_type, .data = item_bytes };
            try self.resolveSingleValue(chunk, base_type, item_val, out);
        }
    }

    // =========================================================================
    // Nested BinXML Handling
    // =========================================================================

    /// Parses a nested BinXML blob and appends resulting elements to `out`.
    fn parseNestedBinXmlInto(self: *Builder, chunk: []const u8, data: []const u8, out: *std.ArrayList(IR.Node)) anyerror!void {
        if (data.len == 0) return;

        var r = Reader.init(data);
        try common.skipFragmentHeaderIfPresent(&r);

        while (r.rem() > 0) {
            const pk = r.peekByte() catch break;
            if (pk != tokens.TOK_TEMPLATE_INSTANCE) break;

            const elem = try self.buildTemplate(chunk, &r);
            try out.append(self.alloc(), .{ .Element = elem });
        }
    }

    /// Checks if a value is nested BinXML (type 0x21 with data).
    fn isNestedBinXml(val: IR.ValuePayload) bool {
        return (val.vtype & 0x7f) == 0x21 and val.bytes.len > 0;
    }
};

// =============================================================================
// Array Iteration Helpers
// =============================================================================

/// Returns the separator string for array joining based on policy and type.
fn joinerFor(policy: JoinerPolicy, base: u8) []const u8 {
    return switch (policy) {
        .Attr => " ",
        .Text => if (base == @intFromEnum(types.ValueType.string) or
            base == @intFromEnum(types.ValueType.ansi_string)) "," else " ",
    };
}

/// Iterator for parsing binary array payloads.
/// Handles variable-length types (strings, SIDs) and fixed-size types.
const ArrayIterator = struct {
    data: []const u8,
    base_type: u8,
    backing_type: u8,
    cursor: usize = 0,

    pub fn next(self: *ArrayIterator) ?[]const u8 {
        if (self.cursor >= self.data.len) return null;

        const start = self.cursor;
        var end = start;

        switch (self.base_type) {
            0x01 => { // Unicode string (NUL-terminated)
                if (self.data.len - start < 2) {
                    self.cursor = self.data.len;
                    return null;
                }
                while (end + 1 < self.data.len) : (end += 2) {
                    const ch = std.mem.readInt(u16, self.data[end .. end + 2][0..2], .little);
                    if (ch == 0) break;
                }
                const next_start = if (end + 1 < self.data.len) end + 2 else end;
                if (next_start <= start) {
                    self.cursor = self.data.len;
                    return null;
                }
                self.cursor = next_start;
                return self.data[start..end];
            },
            0x02 => { // ANSI string (NUL-terminated)
                while (end < self.data.len and self.data[end] != 0) : (end += 1) {}
                const next_start = if (end < self.data.len) end + 1 else end;
                if (next_start <= start) {
                    self.cursor = self.data.len;
                    return null;
                }
                self.cursor = next_start;
                return self.data[start..end];
            },
            0x13 => { // SID
                const size = value_reader.sidSize(self.data[start..]) orelse return null;
                if (start + size > self.data.len) return null;
                self.cursor = start + size;
                return self.data[start .. start + size];
            },
            0x10 => { // SizeT (architecture dependent)
                var size: usize = 0;
                if (self.backing_type == 0x94) size = 4 // HexInt32
                else if (self.backing_type == 0x95) size = 8 // HexInt64
                else return null;

                if (start + size > self.data.len) return null;
                self.cursor = start + size;
                return self.data[start .. start + size];
            },
            else => {
                // Fixed size types
                if (types.valueTypeFixedSize(self.base_type)) |size| {
                    if (start + size > self.data.len) return null;
                    self.cursor = start + size;
                    return self.data[start .. start + size];
                }
                return null;
            },
        }
    }
};
