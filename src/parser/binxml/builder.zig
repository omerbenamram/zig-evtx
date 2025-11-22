const std = @import("std");
const Reader = @import("../reader.zig").Reader;
const IRMod = @import("../ir.zig");
const IR = IRMod.IR;
const Context = @import("context.zig").Context;
const binxml_parser = @import("parser.zig");
const Expander = @import("expander.zig").Expander;
const types = @import("types.zig");
const tokens = @import("tokens.zig");
const common = @import("common.zig");
const util = @import("../util.zig");
const logger = @import("../../logger.zig");
const log = logger.scoped("binxml");

/// The Builder orchestrates the parsing and expansion of BinXML chunks.
/// It handles both regular elements and template instances, including
/// the recursive expansion of nested BinXML values (EVT_XML).
pub const Builder = struct {
    ctx: *Context,
    allocator: std.mem.Allocator,

    pub fn init(ctx: *Context, allocator: std.mem.Allocator) Builder {
        return .{ .ctx = ctx, .allocator = allocator };
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

        // Detect and handle template instances vs regular elements
        if (try self.isTemplateInstance(&r)) {
            return self.buildTemplate(chunk, &r);
        }

        return self.buildRegular(chunk, &r);
    }

    /// Creates a minimal <Event/> element for empty records.
    fn buildEmpty(self: *Builder) !*IR.Element {
        const bytes: []u8 = try util.utf16FromAscii(self.allocator, "Event");
        return IRMod.irNewElement(self.allocator, IR.Name{
            .InlineUtf16 = .{ .bytes = bytes, .num_chars = 5 },
        });
    }

    /// Checks if the next token indicates a template instance.
    fn isTemplateInstance(_: *Builder, r: *Reader) !bool {
        if (r.rem() == 0) return false;
        const first = try r.peekU8();
        return first == tokens.TOK_TEMPLATE_INSTANCE;
    }

    /// Parses a regular (non-template) element and expands any nested BinXML.
    fn buildRegular(self: *Builder, chunk: []const u8, r: *Reader) !*IR.Element {
        // 1. Parse the element into IR
        const root = try binxml_parser.parseElementIR(self.ctx, chunk, r, self.allocator, .rec);

        // 2. Expand values (trivial for regular elements, but standardizes flow)
        var expander = Expander.init(self.ctx, self.allocator);
        const expanded_root = try expander.expand(root, &[_]types.TemplateValue{});

        // 3. Handle nested BinXML payloads (e.g., inside attributes or values)
        try self.spliceNestedBinXml(chunk, expanded_root);

        return expanded_root;
    }

    /// Parses a template instance, looks up or parses the definition, and expands it.
    fn buildTemplate(self: *Builder, chunk: []const u8, r: *Reader) !*IR.Element {
        const header = try r.readStruct(types.TemplateInstanceStart);
        if ((header.token & 0x1f) != tokens.TOK_TEMPLATE_INSTANCE) {
            return error.BadToken;
        }

        // Handle inline definition if present
        try common.skipInlineTemplateDefinition(r, header.def_data_off);
        common.skipInlineCachedTemplateDefs(r);

        // Retrieve template definition (cached or parsed)
        const def_ptr = try self.getOrParseTemplateDef(chunk, header.def_data_off);
        const def = def_ptr.*;

        // Parse substitution values
        const values = try binxml_parser.parseTemplateInstanceValues(r, self.allocator);

        // Expand template with values
        var expander = Expander.init(self.ctx, self.allocator);
        const expanded = try expander.expand(def, values);

        // Handle nested BinXML payloads
        try self.spliceNestedBinXml(chunk, expanded);

        return expanded;
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
        // TemplateDefinitionHeader: [next_offset: u32][guid: u128][data_size: u32]
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

        // Read header manually or via struct to get data size
        // We use manual slice reading here to be safe with alignment/bounds, mostly just need data_size
        // TemplateDefinitionHeader is 24 bytes. data_size is at offset 20.
        const size_slice = chunk[def_off + 20 .. def_off + 24];
        const data_size = std.mem.readInt(u32, size_slice[0..4], .little);

        if (log.enabled(.trace)) {
            log.trace("parseTemplateDef: off=0x{x} size=0x{x}", .{ def_data_off, data_size });
        }

        const data_start = def_off + 24; // sizeof(TemplateDefinitionHeader)
        const data_end = data_start + @as(usize, data_size);

        if (data_end > chunk.len) return error.OutOfBounds;

        var def_r = Reader.init(chunk[data_start..data_end]);
        try common.skipFragmentHeaderIfPresent(&def_r);

        // .def source mode handles specific name parsing rules for templates
        return binxml_parser.parseElementIRWithBase(self.ctx, chunk, &def_r, self.allocator, .def, data_start);
    }

    // --- Nested BinXML Handling ---

    /// Recursively scans the expanded tree for nested BinXML values (EVT_XML)
    /// and splices them into the tree as proper children.
    ///
    /// This is necessary because some events embed full XML fragments as binary
    /// values (type 0x21) which need to be promoted to first-class XML structure.
    /// Explicitly use `anyerror` to avoid recursive inferred-error-set issues.
    fn spliceNestedBinXml(self: *Builder, chunk: []const u8, el: *IR.Element) anyerror!void {
        // We need to check both attributes and children for 0x21 (BinXML) values.
        // If found, we parse them and collect the resulting nodes.

        // 1. Collect children from attributes (weird but possible in BinXML schema)
        var extra_children = std.ArrayList(IR.Node).initCapacity(self.allocator, 0) catch unreachable;

        for (el.attrs.items) |attr| {
            for (attr.value.items) |node| {
                if (self.isNestedBinXmlNode(node)) {
                    try self.collectNestedChildren(chunk, node.vbytes, &extra_children);
                }
            }
        }

        // 2. Rebuild children list if we have nested content or extra children
        var new_children = std.ArrayList(IR.Node).initCapacity(self.allocator, 0) catch unreachable;

        // Pre-allocate if we can guess size (existing + extra)
        const estimated_cap = el.children.items.len + extra_children.items.len;
        if (estimated_cap > 0) {
            try new_children.ensureTotalCapacityPrecise(self.allocator, estimated_cap);
        }

        for (el.children.items) |node| {
            switch (node.tag) {
                .Element => {
                    // Recurse into child elements
                    if (node.elem) |child_elem| {
                        try self.spliceNestedBinXml(chunk, child_elem);
                    }
                    try new_children.append(self.allocator, node);
                },
                .Value => {
                    if (self.isNestedBinXmlNode(node)) {
                        // Expand this node into multiple children
                        try self.collectNestedChildren(chunk, node.vbytes, &new_children);
                    } else {
                        try new_children.append(self.allocator, node);
                    }
                },
                else => try new_children.append(self.allocator, node),
            }
        }

        // Append any children collected from attributes
        for (extra_children.items) |child| {
            try new_children.append(self.allocator, child);
        }

        el.children = new_children;
    }

    fn isNestedBinXmlNode(_: *Builder, node: IR.Node) bool {
        return node.tag == .Value and
            (node.vtype & 0x7f) == 0x21 and
            node.vbytes.len > 0;
    }

    /// Parses a nested BinXML blob and appends resulting elements/nodes to `out`.
    fn collectNestedChildren(self: *Builder, chunk: []const u8, data: []const u8, out: *std.ArrayList(IR.Node)) !void {
        if (data.len == 0) return;
        var r = Reader.init(data);
        try common.skipFragmentHeaderIfPresent(&r);

        while (r.rem() > 0) {
            const pk = r.peekU8() catch break;
            if (pk != tokens.TOK_TEMPLATE_INSTANCE) break;

            // Parse the nested template instance
            // We recurse by calling buildTemplate logic essentially
            const header = r.readStruct(types.TemplateInstanceStart) catch break;

            common.skipInlineTemplateDefinition(&r, header.def_data_off) catch break;
            common.skipInlineCachedTemplateDefs(&r);

            const def_ptr = try self.getOrParseTemplateDef(chunk, header.def_data_off);
            const def = def_ptr.*;

            const vals = try binxml_parser.parseTemplateInstanceValues(&r, self.allocator);

            var expander = Expander.init(self.ctx, self.allocator);
            const expanded_child = try expander.expand(def, vals);

            // Recurse for deeper nesting
            try self.spliceNestedBinXml(chunk, expanded_child);

            try out.append(self.allocator, .{ .tag = .Element, .elem = expanded_child });
        }
    }
};
