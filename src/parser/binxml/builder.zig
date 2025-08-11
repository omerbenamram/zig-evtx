const std = @import("std");
const Reader = @import("../reader.zig").Reader;
const IRMod = @import("../ir.zig");
const IR = IRMod.IR;
const Context = @import("context.zig").Context;
const Parser = @import("parser.zig").Parser;
const Expander = @import("expander.zig").Expander;
const types = @import("types.zig");
const tokens = @import("tokens.zig");
const common = @import("common.zig");
const util = @import("../util.zig");

// Thin convenience facade: parse + expand to a fully expanded IR tree.
// For now this forwards to core functions in binxml.zig via Parser/Expander wrappers.

pub const Builder = struct {
    ctx: *Context,
    allocator: std.mem.Allocator,

    pub fn init(ctx: *Context, allocator: std.mem.Allocator) Builder {
        return .{ .ctx = ctx, .allocator = allocator };
    }

    pub fn buildExpandedElementTree(self: *Builder, chunk: []const u8, bin: []const u8) !*IR.Element {
        var r = Reader.init(bin);
        try common.skipFragmentHeaderIfPresent(&r);
        if (r.rem() == 0) {
            // Build minimal <Event/> IR
            const bytes: []u8 = try util.utf16FromAscii(self.ctx.arena.allocator(), "Event");
            return try IRMod.irNewElement(self.ctx.arena.allocator(), IR.Name{ .InlineUtf16 = .{ .bytes = bytes, .num_chars = 5 } });
        }
        const first = try r.peekU8();
        // Parse using the per-chunk arena for all IR allocations
        var parser = Parser.init(self.ctx, self.ctx.arena.allocator());
        if (first == tokens.TOK_TEMPLATE_INSTANCE) {
            _ = try r.readU8();
            if (r.rem() < 1 + 4 + 4) return error.UnexpectedEof;
            _ = try r.readU8(); // unknown
            _ = try r.readU32le(); // template id
            const def_data_off = try r.readU32le();
            if (def_data_off == @as(u32, @intCast(r.pos))) {
                if (r.rem() < 24) return error.UnexpectedEof;
                _ = try r.readU32le();
                _ = try r.readGuid();
                const data_size_inline = try r.readU32le();
                if (r.rem() < data_size_inline) return error.UnexpectedEof;
                r.pos += @as(usize, data_size_inline);
            }
            common.skipInlineCachedTemplateDefs(&r);
            const parsed = try parseTemplateDefFromChunk(self.ctx, chunk, def_data_off, self.ctx.arena.allocator());
            const parsed_def = parsed.def;
            const expected = @import("parser.zig").expectedValuesFromTemplate(parsed_def);
            const values = try @import("parser.zig").parseTemplateInstanceValuesExpected(&r, self.ctx.arena.allocator(), expected);
            var guid: [16]u8 = undefined;
            const def_off_usize2: usize = @intCast(def_data_off);
            std.mem.copyForwards(u8, guid[0..], chunk[def_off_usize2 + 4 .. def_off_usize2 + 20]);
            const key: Context.DefKey = .{ .def_data_off = def_data_off, .guid = guid };
            const got = try self.ctx.cache.getOrPut(key);
            if (!got.found_existing) got.value_ptr.* = parsed_def;
            // Expand into arena-owned IR to avoid libc allocation churn
            var expander = Expander.init(self.ctx, self.ctx.arena.allocator());
            const expanded = try expander.expandElementWithValues(got.value_ptr.*, values);
            try spliceEvtXmlAll(self.ctx, chunk, expanded, self.ctx.arena.allocator());
            return expanded;
        }
        const root = try parser.parseElementIR(chunk, &r, .rec);
        var expander = Expander.init(self.ctx, self.ctx.arena.allocator());
        const expanded_root = try expander.expandElementWithValues(root, &[_]types.TemplateValue{});
        try spliceEvtXmlAll(self.ctx, chunk, expanded_root, self.ctx.arena.allocator());
        return expanded_root;
    }

    // Local copies removed; use common.zig
    fn parseTemplateDefFromChunk(ctx: *Context, chunk: []const u8, def_data_off: u32, allocator: std.mem.Allocator) !struct { def: *IR.Element, data_start: usize } {
        const def_off_usize: usize = @intCast(def_data_off);
        if (def_off_usize + 24 > chunk.len) return error.OutOfBounds;
        const td_data_size = std.mem.readInt(u32, chunk[def_off_usize + 20 .. def_off_usize + 24][0..4], .little);
        const data_start = def_off_usize + 24;
        const data_end = data_start + @as(usize, td_data_size);
        if (data_end > chunk.len or data_start >= chunk.len) return error.OutOfBounds;
        var def_r = Reader.init(chunk[data_start..data_end]);
        try common.skipFragmentHeaderIfPresent(&def_r);
        var p = Parser.init(ctx, allocator);
        const parsed_def = try p.parseElementIRWithBase(chunk, &def_r, .def, data_start);
        return .{ .def = parsed_def, .data_start = data_start };
    }
    fn collectEvtXmlPayloadChildren(ctx: *Context, chunk: []const u8, data: []const u8, alloc: std.mem.Allocator, out: *std.ArrayList(IR.Node)) !void {
        if (data.len == 0) return;
        var r = Reader.init(data);
        try common.skipFragmentHeaderIfPresent(&r);
        while (r.rem() > 0) {
            const pk = r.buf[r.pos];
            if (pk != tokens.TOK_TEMPLATE_INSTANCE) break;
            _ = try r.readU8();
            if (r.rem() < 1 + 4 + 4) break;
            _ = try r.readU8();
            _ = try r.readU32le();
            const def_data_off = try r.readU32le();
            common.skipInlineCachedTemplateDefs(&r);
            const parsed = try parseTemplateDefFromChunk(ctx, chunk, def_data_off, alloc);
            const child_def = parsed.def;
            const expected = @import("parser.zig").expectedValuesFromTemplate(child_def);
            const vals = try @import("parser.zig").parseTemplateInstanceValuesExpected(&r, alloc, expected);
            var expander = Expander.init(ctx, alloc);
            const expanded_child = try expander.expandElementWithValues(child_def, vals);
            try out.append(.{ .tag = .Element, .elem = expanded_child });
        }
    }
    fn spliceEvtXmlAll(ctx: *Context, chunk: []const u8, el: *IR.Element, alloc: std.mem.Allocator) !void {
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
                        try collectEvtXmlPayloadChildren(ctx, chunk, nd.vbytes, alloc, &new_children);
                    } else {
                        try new_children.append(nd);
                    }
                },
                else => try new_children.append(nd),
            }
        }
        var k: usize = 0;
        while (k < staged_attr_children.items.len) : (k += 1) try new_children.append(staged_attr_children.items[k]);
        el.children = new_children;
    }
    // utf16FromAscii moved to util.zig
};
