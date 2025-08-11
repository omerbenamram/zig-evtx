const std = @import("std");
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const Context = @import("context.zig").Context;
const types = @import("types.zig");

pub const JoinerPolicy = enum { Attr, Text };

pub const Expander = struct {
    ctx: *Context,
    allocator: std.mem.Allocator,

    pub fn init(ctx: *Context, allocator: std.mem.Allocator) Expander {
        return .{ .ctx = ctx, .allocator = allocator };
    }

    // Expand substitutions inside a template definition IR using a specific substitution array (scope).
    // This matches the core behavior and preserves all semantics.
    pub fn expandElementWithValues(self: *Expander, src: *const IR.Element, values: []const types.TemplateValue) !*IR.Element {
        const dst = try IRModule.irNewElement(self.allocator, src.name);
        // Pre-size destination containers based on source sizes
        if (src.attrs.items.len > 0) try dst.attrs.ensureTotalCapacityPrecise(src.attrs.items.len);
        // attributes
        var ai: usize = 0;
        while (ai < src.attrs.items.len) : (ai += 1) {
            const a = src.attrs.items[ai];
            const expanded = try cloneNodesReplacingSubstWithPolicy(self.ctx, .Attr, self.allocator, a.value.items, values);
            try dst.attrs.append(.{ .name = a.name, .value = expanded });
        }
        // children
        const expanded_children = try cloneNodesReplacingSubstWithPolicy(self.ctx, .Text, self.allocator, src.children.items, values);
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
};

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
            if (types.valueTypeFixedSize(base)) |esz| {
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

fn cloneNodesReplacingSubstWithPolicy(ctx: *Context, policy: JoinerPolicy, alloc: std.mem.Allocator, nodes: []const IR.Node, values: []const types.TemplateValue) anyerror!std.ArrayList(IR.Node) {
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
                const eff_vals: []const types.TemplateValue = if (child.local_values.len > 0) child.local_values else values;
                var sub_expander = Expander.init(ctx, alloc);
                const repl = try sub_expander.expandElementWithValues(child, eff_vals);
                try out.append(.{ .tag = .Element, .elem = repl });
            },
            else => try out.append(nd),
        }
    }
    return out;
}
