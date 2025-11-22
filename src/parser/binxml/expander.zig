const std = @import("std");
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const Context = @import("context.zig").Context;
const types = @import("types.zig");

pub const JoinerPolicy = enum { Attr, Text };

/// The Expander handles the instantiation of templates.
/// It replaces substitution nodes (placeholders) with actual values from the event data.
pub const Expander = struct {
    ctx: *Context,
    allocator: std.mem.Allocator,

    pub fn init(ctx: *Context, allocator: std.mem.Allocator) Expander {
        return .{ .ctx = ctx, .allocator = allocator };
    }

    /// Expands a template definition element into a concrete element instance using the provided values.
    /// Recursive substitutions are handled here.
    /// Use `anyerror` to avoid inferred-error-set issues with recursive expansion.
    pub fn expand(self: *Expander, src: *const IR.Element, values: []const types.TemplateValue) anyerror!*IR.Element {
        const dst = try IRModule.irNewElement(self.allocator, src.name);

        // Pre-size destination containers
        if (src.attrs.items.len > 0) {
            try dst.attrs.ensureTotalCapacityPrecise(self.allocator, src.attrs.items.len);
        }

        // 1. Expand Attributes
        for (src.attrs.items) |attr| {
            const expanded_value = try self.expandNodes(attr.value.items, values, .Attr);
            try dst.attrs.append(self.allocator, .{ .name = attr.name, .value = expanded_value });
        }

        // 2. Expand Children
        const expanded_children = try self.expandNodes(src.children.items, values, .Text);

        // Copy children to destination
        if (expanded_children.items.len > 0) {
            try dst.children.ensureTotalCapacityPrecise(self.allocator, expanded_children.items.len);
        }
        for (expanded_children.items) |child| {
            try dst.children.append(self.allocator, child);
        }

        // 3. Copy flags (resetting expansion-specific ones)
        dst.has_element_child = src.has_element_child;

        return dst;
    }

    /// Expands a list of nodes, handling substitutions and recursion.
    fn expandNodes(
        self: *Expander,
        nodes: []const IR.Node,
        values: []const types.TemplateValue,
        policy: JoinerPolicy,
    ) !std.ArrayList(IR.Node) {
        var out = std.ArrayList(IR.Node).initCapacity(self.allocator, 0) catch unreachable;
        if (nodes.len > 0) {
            try out.ensureTotalCapacityPrecise(self.allocator, nodes.len);
        }

        for (nodes) |nd| {
            switch (nd.tag) {
                .Subst => try self.handleSubstitution(nd, values, policy, &out),
                .Element => try self.handleRecursiveElement(nd, values, &out),
                else => try out.append(self.allocator, nd),
            }
        }
        return out;
    }

    fn handleSubstitution(
        self: *Expander,
        nd: IR.Node,
        values: []const types.TemplateValue,
        policy: JoinerPolicy,
        out: *std.ArrayList(IR.Node),
    ) !void {
        if (nd.subst_id >= values.len) return; // Out of bounds substitution, ignore

        const val = values[nd.subst_id];

        // Skip optional empty substitutions
        if (nd.subst_optional and (val.t == 0x00 or val.data.len == 0)) {
            return;
        }

        const is_array = (nd.subst_vtype & types.ValueType.ARRAY_FLAG) != 0;
        const base_type = nd.subst_vtype & 0x7f;

        if (is_array) {
            try self.expandArrayValue(base_type, val, policy, out);
        } else {
            try self.expandSingleValue(base_type, val, out);
        }
    }

    fn expandSingleValue(
        self: *Expander,
        base_type: u8,
        val: types.TemplateValue,
        out: *std.ArrayList(IR.Node),
    ) !void {
        // String types (0x01) are treated as Text nodes for proper XML escaping/joining
        if (base_type == @intFromEnum(types.ValueType.string)) {
            // Check for null-terminator to trim
            var num_chars = val.data.len / 2;
            if (num_chars > 0) {
                const last_char = std.mem.readInt(u16, val.data[val.data.len - 2 .. val.data.len][0..2], .little);
                if (last_char == 0) num_chars -= 1;
            }

            try out.append(self.allocator, .{
                .tag = .Text,
                .text_utf16 = val.data[0 .. num_chars * 2],
                .text_num_chars = num_chars,
            });
        } else {
            try out.append(self.allocator, .{
                .tag = .Value,
                .vtype = val.t,
                .vbytes = val.data,
            });
        }
    }

    fn expandArrayValue(
        self: *Expander,
        base_type: u8,
        val: types.TemplateValue,
        policy: JoinerPolicy,
        out: *std.ArrayList(IR.Node),
    ) !void {
        var iter = ArrayIterator{
            .data = val.data,
            .base_type = base_type,
            .backing_type = val.t,
        };

        var first = true;
        const sep_ascii = joinerFor(policy, base_type);

        const sep_utf16 = if (sep_ascii.len > 0)
            try self.ctx.getSepUtf16(sep_ascii)
        else
            null;

        while (iter.next()) |item_bytes| {
            if (!first) {
                if (sep_utf16) |sep| {
                    try out.append(self.allocator, .{ .tag = .Text, .text_utf16 = sep.bytes, .text_num_chars = sep.num_chars });
                }
            }
            first = false;

            // Recursively handle single value logic for array items
            // Construct a temporary TemplateValue for the item
            const item_val = types.TemplateValue{ .t = base_type, .data = item_bytes };
            try self.expandSingleValue(base_type, item_val, out);
        }
    }

    fn handleRecursiveElement(
        self: *Expander,
        nd: IR.Node,
        values: []const types.TemplateValue,
        out: *std.ArrayList(IR.Node),
    ) !void {
        const child_elem = nd.elem.?;
        var sub_expander = Expander.init(self.ctx, self.allocator);
        // Pass pointer to child_elem since expand expects *const IR.Element
        const expanded_child = sub_expander.expand(child_elem, values) catch |err| return err;

        try out.append(self.allocator, .{ .tag = .Element, .elem = expanded_child });
    }
};

/// Returns the separator string for array joining based on policy and type.
fn joinerFor(policy: JoinerPolicy, base: u8) []const u8 {
    return switch (policy) {
        .Attr => " ",
        .Text => if (base == @intFromEnum(types.ValueType.string) or
            base == @intFromEnum(types.ValueType.ansi_string)) "," else " ",
    };
}

/// Iterator for parsing binary array payloads.
const ArrayIterator = struct {
    data: []const u8,
    base_type: u8,
    backing_type: u8,
    cursor: usize = 0,

    pub fn next(self: *ArrayIterator) ?[]const u8 {
        if (self.cursor >= self.data.len) return null;

        // Determine the size of the next item based on type
        const start = self.cursor;
        var end = start;

        switch (self.base_type) {
            0x01 => { // Unicode string (NUL-terminated in sequence)
                // Scan for double-null (0x0000)
                if (self.data.len - start < 2) {
                    self.cursor = self.data.len;
                    return null;
                }
                while (end + 1 < self.data.len) : (end += 2) {
                    const ch = std.mem.readInt(u16, self.data[end .. end + 2][0..2], .little);
                    if (ch == 0) break;
                }
                // Advance past NUL for next item, but return slice including NUL if present (logic in expandSingleValue handles trimming)
                const next_start = if (end + 1 < self.data.len) end + 2 else end;
                if (next_start <= start) { // Infinite loop guard
                    self.cursor = self.data.len;
                    return null;
                }
                self.cursor = next_start;
                return self.data[start..end]; // Return data WITHOUT null terminator for cleaner consistency?
                // Original logic returned data[start..end] where end pointed AT the null terminator?
                // Let's check old logic: `return data[start..end]` where end loop stopped at NUL.
                // So it excluded the NUL bytes in the returned slice.
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
                // SID structure: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthorities(SubAuthorityCount * 4)
                // Total header = 8 bytes.
                if (start + 8 > self.data.len) return null;
                const sub_count = self.data[start + 1];
                const size = 8 + @as(usize, sub_count) * 4;
                if (start + size > self.data.len) return null;
                self.cursor = start + size;
                return self.data[start .. start + size];
            },
            0x10 => { // SizeT (architecture dependent, stored as fixed 4 or 8 bytes)
                var size: usize = 0;
                if (self.backing_type == 0x94) size = 4 // HexInt32
                else if (self.backing_type == 0x95) size = 8 // HexInt64
                else return null; // Should not happen for valid chunks

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
                // Unknown type or not array-compatible
                return null;
            },
        }
    }
};
