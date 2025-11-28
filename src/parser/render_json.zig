const std = @import("std");
const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const util = @import("util.zig");
const utf16EqualsAscii = util.utf16EqualsAscii;
const formatIso8601UtcFromFiletimeMicros = util.formatIso8601UtcFromFiletimeMicros;
const writeUtf16LeRawToUtf8 = util.writeUtf16LeRawToUtf8;
const jsonEscapeUtf8 = util.jsonEscapeUtf8;
const writeUtf16LeJsonEscaped = util.writeUtf16LeJsonEscaped;
const writeAnsiCp1252JsonEscaped = util.writeAnsiCp1252JsonEscaped;
const attrNameIsSystemTime = @import("binxml/name.zig").attrNameIsSystemTime;

fn writeNameJsonQuoted(w: anytype, name: IR.Name, chunk: []const u8) !void {
    _ = chunk;
    try w.writeByte('"');
    try writeUtf16LeJsonEscaped(w, name.bytes, name.num_chars);
    try w.writeByte('"');
}

fn writeValueJson(w: anytype, t: u8, data: []const u8) !void {
    switch (t) {
        0x03 => { // Int8
            if (data.len < 1) return;
            const v: i8 = @bitCast(data[0]);
            try w.print("{d}", .{v});
        },
        0x04 => { // UInt8
            if (data.len < 1) return;
            try w.print("{d}", .{data[0]});
        },
        0x05 => { // Int16
            if (data.len < 2) return;
            const v = std.mem.readInt(i16, data[0..2], .little);
            try w.print("{d}", .{v});
        },
        0x06 => { // UInt16
            if (data.len < 2) return;
            const v = std.mem.readInt(u16, data[0..2], .little);
            try w.print("{d}", .{v});
        },
        0x07 => { // Int32
            if (data.len < 4) return;
            const v = std.mem.readInt(i32, data[0..4], .little);
            try w.print("{d}", .{v});
        },
        0x08 => { // UInt32
            if (data.len < 4) return;
            const v = std.mem.readInt(u32, data[0..4], .little);
            try w.print("{d}", .{v});
        },
        0x09 => { // Int64
            if (data.len < 8) return;
            const v = std.mem.readInt(i64, data[0..8], .little);
            try w.print("{d}", .{v});
        },
        0x0a => { // UInt64
            if (data.len < 8) return;
            const v = std.mem.readInt(u64, data[0..8], .little);
            try w.print("{d}", .{v});
        },
        0x0b => { // Real32
            if (data.len < 4) return;
            const bits = std.mem.readInt(u32, data[0..4], .little);
            const f: f32 = @bitCast(bits);
            if (std.math.isNan(f)) return try w.writeAll("\"-1.#IND\"");
            if (std.math.isInf(f)) return try w.writeAll(if (f > 0) "\"1.#INF\"" else "\"-1.#INF\"");
            try w.print("{d}", .{f});
        },
        0x0c => { // Real64
            if (data.len < 8) return;
            const bits = std.mem.readInt(u64, data[0..8], .little);
            const f: f64 = @bitCast(bits);
            if (std.math.isNan(f)) return try w.writeAll("\"-1.#IND\"");
            if (std.math.isInf(f)) return try w.writeAll(if (f > 0) "\"1.#INF\"" else "\"-1.#INF\"");
            try w.print("{d}", .{f});
        },
        0x0d => { // Bool
            if (data.len < 4) return;
            const v = std.mem.readInt(u32, data[0..4], .little);
            try w.writeAll(if (v == 0) "false" else "true");
        },
        0x0f => { // GUID
            if (data.len < 16) return;
            const d1 = std.mem.readInt(u32, data[0..4], .little);
            const d2 = std.mem.readInt(u16, data[4..6], .little);
            const d3 = std.mem.readInt(u16, data[6..8], .little);
            const d4 = data[8..16];
            try w.print("\"{{{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}}}\"", .{ d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7] });
        },
        0x11 => { // FILETIME
            if (data.len < 8) return;
            const ft = std.mem.readInt(u64, data[0..8], .little);
            var buf: [40]u8 = undefined;
            const out = formatIso8601UtcFromFiletimeMicros(&buf, ft) catch {
                return try w.print("{d}", .{ft});
            };
            try w.writeByte('"');
            try w.writeAll(out);
            try w.writeByte('"');
        },
        0x12 => { // SysTime
            if (data.len < 16) return;
            const year = std.mem.readInt(u16, data[0..2], .little);
            const month = std.mem.readInt(u16, data[2..4], .little);
            const day = std.mem.readInt(u16, data[6..8], .little);
            const hour = std.mem.readInt(u16, data[8..10], .little);
            const minute = std.mem.readInt(u16, data[10..12], .little);
            const second = std.mem.readInt(u16, data[12..14], .little);
            const millis = std.mem.readInt(u16, data[14..16], .little);
            var buf: [32]u8 = undefined;
            const slice = try std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{ year, month, day, hour, minute, second, millis });
            try w.writeByte('"');
            try w.writeAll(slice);
            try w.writeByte('"');
        },
        0x13 => { // SID
            if (data.len < 8) return error.UnexpectedEof;
            const rev = data[0];
            const sub_count = data[1];
            const ida_bytes = data[2..8];
            var idauth: u64 = 0;
            var k: usize = 0;
            while (k < 6) : (k += 1) idauth = (idauth << 8) | ida_bytes[k];
            try w.print("\"S-{d}-{d}", .{ rev, idauth });
            var off: usize = 8;
            var i: usize = 0;
            while (i < sub_count and off + 4 <= data.len) : (i += 1) {
                const sub = std.mem.readInt(u32, data[off .. off + 4][0..4], .little);
                off += 4;
                try w.print("-{d}", .{sub});
            }
            try w.writeByte('"');
        },
        0x14 => { // HexInt32
            if (data.len < 4) return error.UnexpectedEof;
            const v = std.mem.readInt(u32, data[0..4], .little);
            try w.print("\"0x{X}\"", .{v});
        },
        0x15 => { // HexInt64
            if (data.len < 8) return error.UnexpectedEof;
            const v = std.mem.readInt(u64, data[0..8], .little);
            try w.print("\"0x{X}\"", .{v});
        },
        0x01 => { // StringType (UTF-16 sized)
            if (data.len == 0) return try w.writeAll("\"\"");
            if ((data.len & 1) != 0) return error.UnexpectedEof;
            var num = data.len / 2;
            if (num > 0) {
                const last = std.mem.readInt(u16, data[data.len - 2 .. data.len][0..2], .little);
                if (last == 0) num -= 1;
            }
            try w.writeByte('"');
            if (num > 0) try writeUtf16LeJsonEscaped(w, data[0 .. num * 2], num);
            try w.writeByte('"');
        },
        0x02 => { // ANSI CP-1252
            try w.writeByte('"');
            try writeAnsiCp1252JsonEscaped(w, data);
            try w.writeByte('"');
        },
        0x0e => { // Binary -> hex string
            try w.writeByte('"');
            var i: usize = 0;
            while (i < data.len) : (i += 1) try w.print("{x:0>2}", .{data[i]});
            try w.writeByte('"');
        },
        0x20 => { // EvtHandle
            if (data.len >= 8) {
                const v = std.mem.readInt(u64, data[0..8], .little);
                try w.print("{d}", .{v});
            } else if (data.len >= 4) {
                const v = std.mem.readInt(u32, data[0..4], .little);
                try w.print("{d}", .{v});
            } else try w.writeAll("0");
        },
        0x23 => { // EvtXml opaque -> hex string
            try w.writeByte('"');
            var i: usize = 0;
            while (i < data.len) : (i += 1) try w.print("{x:0>2}", .{data[i]});
            try w.writeByte('"');
        },
        else => try w.writeAll("null"),
    }
}

fn renderTextToJsonString(_: []const u8, nodes: []const IR.Node, w: anytype) !void {
    try w.writeByte('"');
    for (nodes) |nd| {
        switch (nd) {
            .Text => |text| try writeUtf16LeJsonEscaped(w, text.utf16, text.num_chars),
            .Pad => {},
            .Value => |val| try writeValueInlineJson(w, val.vtype, val.bytes),
            .CharRef => |charref| try w.print("&#{d};", .{charref}),
            .EntityRef => try w.writeByte('&'),
            .CData => |cdata| try writeUtf16LeJsonEscaped(w, cdata.utf16, cdata.num_chars),
            .PITarget, .PIData, .Element, .Subst => {},
        }
    }
    try w.writeByte('"');
}

/// Writes a value inline within a JSON string (no surrounding quotes)
fn writeValueInlineJson(w: anytype, vtype: u8, data: []const u8) !void {
    switch (vtype & 0x7f) {
        0x03 => if (data.len >= 1) try w.print("{d}", .{@as(i8, @bitCast(data[0]))}),
        0x04 => if (data.len >= 1) try w.print("{d}", .{data[0]}),
        0x05 => if (data.len >= 2) try w.print("{d}", .{std.mem.readInt(i16, data[0..2], .little)}),
        0x06 => if (data.len >= 2) try w.print("{d}", .{std.mem.readInt(u16, data[0..2], .little)}),
        0x07 => if (data.len >= 4) try w.print("{d}", .{std.mem.readInt(i32, data[0..4], .little)}),
        0x08 => if (data.len >= 4) try w.print("{d}", .{std.mem.readInt(u32, data[0..4], .little)}),
        0x09 => if (data.len >= 8) try w.print("{d}", .{std.mem.readInt(i64, data[0..8], .little)}),
        0x0a => if (data.len >= 8) try w.print("{d}", .{std.mem.readInt(u64, data[0..8], .little)}),
        0x0b => if (data.len >= 4) {
            const bits = std.mem.readInt(u32, data[0..4], .little);
            const f: f32 = @bitCast(bits);
            if (std.math.isNan(f)) try w.writeAll("-1.#IND") else if (std.math.isInf(f)) try w.writeAll(if (f > 0) "1.#INF" else "-1.#INF") else try w.print("{d}", .{f});
        },
        0x0c => if (data.len >= 8) {
            const bits = std.mem.readInt(u64, data[0..8], .little);
            const f: f64 = @bitCast(bits);
            if (std.math.isNan(f)) try w.writeAll("-1.#IND") else if (std.math.isInf(f)) try w.writeAll(if (f > 0) "1.#INF" else "-1.#INF") else try w.print("{d}", .{f});
        },
        0x0d => if (data.len >= 4) try w.writeAll(if (std.mem.readInt(u32, data[0..4], .little) == 0) "false" else "true"),
        0x0f => if (data.len >= 16) {
            const d1 = std.mem.readInt(u32, data[0..4], .little);
            const d2 = std.mem.readInt(u16, data[4..6], .little);
            const d3 = std.mem.readInt(u16, data[6..8], .little);
            const d4 = data[8..16];
            try w.print("{{{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}}}", .{ d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7] });
        },
        0x11 => if (data.len >= 8) {
            const ft = std.mem.readInt(u64, data[0..8], .little);
            var buf: [40]u8 = undefined;
            const out = formatIso8601UtcFromFiletimeMicros(&buf, ft) catch return;
            try w.writeAll(out);
        },
        0x12 => if (data.len >= 16) {
            const year = std.mem.readInt(u16, data[0..2], .little);
            const month = std.mem.readInt(u16, data[2..4], .little);
            const day = std.mem.readInt(u16, data[6..8], .little);
            const hour = std.mem.readInt(u16, data[8..10], .little);
            const minute = std.mem.readInt(u16, data[10..12], .little);
            const second = std.mem.readInt(u16, data[12..14], .little);
            const millis = std.mem.readInt(u16, data[14..16], .little);
            try w.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{ year, month, day, hour, minute, second, millis });
        },
        0x13 => if (data.len >= 8) {
            const rev = data[0];
            const sub_count = data[1];
            const ida_bytes = data[2..8];
            var idauth: u64 = 0;
            var kk: usize = 0;
            while (kk < 6) : (kk += 1) idauth = (idauth << 8) | ida_bytes[kk];
            try w.print("S-{d}-{d}", .{ rev, idauth });
            var off: usize = 8;
            var si: usize = 0;
            while (si < sub_count and off + 4 <= data.len) : (si += 1) {
                const sub = std.mem.readInt(u32, data[off .. off + 4][0..4], .little);
                off += 4;
                try w.print("-{d}", .{sub});
            }
        },
        0x14 => if (data.len >= 4) try w.print("0x{X}", .{std.mem.readInt(u32, data[0..4], .little)}),
        0x15 => if (data.len >= 8) try w.print("0x{X}", .{std.mem.readInt(u64, data[0..8], .little)}),
        0x01 => {
            if (data.len > 0) {
                var num = data.len / 2;
                if (num > 0 and std.mem.readInt(u16, data[data.len - 2 .. data.len][0..2], .little) == 0) num -= 1;
                if (num > 0) try writeUtf16LeJsonEscaped(w, data[0 .. num * 2], num);
            }
        },
        0x02 => try writeAnsiCp1252JsonEscaped(w, data),
        0x0e => {
            for (data) |b| try w.print("{x:0>2}", .{b});
        },
        else => {},
    }
}

fn renderAttrValueToJsonString(chunk: []const u8, nodes: []const IR.Node, w: anytype) !void {
    try renderTextToJsonString(chunk, nodes, w);
}

fn isLeafString(el: *const IR.Element) bool {
    return el.attrs.items.len == 0 and !el.has_element_child;
}

fn writeElementBodyJson(chunk: []const u8, el: *const IR.Element, alloc: std.mem.Allocator, w: anytype) !void {
    // Group child elements by name
    var groups = std.StringHashMap(std.ArrayList(*IR.Element)).init(alloc);
    defer groups.deinit();
    var has_textual: bool = false;
    var textual_nodes = std.ArrayList(IR.Node).initCapacity(alloc, 0) catch unreachable;
    defer textual_nodes.deinit(alloc);

    if (el.children.items.len > 0) try textual_nodes.ensureTotalCapacityPrecise(alloc, el.children.items.len);
    for (el.children.items) |nd| {
        switch (nd) {
            .Element => |child| {
                // Convert name to UTF-8 key
                var key_builder = std.ArrayList(u8).initCapacity(alloc, 0) catch unreachable;
                defer key_builder.deinit(alloc);
                try writeUtf16LeJsonEscaped(key_builder.writer(alloc), child.name.bytes, child.name.num_chars);
                const key = try key_builder.toOwnedSlice(alloc);
                var entry = try groups.getOrPut(key);
                if (!entry.found_existing) {
                    entry.value_ptr.* = std.ArrayList(*IR.Element).initCapacity(alloc, 0) catch unreachable;
                    // Guess a small group size to avoid early growth (tuneable)
                    try entry.value_ptr.ensureTotalCapacityPrecise(alloc, 2);
                }
                try entry.value_ptr.append(alloc, child);
            },
            else => {
                has_textual = true;
                try textual_nodes.append(alloc, nd);
            },
        }
    }

    try w.writeByte('{');
    var wrote_any = false;

    // Attributes
    var ai: usize = 0;
    while (ai < el.attrs.items.len) : (ai += 1) {
        const a = el.attrs.items[ai];
        if (wrote_any) try w.writeByte(',');
        try w.writeByte('"');
        try w.writeByte('@');
        try writeUtf16LeJsonEscaped(w, a.name.bytes, a.name.num_chars);
        try w.writeAll("\":");
        // Special-case SystemTime normalization like XML path
        if (attrNameIsSystemTime(a.name)) {
            var tmp: [256]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&tmp);
            const aw = fbs.writer();
            var vi: usize = 0;
            while (vi < el.attrs.items[ai].value.items.len) : (vi += 1) {
                const ndv = el.attrs.items[ai].value.items[vi];
                if (ndv == .Text) {
                    try writeUtf16LeRawToUtf8(aw, ndv.Text.utf16, ndv.Text.num_chars);
                }
            }
            const ascii = fbs.getWritten();
            try w.writeByte('"');
            try util.normalizeAndWriteSystemTimeAscii(w, ascii);
            try w.writeByte('"');
        } else {
            // Render attribute value as JSON string
            try renderAttrValueToJsonString(chunk, a.value.items, w);
        }
        wrote_any = true;
    }

    // Textual content if present
    if (has_textual) {
        if (wrote_any) try w.writeByte(',');
        try w.writeAll("\"#text\":");
        try renderTextToJsonString(chunk, textual_nodes.items, w);
        wrote_any = true;
    }

    // Child element groups
    var it = groups.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const elems = entry.value_ptr.*;
        if (wrote_any) try w.writeByte(',');
        try w.writeByte('"');
        try jsonEscapeUtf8(w, key);
        try w.writeAll("\":");
        if (elems.items.len == 1) {
            const child = elems.items[0];
            if (isLeafString(child)) {
                // Represent as string
                // Collect child's textual nodes
                var text_nodes = std.ArrayList(IR.Node).initCapacity(alloc, 0) catch unreachable;
                defer text_nodes.deinit(alloc);
                for (child.children.items) |nd| {
                    if (nd != .Element) try text_nodes.append(alloc, nd);
                }
                try renderTextToJsonString(chunk, text_nodes.items, w);
            } else {
                try writeElementBodyJson(chunk, child, alloc, w);
            }
        } else {
            try w.writeByte('[');
            var k: usize = 0;
            while (k < elems.items.len) : (k += 1) {
                if (k > 0) try w.writeByte(',');
                const child = elems.items[k];
                if (isLeafString(child)) {
                    var text_nodes = std.ArrayList(IR.Node).initCapacity(alloc, 0) catch unreachable;
                    defer text_nodes.deinit(alloc);
                    for (child.children.items) |nd| {
                        if (nd != .Element) try text_nodes.append(alloc, nd);
                    }
                    try renderTextToJsonString(chunk, text_nodes.items, w);
                } else {
                    try writeElementBodyJson(chunk, child, alloc, w);
                }
            }
            try w.writeByte(']');
        }
        wrote_any = true;
    }

    try w.writeByte('}');
}

pub fn renderElementJson(chunk: []const u8, root: *const IR.Element, alloc: std.mem.Allocator, w: anytype) !void {
    // We produce body of the root element, not re-emitting the root name
    try writeElementBodyJson(chunk, root, alloc, w);
}
