const std = @import("std");
const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const util = @import("util.zig");
const writeUtf16LeJsonEscaped = util.writeUtf16LeJsonEscaped;
const writeAnsiCp1252JsonEscaped = util.writeAnsiCp1252JsonEscaped;
const writeUtf16LeRawToUtf8 = util.writeUtf16LeRawToUtf8;
const formatIso8601UtcFromFiletimeMicros = util.formatIso8601UtcFromFiletimeMicros;
const attrNameIsSystemTime = @import("binxml/name.zig").attrNameIsSystemTime;

fn jsonEscapeUtf8(w: anytype, s: []const u8) !void {
    try util.jsonEscapeUtf8(w, s);
}

fn writeNameJsonQuoted(w: anytype, name: IR.Name, chunk: []const u8) !void {
    try w.writeByte('"');
    switch (name) {
        .InlineUtf16 => |inl| try writeUtf16LeJsonEscaped(w, inl.bytes, inl.num_chars),
        .NameOffset => |off| {
            const o: usize = @intCast(off);
            if (o + 8 > chunk.len) return error.UnexpectedEof;
            const num_chars = std.mem.readInt(u16, chunk[o + 6 .. o + 8][0..2], .little);
            const str_start = o + 8;
            const byte_len = @as(usize, num_chars) * 2;
            if (str_start + byte_len > chunk.len) return error.UnexpectedEof;
            try writeUtf16LeJsonEscaped(w, chunk[str_start .. str_start + byte_len], num_chars);
        },
    }
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
        0x01 => { // UTF-16 sized string
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

fn writeNodesAsJsonString(chunk: []const u8, nodes: []const IR.Node, w: anytype) !void {
    // Render a sequence of nodes into a single JSON string value
    try w.writeByte('"');
    var i: usize = 0;
    while (i < nodes.len) : (i += 1) {
        const nd = nodes[i];
        switch (nd.tag) {
            .Text => try writeUtf16LeJsonEscaped(w, nd.text_utf16, nd.text_num_chars),
            .Pad => {
                // Pad for numeric width with leading zeros
                const width = nd.pad_width;
                if (width > 0 and i + 1 < nodes.len and nodes[i + 1].tag == .Value) {
                    const v = nodes[i + 1];
                    var tmp: [64]u8 = undefined;
                    var fbs = std.io.fixedBufferStream(&tmp);
                    const aw = fbs.writer();
                    switch (v.vtype) {
                        0x07 => try aw.print("{d}", .{std.mem.readInt(i32, v.vbytes[0..4], .little)}),
                        0x08 => try aw.print("{d}", .{std.mem.readInt(u32, v.vbytes[0..4], .little)}),
                        0x09 => try aw.print("{d}", .{std.mem.readInt(i64, v.vbytes[0..8], .little)}),
                        0x0a => try aw.print("{d}", .{std.mem.readInt(u64, v.vbytes[0..8], .little)}),
                        else => {},
                    }
                    const s = fbs.getWritten();
                    if (s.len >= width) {
                        try jsonEscapeUtf8(w, s);
                    } else {
                        var zeros: [32]u8 = undefined;
                        const need = @min(width - s.len, zeros.len);
                        @memset(zeros[0..need], '0');
                        try w.writeAll(zeros[0..need]);
                        try jsonEscapeUtf8(w, s);
                    }
                    i += 1; // consumed following value
                }
            },
            .Value => switch (nd.vtype & 0x7f) {
                0x03 => if (nd.vbytes.len >= 1) try w.print("{d}", .{@as(i8, @bitCast(nd.vbytes[0]))}),
                0x04 => if (nd.vbytes.len >= 1) try w.print("{d}", .{nd.vbytes[0]}),
                0x05 => if (nd.vbytes.len >= 2) try w.print("{d}", .{std.mem.readInt(i16, nd.vbytes[0..2], .little)}),
                0x06 => if (nd.vbytes.len >= 2) try w.print("{d}", .{std.mem.readInt(u16, nd.vbytes[0..2], .little)}),
                0x07 => if (nd.vbytes.len >= 4) try w.print("{d}", .{std.mem.readInt(i32, nd.vbytes[0..4], .little)}),
                0x08 => if (nd.vbytes.len >= 4) try w.print("{d}", .{std.mem.readInt(u32, nd.vbytes[0..4], .little)}),
                0x09 => if (nd.vbytes.len >= 8) try w.print("{d}", .{std.mem.readInt(i64, nd.vbytes[0..8], .little)}),
                0x0a => if (nd.vbytes.len >= 8) try w.print("{d}", .{std.mem.readInt(u64, nd.vbytes[0..8], .little)}),
                0x0b => if (nd.vbytes.len >= 4) {
                    const bits = std.mem.readInt(u32, nd.vbytes[0..4], .little);
                    const f: f32 = @bitCast(bits);
                    if (std.math.isNan(f)) try w.writeAll("-1.#IND") else if (std.math.isInf(f)) try w.writeAll(if (f > 0) "1.#INF" else "-1.#INF") else try w.print("{d}", .{f});
                },
                0x0c => if (nd.vbytes.len >= 8) {
                    const bits = std.mem.readInt(u64, nd.vbytes[0..8], .little);
                    const f: f64 = @bitCast(bits);
                    if (std.math.isNan(f)) try w.writeAll("-1.#IND") else if (std.math.isInf(f)) try w.writeAll(if (f > 0) "1.#INF" else "-1.#INF") else try w.print("{d}", .{f});
                },
                0x0d => if (nd.vbytes.len >= 4) try w.writeAll(if (std.mem.readInt(u32, nd.vbytes[0..4], .little) == 0) "false" else "true"),
                0x0f => if (nd.vbytes.len >= 16) {
                    const d1 = std.mem.readInt(u32, nd.vbytes[0..4], .little);
                    const d2 = std.mem.readInt(u16, nd.vbytes[4..6], .little);
                    const d3 = std.mem.readInt(u16, nd.vbytes[6..8], .little);
                    const d4 = nd.vbytes[8..16];
                    try w.print("{{{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}}}", .{ d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7] });
                },
                0x11 => if (nd.vbytes.len >= 8) {
                    const ft = std.mem.readInt(u64, nd.vbytes[0..8], .little);
                    var buf: [40]u8 = undefined;
                    const out = formatIso8601UtcFromFiletimeMicros(&buf, ft) catch return; // nothing on error
                    try w.writeAll(out);
                },
                0x12 => if (nd.vbytes.len >= 16) {
                    const year = std.mem.readInt(u16, nd.vbytes[0..2], .little);
                    const month = std.mem.readInt(u16, nd.vbytes[2..4], .little);
                    const day = std.mem.readInt(u16, nd.vbytes[6..8], .little);
                    const hour = std.mem.readInt(u16, nd.vbytes[8..10], .little);
                    const minute = std.mem.readInt(u16, nd.vbytes[10..12], .little);
                    const second = std.mem.readInt(u16, nd.vbytes[12..14], .little);
                    const millis = std.mem.readInt(u16, nd.vbytes[14..16], .little);
                    try w.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{ year, month, day, hour, minute, second, millis });
                },
                0x13 => if (nd.vbytes.len >= 8) {
                    const rev = nd.vbytes[0];
                    const sub_count = nd.vbytes[1];
                    const ida_bytes = nd.vbytes[2..8];
                    var idauth: u64 = 0;
                    var kk: usize = 0;
                    while (kk < 6) : (kk += 1) idauth = (idauth << 8) | ida_bytes[kk];
                    try w.print("S-{d}-{d}", .{ rev, idauth });
                    var off: usize = 8;
                    var si: usize = 0;
                    while (si < sub_count and off + 4 <= nd.vbytes.len) : (si += 1) {
                        const sub = std.mem.readInt(u32, nd.vbytes[off .. off + 4][0..4], .little);
                        off += 4;
                        try w.print("-{d}", .{sub});
                    }
                },
                0x14 => if (nd.vbytes.len >= 4) try w.print("0x{X}", .{std.mem.readInt(u32, nd.vbytes[0..4], .little)}),
                0x15 => if (nd.vbytes.len >= 8) try w.print("0x{X}", .{std.mem.readInt(u64, nd.vbytes[0..8], .little)}),
                0x01 => {
                    if (nd.vbytes.len > 0) {
                        var num = nd.vbytes.len / 2;
                        if (num > 0 and std.mem.readInt(u16, nd.vbytes[nd.vbytes.len - 2 .. nd.vbytes.len][0..2], .little) == 0) num -= 1;
                        if (num > 0) try writeUtf16LeJsonEscaped(w, nd.vbytes[0 .. num * 2], num);
                    }
                },
                0x02 => try writeAnsiCp1252JsonEscaped(w, nd.vbytes),
                0x0e => {
                    var j: usize = 0;
                    while (j < nd.vbytes.len) : (j += 1) try w.print("{x:0>2}", .{nd.vbytes[j]});
                },
                else => {},
            },
            .CharRef => try w.print("&#{d};", .{nd.charref_value}),
            .EntityRef => try w.writeByte('&'),
            .CData => try writeUtf16LeJsonEscaped(w, nd.text_utf16, nd.text_num_chars),
            .PITarget, .PIData, .Element, .Subst => {},
        }
    }
    try w.writeByte('"');
}

fn writeAttrValueJson(chunk: []const u8, nodes: []const IR.Node, w: anytype) !void {
    // Prefer typed render when value is a single .Value node, otherwise render as string
    if (nodes.len == 1 and nodes[0].tag == .Value) {
        const nd = nodes[0];
        return writeValueJson(w, nd.vtype, nd.vbytes);
    }
    try writeNodesAsJsonString(chunk, nodes, w);
}

fn keyFromNameAlloc(alloc: std.mem.Allocator, name: IR.Name, chunk: []const u8) ![]u8 {
    var key_builder = std.ArrayList(u8).init(alloc);
    defer key_builder.deinit();
    switch (name) {
        .InlineUtf16 => |inl| try writeUtf16LeJsonEscaped(key_builder.writer(), inl.bytes, inl.num_chars),
        .NameOffset => |off| {
            const o: usize = @intCast(off);
            if (o + 8 > chunk.len) return error.UnexpectedEof;
            const num_chars = std.mem.readInt(u16, chunk[o + 6 .. o + 8][0..2], .little);
            const str_start = o + 8;
            const byte_len = @as(usize, num_chars) * 2;
            if (str_start + byte_len > chunk.len) return error.UnexpectedEof;
            try writeUtf16LeJsonEscaped(key_builder.writer(), chunk[str_start .. str_start + byte_len], num_chars);
        },
    }
    return key_builder.toOwnedSlice();
}

fn keyFromUtf16AttrValue(alloc: std.mem.Allocator, nodes: []const IR.Node) ![]u8 {
    // Build a UTF-8 key string from attribute value nodes (assumed to be text)
    var key_builder = std.ArrayList(u8).init(alloc);
    defer key_builder.deinit();
    var i: usize = 0;
    while (i < nodes.len) : (i += 1) {
        const nd = nodes[i];
        switch (nd.tag) {
            .Text, .CData => try writeUtf16LeJsonEscaped(key_builder.writer(), nd.text_utf16, nd.text_num_chars),
            .Value => try writeValueJson(key_builder.writer(), nd.vtype, nd.vbytes),
            else => {},
        }
    }
    return key_builder.toOwnedSlice();
}

fn objectHasKey(obj: *std.StringHashMap(usize), key: []const u8) bool {
    return obj.get(key) != null;
}

fn findAndInsertSuffixMove(
    alloc: std.mem.Allocator,
    keys: *std.ArrayList([]const u8),
    values: *std.ArrayList([]const u8),
    key_to_replace_index: usize,
    new_key: []const u8,
    old_value_json: []const u8,
) !void {
    // Move the old value to the first free suffixed slot, keep base key for new insertion
    var suffix: usize = 1;
    var tmp_key = std.ArrayList(u8).init(alloc);
    defer tmp_key.deinit();
    while (true) : (suffix += 1) {
        tmp_key.clearRetainingCapacity();
        try tmp_key.writer().print("{s}_{d}", .{ new_key, suffix });
        // Check if any existing key equals tmp_key
        var exists = false;
        var i: usize = 0;
        while (i < keys.items.len) : (i += 1) {
            if (std.mem.eql(u8, keys.items[i], tmp_key.items)) { exists = true; break; }
        }
        if (!exists) {
            // Insert a new entry at end with the suffixed key and old value
            try keys.append(try std.mem.dupe(alloc, u8, tmp_key.items));
            try values.append(old_value_json);
            break;
        }
    }
    // Note: caller will insert/overwrite the base key's value afterwards
    _ = key_to_replace_index; // unused (kept for potential future in-place reordering)
}

fn writeElementBodyEvtxRs(
    chunk: []const u8,
    el: *const IR.Element,
    alloc: std.mem.Allocator,
    w: anytype,
) !void {
    // We build an object with insertion order preserved using parallel arrays of keys and serialized value slices.
    // To keep memory use low, we serialize child values into a temporary buffer per child, then emit the object.
    var out_keys = std.ArrayList([]const u8).init(alloc);
    defer out_keys.deinit();
    var out_vals = std.ArrayList([]const u8).init(alloc);
    defer out_vals.deinit();

    // Helper buffer for serializing values
    var val_buf = std.ArrayList(u8).init(alloc);
    defer val_buf.deinit();

    // Attributes first -> "#attributes" object if not empty
    var has_any = false;
    if (el.attrs.items.len > 0) {
        // Serialize attributes object
        val_buf.clearRetainingCapacity();
        var vbw = val_buf.writer();
        try vbw.writeByte('{');
        var wrote_attr = false;
        var ai: usize = 0;
        while (ai < el.attrs.items.len) : (ai += 1) {
            const a = el.attrs.items[ai];
            if (wrote_attr) try vbw.writeByte(',');
            try vbw.writeByte('"');
            switch (a.name) {
                .InlineUtf16 => |inl| try writeUtf16LeJsonEscaped(vbw, inl.bytes, inl.num_chars),
                .NameOffset => |off| {
                    const o: usize = @intCast(off);
                    if (o + 8 > chunk.len) return error.UnexpectedEof;
                    const num_chars = std.mem.readInt(u16, chunk[o + 6 .. o + 8][0..2], .little);
                    const str_start = o + 8;
                    const byte_len = @as(usize, num_chars) * 2;
                    if (str_start + byte_len > chunk.len) return error.UnexpectedEof;
                    try writeUtf16LeJsonEscaped(vbw, chunk[str_start .. str_start + byte_len], num_chars);
                },
            }
            try vbw.writeAll("":");
            if (attrNameIsSystemTime(a.name, chunk)) {
                var tmp: [256]u8 = undefined;
                var fbs = std.io.fixedBufferStream(&tmp);
                const aw = fbs.writer();
                var vi: usize = 0;
                while (vi < el.attrs.items[ai].value.items.len) : (vi += 1) {
                    const ndv = el.attrs.items[ai].value.items[vi];
                    if (ndv.tag == .Text) {
                        try writeUtf16LeRawToUtf8(aw, ndv.text_utf16, ndv.text_num_chars);
                    }
                }
                const ascii = fbs.getWritten();
                try vbw.writeByte('"');
                try util.normalizeAndWriteSystemTimeAscii(vbw, ascii);
                try vbw.writeByte('"');
            } else {
                try writeAttrValueJson(chunk, a.value.items, vbw);
            }
            wrote_attr = true;
        }
        try vbw.writeByte('}');
        try out_keys.append(try std.mem.dupe(alloc, u8, "#attributes"));
        try out_vals.append(val_buf.items);
        has_any = true;
    }

    // Collect textual content nodes (non-element children)
    var has_textual: bool = false;
    var text_nodes = std.ArrayList(IR.Node).init(alloc);
    defer text_nodes.deinit();

    // Process child elements in order, implementing evtx_dump duplicate key semantics
    var ci: usize = 0;
    while (ci < el.children.items.len) : (ci += 1) {
        const nd = el.children.items[ci];
        if (nd.tag == .Element) {
            const child = nd.elem.?;
            // Compute key, with special handling for Data[Name]
            var key_slice: []u8 = undefined;
            var key_arena = std.ArrayList(u8).init(alloc);
            defer key_arena.deinit();
            var use_name_attr = false;
            // If child name equals "Data" and has a Name attribute, key is Name's value and attributes are dropped
            var is_data_name = IRModule.nameEqualsAscii(chunk, child.name, "Data");
            if (is_data_name and child.attrs.items.len > 0) {
                var iattr: usize = 0;
                while (iattr < child.attrs.items.len) : (iattr += 1) {
                    const a = child.attrs.items[iattr];
                    if (IRModule.nameEqualsAscii(chunk, a.name, "Name")) {
                        key_slice = try keyFromUtf16AttrValue(alloc, a.value.items);
                        use_name_attr = true;
                        break;
                    }
                }
            }
            if (!use_name_attr) {
                key_slice = try keyFromNameAlloc(alloc, child.name, chunk);
            }

            // Prepare placeholder and render child value
            // Insert semantics: if key exists with a non-empty value, move old value to first free "key_N" and keep base for new
            // We check if key exists in out_keys and whether its value is "null" or "{}" (empty object) when deciding move.
            // Serialize child body into val_buf
            val_buf.clearRetainingCapacity();
            var vbw2 = val_buf.writer();
            // Decide representation: leaf string -> JSON string, else object body
            const leaf = child.attrs.items.len == 0 and !child.has_element_child;
            if (leaf) {
                // Collect textual nodes of child
                var leaf_text = std.ArrayList(IR.Node).init(alloc);
                defer leaf_text.deinit();
                var j: usize = 0;
                while (j < child.children.items.len) : (j += 1) {
                    const cnd = child.children.items[j];
                    if (cnd.tag != .Element) try leaf_text.append(cnd);
                }
                try writeNodesAsJsonString(chunk, leaf_text.items, vbw2);
            } else {
                // Render nested object with attributes/text/children
                try writeElementBodyEvtxRs(chunk, child, alloc, vbw2);
            }

            // Determine if we need to move old value
            var found_index: ?usize = null;
            var idx: usize = 0;
            while (idx < out_keys.items.len) : (idx += 1) {
                if (std.mem.eql(u8, out_keys.items[idx], key_slice)) { found_index = idx; break; }
            }
            if (found_index) |fi| {
                const old = out_vals.items[fi];
                const is_placeholder = (old.len == 4 and std.mem.eql(u8, old, "null")) or (old.len == 2 and std.mem.eql(u8, old, "{}"));
                if (!is_placeholder) {
                    try findAndInsertSuffixMove(alloc, &out_keys, &out_vals, fi, key_slice, old);
                }
                // Overwrite base key with new value (or leave placeholder replaced)
                out_vals.items[fi] = val_buf.items;
            } else {
                try out_keys.append(key_slice);
                try out_vals.append(val_buf.items);
            }
            has_any = true;
        } else {
            has_textual = true;
            try text_nodes.append(nd);
        }
    }

    // If there is textual content, emit "#text"
    if (has_textual) {
        val_buf.clearRetainingCapacity();
        var vbw3 = val_buf.writer();
        try writeNodesAsJsonString(chunk, text_nodes.items, vbw3);
        try out_keys.append(try std.mem.dupe(alloc, u8, "#text"));
        try out_vals.append(val_buf.items);
        has_any = true;
    }

    // If nothing at all (no attrs, no text, no children), represent as null
    if (!has_any) {
        try w.writeAll("null");
        return;
    }

    // Emit the object from collected keys/values
    try w.writeByte('{');
    var i: usize = 0;
    while (i < out_keys.items.len) : (i += 1) {
        if (i > 0) try w.writeByte(',');
        try w.writeByte('"');
        try jsonEscapeUtf8(w, out_keys.items[i]);
        try w.writeAll("":");
        try w.writeAll(out_vals.items[i]);
    }
    try w.writeByte('}');
}

pub fn renderElementJsonEvtxRs(chunk: []const u8, root: *const IR.Element, alloc: std.mem.Allocator, w: anytype) !void {
    // Emit only the body of the root element ("Event" object), matching our existing JSON wrappers
    try writeElementBodyEvtxRs(chunk, root, alloc, w);
}

test "evtxrs json: duplicate keys suffixing with latest at base" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    // Construct a minimal IR.Element with two children of same name with leaf strings
    var root = IR.Element{
        .name = IR.Name{ .InlineUtf16 = .{ .bytes = &[_]u8{ 'R', 0, 'o', 0, 'o', 0, 't', 0 }, .num_chars = 4 } },
        .attrs = std.ArrayList(IR.Attribute).init(A),
        .children = std.ArrayList(IR.Node).init(A),
        .has_element_child = true,
        .has_evtxml_subst_in_tree = false,
        .has_evtxml_value_in_tree = false,
    };
    defer root.attrs.deinit();
    defer root.children.deinit();

    // Helper to make a leaf child element named "Header" with text content
    fn makeLeafHeader(a: std.mem.Allocator, text: []const u8) !*IR.Element {
        var child = try a.create(IR.Element);
        child.* = .{
            .name = IR.Name{ .InlineUtf16 = .{ .bytes = &[_]u8{ 'H', 0, 'e', 0, 'a', 0, 'd', 0, 'e', 0, 'r', 0 }, .num_chars = 6 } },
            .attrs = std.ArrayList(IR.Attribute).init(a),
            .children = std.ArrayList(IR.Node).init(a),
            .has_element_child = false,
            .has_evtxml_subst_in_tree = false,
            .has_evtxml_value_in_tree = false,
        };
        var utf16 = try a.alloc(u8, text.len * 2);
        var i: usize = 0;
        while (i < text.len) : (i += 1) {
            utf16[i * 2] = text[i];
            utf16[i * 2 + 1] = 0;
        }
        try child.children.append(.{ .tag = .Text, .text_utf16 = utf16, .text_num_chars = @intCast(text.len) });
        return child;
    }

    const c1 = try makeLeafHeader(A, "A");
    const c2 = try makeLeafHeader(A, "B");
    defer {
        c1.children.deinit();
        c1.attrs.deinit();
        c2.children.deinit();
        c2.attrs.deinit();
        A.destroy(c1);
        A.destroy(c2);
    }

    try root.children.append(.{ .tag = .Element, .elem = c1 });
    try root.children.append(.{ .tag = .Element, .elem = c2 });

    var buf = std.ArrayList(u8).init(A);
    defer buf.deinit();
    try renderElementJsonEvtxRs(&[_]u8{}, &root, A, buf.writer());
    const s = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, s, "\"Header\":\"B\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"Header_1\":\"A\"") != null);
}

test "evtxrs json: Data[Name] remapping and dropping attributes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    var root = IR.Element{
        .name = IR.Name{ .InlineUtf16 = .{ .bytes = &[_]u8{ 'E', 0, 'v', 0, 'n', 0, 't', 0 }, .num_chars = 4 } },
        .attrs = std.ArrayList(IR.Attribute).init(A),
        .children = std.ArrayList(IR.Node).init(A),
        .has_element_child = true,
        .has_evtxml_subst_in_tree = false,
        .has_evtxml_value_in_tree = false,
    };
    defer root.attrs.deinit();
    defer root.children.deinit();

    // Build <Data Name="Foo">bar</Data>
    var data_el = try A.create(IR.Element);
    data_el.* = .{
        .name = IR.Name{ .InlineUtf16 = .{ .bytes = &[_]u8{ 'D', 0, 'a', 0, 't', 0, 'a', 0 }, .num_chars = 4 } },
        .attrs = std.ArrayList(IR.Attribute).init(A),
        .children = std.ArrayList(IR.Node).init(A),
        .has_element_child = false,
        .has_evtxml_subst_in_tree = false,
        .has_evtxml_value_in_tree = false,
    };
    // Name attr
    var name_val = std.ArrayList(IR.Node).init(A);
    defer name_val.deinit();
    var name_utf16 = try A.alloc(u8, 3 * 2);
    name_utf16[0] = 'F'; name_utf16[1] = 0;
    name_utf16[2] = 'o'; name_utf16[3] = 0;
    name_utf16[4] = 'o'; name_utf16[5] = 0;
    try name_val.append(.{ .tag = .Text, .text_utf16 = name_utf16, .text_num_chars = 3 });
    try data_el.attrs.append(.{ .name = IR.Name{ .InlineUtf16 = .{ .bytes = &[_]u8{ 'N', 0, 'a', 0, 'm', 0, 'e', 0 }, .num_chars = 4 } }, .value = name_val });

    // Text "bar"
    var txt_utf16 = try A.alloc(u8, 3 * 2);
    txt_utf16[0] = 'b'; txt_utf16[1] = 0;
    txt_utf16[2] = 'a'; txt_utf16[3] = 0;
    txt_utf16[4] = 'r'; txt_utf16[5] = 0;
    try data_el.children.append(.{ .tag = .Text, .text_utf16 = txt_utf16, .text_num_chars = 3 });

    try root.children.append(.{ .tag = .Element, .elem = data_el });

    var buf = std.ArrayList(u8).init(A);
    defer buf.deinit();
    try renderElementJsonEvtxRs(&[_]u8{}, &root, A, buf.writer());
    const s = buf.items;
    // Expect {"Foo":"bar"}
    try std.testing.expect(std.mem.eql(u8, s, "{\"Foo\":\"bar\"}"));
}