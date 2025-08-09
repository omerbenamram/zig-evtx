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
const attrNameIsSystemTime = @import("binxml.zig").attrNameIsSystemTime;

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
    var pending_pad: usize = 0;
    var i: usize = 0;
    while (i < nodes.len) : (i += 1) {
        const nd = nodes[i];
        switch (nd.tag) {
            .Text => {
                // Drop '+' padding sentinels that occasionally appear in manifests
                if (nd.text_num_chars == 1 and nd.text_utf16.len >= 2 and nd.text_utf16[0] == 0x2B and nd.text_utf16[1] == 0x00) {
                    continue;
                }
                try writeUtf16LeJsonEscaped(w, nd.text_utf16, nd.text_num_chars);
            },
            .Pad => pending_pad = nd.pad_width,
            .Value => {
                if (pending_pad > 0 and (nd.vtype == 0x07 or nd.vtype == 0x08 or nd.vtype == 0x09 or nd.vtype == 0x0a)) {
                    var tmp: [64]u8 = undefined;
                    var fbs = std.io.fixedBufferStream(&tmp);
                    const aw = fbs.writer();
                    switch (nd.vtype) {
                        0x07 => try aw.print("{d}", .{std.mem.readInt(i32, nd.vbytes[0..4], .little)}),
                        0x08 => try aw.print("{d}", .{std.mem.readInt(u32, nd.vbytes[0..4], .little)}),
                        0x09 => try aw.print("{d}", .{std.mem.readInt(i64, nd.vbytes[0..8], .little)}),
                        0x0a => try aw.print("{d}", .{std.mem.readInt(u64, nd.vbytes[0..8], .little)}),
                        else => {},
                    }
                    const s = fbs.getWritten();
                    // Left pad with zeros
                    if (s.len >= pending_pad) {
                        try jsonEscapeUtf8(w, s);
                    } else {
                        var zeros: [32]u8 = undefined;
                        const need = @min(pending_pad - s.len, zeros.len);
                        @memset(zeros[0..need], '0');
                        try w.writeAll(zeros[0..need]);
                        try jsonEscapeUtf8(w, s);
                    }
                    pending_pad = 0;
                } else {
                    // Render value as plain textual content inside an existing JSON string
                    switch (nd.vtype & 0x7f) {
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
                            const out = formatIso8601UtcFromFiletimeMicros(&buf, ft) catch return; // write nothing on error
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
                            // Sized UTF-16 string
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
                    }
                }
            },
            .CharRef => try w.print("&#{d};", .{nd.charref_value}),
            .EntityRef => {
                try w.writeByte('&');
            },
            .CData => try writeUtf16LeJsonEscaped(w, nd.text_utf16, nd.text_num_chars),
            .PITarget, .PIData, .Element, .Subst => {},
        }
    }
    try w.writeByte('"');
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
    var textual_nodes = std.ArrayList(IR.Node).init(alloc);
    defer textual_nodes.deinit();

    var ci: usize = 0;
    if (el.children.items.len > 0) try textual_nodes.ensureTotalCapacityPrecise(el.children.items.len);
    while (ci < el.children.items.len) : (ci += 1) {
        const nd = el.children.items[ci];
        switch (nd.tag) {
            .Element => {
                const child = nd.elem.?;
                // Convert name to UTF-8 key
                var key_builder = std.ArrayList(u8).init(alloc);
                defer key_builder.deinit();
                switch (child.name) {
                    .InlineUtf16 => |inl| try writeUtf16LeJsonEscaped(key_builder.writer(), inl.bytes, inl.num_chars),
                    .NameOffset => |off| {
                        const o: usize = @intCast(off);
                        if (o + 8 > chunk.len) continue;
                        const num_chars = std.mem.readInt(u16, chunk[o + 6 .. o + 8][0..2], .little);
                        const str_start = o + 8;
                        const byte_len = @as(usize, num_chars) * 2;
                        if (str_start + byte_len > chunk.len) continue;
                        try writeUtf16LeJsonEscaped(key_builder.writer(), chunk[str_start .. str_start + byte_len], num_chars);
                    },
                }
                const key = try key_builder.toOwnedSlice();
                var entry = try groups.getOrPut(key);
                if (!entry.found_existing) {
                    entry.value_ptr.* = std.ArrayList(*IR.Element).init(alloc);
                    // Guess a small group size to avoid early growth (tuneable)
                    try entry.value_ptr.ensureTotalCapacityPrecise(2);
                }
                try entry.value_ptr.append(child);
            },
            else => {
                has_textual = true;
                try textual_nodes.append(nd);
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
        switch (a.name) {
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
        try w.writeAll("\":");
        // Special-case SystemTime normalization like XML path
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
                var text_nodes = std.ArrayList(IR.Node).init(alloc);
                defer text_nodes.deinit();
                var j: usize = 0;
                while (j < child.children.items.len) : (j += 1) {
                    const nd = child.children.items[j];
                    if (nd.tag != .Element) try text_nodes.append(nd);
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
                    var text_nodes = std.ArrayList(IR.Node).init(alloc);
                    defer text_nodes.deinit();
                    var j: usize = 0;
                    while (j < child.children.items.len) : (j += 1) {
                        const nd = child.children.items[j];
                        if (nd.tag != .Element) try text_nodes.append(nd);
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
