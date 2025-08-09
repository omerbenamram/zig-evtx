const IRModule = @import("ir.zig");
const IR = IRModule.IR;
const irNewElement = IRModule.irNewElement;
const TemplateValue = @import("binxml.zig").TemplateValue;
const logger = @import("../logger.zig");
const log = logger.scoped("render_xml");
const std = @import("std");
const BinXmlError = @import("binxml.zig").BinXmlError;
const writeUtf16LeXmlEscaped = @import("util.zig").writeUtf16LeXmlEscaped;
const writeAnsiCp1252Escaped = @import("util.zig").writeAnsiCp1252Escaped;
const writeValueXml = @import("binxml.zig").writeValueXml;

const normalizeAndWriteSystemTimeAscii = @import("util.zig").normalizeAndWriteSystemTimeAscii;
const writePaddedInt = @import("util.zig").writePaddedInt;
const writeUtf16LeRawToUtf8 = @import("util.zig").writeUtf16LeRawToUtf8;
const Reader = @import("reader.zig").Reader;
const appendEvtXmlPayloadChildrenIR = @import("binxml.zig").appendEvtXmlPayloadChildrenIR;
const Context = @import("binxml.zig").Context;
const TOK_FRAGMENT_HEADER = @import("binxml.zig").TOK_FRAGMENT_HEADER;
const TOK_TEMPLATE_INSTANCE = @import("binxml.zig").TOK_TEMPLATE_INSTANCE;
const TOK_OPEN_START = @import("binxml.zig").TOK_OPEN_START;
const parseElementIR = @import("binxml.zig").parseElementIR;
const expectedValuesFromTemplate = @import("binxml.zig").expectedValuesFromTemplate;
const parseTemplateInstanceValuesExpected = @import("binxml.zig").parseTemplateInstanceValuesExpected;
const expandElementWithValues = @import("binxml.zig").expandElementWithValues;
const logNameTrace = @import("binxml.zig").logNameTrace;
const isToken = @import("binxml.zig").isToken;
const valueTypeFixedSize = @import("binxml.zig").valueTypeFixedSize;
const attrNameIsSystemTime = @import("binxml.zig").attrNameIsSystemTime;

fn renderElementIRXml(chunk: []const u8, el: *const IR.Element, values: []const TemplateValue, w: anytype, indent: usize) anyerror!void {
    // If this element has local template values, prefer them for its subtree
    const eff_values: []const TemplateValue = if (el.local_values.len > 0) el.local_values else values;
    // Use precomputed hints
    const has_elem_child = el.has_element_child;
    const has_evtxml_subst = el.has_evtxml_subst_in_tree;
    const has_evtxml_value = el.has_evtxml_value_in_tree;
    // Drop debug-only Data tracing (kept minimal logging elsewhere)
    // Early: drop element if its only content is an optional substitution resolving to NULL
    if (!has_elem_child and el.children.items.len == 1) {
        const only = el.children.items[0];
        if (only.tag == .Subst and only.subst_optional and only.subst_id < eff_values.len) {
            const vv0 = eff_values[only.subst_id];
            if (vv0.t == 0x00 or vv0.data.len == 0) return;
        }
    }
    // Early: array substitution repetition for sole content
    if (!has_elem_child and !has_evtxml_subst and !has_evtxml_value and el.children.items.len == 1 and !IRModule.nameEqualsAscii(chunk, el.name, "Data")) {
        const c0 = el.children.items[0];
        if (c0.tag == .Subst and (c0.subst_vtype & 0x80) != 0 and c0.subst_id < eff_values.len) {
            const vv = eff_values[c0.subst_id];
            const base: u8 = c0.subst_vtype & 0x7f;
            if (base == 0x21) {
                log.warn("array of 0x21 not supported; skipping repetition", .{});
            } else if (base == 0x10 and !(vv.t == 0x94 or vv.t == 0x95)) {
                log.warn("size array backing mismatch in element repetition: got 0x{x}", .{vv.t});
                return;
            }
            // Helper lambdas
            const write_open = struct {
                fn go(chunk_: []const u8, el_: *const IR.Element, w_: anytype, indent_spaces: usize) !void {
                    var i_: usize = 0;
                    while (i_ < indent_spaces) : (i_ += 1) try w_.writeByte(' ');
                    try w_.writeByte('<');
                    try writeNameXml(chunk_, el_.name, w_);
                    // re-emit attributes
                    var ai_: usize = 0;
                    while (ai_ < el_.attrs.items.len) : (ai_ += 1) {
                        const a_ = el_.attrs.items[ai_];
                        var tmp_: [512]u8 = undefined;
                        var fbs_ = std.io.fixedBufferStream(&tmp_);
                        const eff_vals_: []const TemplateValue = if (el_.local_values.len > 0) el_.local_values else &[_]TemplateValue{};
                        try renderAttrValueFromIR(chunk_, a_.value.items, eff_vals_, fbs_.writer());
                        const rendered_ = fbs_.getWritten();
                        if (rendered_.len == 0) continue;
                        try w_.writeByte(' ');
                        try writeNameXml(chunk_, a_.name, w_);
                        try w_.writeAll("=\"");
                        if (attrNameIsSystemTime(a_.name, chunk_)) {
                            try normalizeAndWriteSystemTimeAscii(w_, rendered_);
                        } else {
                            try w_.writeAll(rendered_);
                        }
                        try w_.writeByte('"');
                    }
                    try w_.writeByte('>');
                }
            };

            const write_close = struct {
                fn go(chunk_: []const u8, el_: *const IR.Element, w_: anytype, _: usize) !void {
                    try w_.writeAll("</");
                    try writeNameXml(chunk_, el_.name, w_);
                    try w_.writeByte('>');
                    try w_.writeByte('\n');
                }
            };

            // Determine iteration by base type
            var any_item = false;
            if (base == 0x01) { // Unicode string array: NUL-terminated items
                var j: usize = 0;
                while (j <= vv.data.len) {
                    const start = j;
                    var end = j;
                    while (end + 1 < vv.data.len) : (end += 2) {
                        if (std.mem.readInt(u16, vv.data[end .. end + 2][0..2], .little) == 0) break;
                    }
                    try write_open.go(chunk, el, w, indent);
                    if (end > start) try writeUtf16LeXmlEscaped(w, vv.data[start..end], (end - start) / 2);
                    try write_close.go(chunk, el, w, indent);
                    any_item = true;
                    if (end + 1 < vv.data.len) j = end + 2 else break;
                }
            } else if (base == 0x02) { // ANSI string array: NUL-separated
                var j: usize = 0;
                while (j <= vv.data.len) {
                    const start = j;
                    var end = j;
                    while (end < vv.data.len and vv.data[end] != 0) : (end += 1) {}
                    try write_open.go(chunk, el, w, indent);
                    if (end > start) try writeAnsiCp1252Escaped(w, vv.data[start..end]);
                    try write_close.go(chunk, el, w, indent);
                    any_item = true;
                    if (end < vv.data.len and vv.data[end] == 0) j = end + 1 else break;
                }
            } else if (valueTypeFixedSize(base)) |esz| {
                var j: usize = 0;
                while (j + esz <= vv.data.len) : (j += esz) {
                    try write_open.go(chunk, el, w, indent);
                    try writeValueXml(w, base, vv.data[j .. j + esz]);
                    try write_close.go(chunk, el, w, indent);
                    any_item = true;
                }
            } else if (base == 0x13) { // SID array
                var j: usize = 0;
                while (j + 8 <= vv.data.len) {
                    const subc: usize = vv.data[j + 1];
                    const need: usize = 8 + subc * 4;
                    if (j + need > vv.data.len) break;
                    try write_open.go(chunk, el, w, indent);
                    try writeValueXml(w, 0x13, vv.data[j .. j + need]);
                    try write_close.go(chunk, el, w, indent);
                    any_item = true;
                    j += need;
                }
            }
            if (!any_item) {
                // zero-length arrays -> one empty element
                try write_open.go(chunk, el, w, indent);
                try write_close.go(chunk, el, w, indent);
            }
            return;
        }
    }

    // Write opening tag and attributes (after early structural decisions)
    var i: usize = 0;
    while (i < indent) : (i += 1) try w.writeByte(' ');
    try w.writeByte('<');
    try writeNameXml(chunk, el.name, w);

    var ai: usize = 0;
    while (ai < el.attrs.items.len) : (ai += 1) {
        const a = el.attrs.items[ai];
        // Render attribute value to buffer
        var tmp: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&tmp);
        try renderAttrValueFromIR(chunk, a.value.items, eff_values, fbs.writer());
        const rendered = fbs.getWritten();
        // Drop only if the attribute is a single optional substitution resolving NULL
        var drop_attr = false;
        if (a.value.items.len == 1) {
            const n0 = a.value.items[0];
            if (n0.tag == .Subst and n0.subst_optional and n0.subst_id < eff_values.len) {
                const vv0 = eff_values[n0.subst_id];
                if (vv0.t == 0x00 or vv0.data.len == 0) drop_attr = true;
            }
        }
        if (drop_attr) continue;
        try w.writeByte(' ');
        try writeNameXml(chunk, a.name, w);
        try w.writeAll("=\"");
        if (attrNameIsSystemTime(a.name, chunk)) {
            try normalizeAndWriteSystemTimeAscii(w, rendered);
        } else {
            try w.writeAll(rendered);
        }
        try w.writeByte('"');
    }
    if (el.children.items.len == 0) {
        // Emit explicit open/close for elements that can be compared with rust output (<Binary></Binary>)
        try w.writeByte('>');
        try w.writeAll("</");
        try writeNameXml(chunk, el.name, w);
        try w.writeByte('>');
        try w.writeByte('\n');
        return;
    }

    if (!has_elem_child and !has_evtxml_subst and !has_evtxml_value) {
        // Inline textual content
        try w.writeByte('>');
        try renderTextContentFromIR(chunk, el.children.items, eff_values, w);
        try w.writeAll("</");
        try writeNameXml(chunk, el.name, w);
        try w.writeByte('>');
        try w.writeByte('\n');
        return;
    }
    // Block form for element children and evtxml substitutions
    try w.writeByte('>');
    try w.writeByte('\n');
    // Splice any nested EvtXml payloads that appeared inside attribute value token streams
    if (el.has_attr_evtxml_value) {
        var ai_pre: usize = 0;
        while (ai_pre < el.attrs.items.len) : (ai_pre += 1) {
            const a = el.attrs.items[ai_pre];
            var vi_pre: usize = 0;
            while (vi_pre < a.value.items.len) : (vi_pre += 1) {
                const ndv = a.value.items[vi_pre];
                if (ndv.tag == .Value and (ndv.vtype & 0x7f) == 0x21 and ndv.vbytes.len > 0) {
                    try appendEvtXmlPayloadChildrenIR(chunk, ndv.vbytes, std.heap.page_allocator, @constCast(el));
                }
            }
        }
    }

    // First render textual tokens (if any) as indented separate line(s)
    var idx: usize = 0;
    while (idx < el.children.items.len) : (idx += 1) {
        const nd = el.children.items[idx];
        switch (nd.tag) {
            .Element => try renderElementIRXml(chunk, nd.elem.?, eff_values, w, indent + 2),
            .Subst => {
                if (nd.subst_id < values.len) {
                    const vv = eff_values[nd.subst_id];
                    if ((vv.t & 0x7f) == 0x21 and vv.data.len > 0) {
                        // Render nested payload as children: append IR children and then render
                        try appendEvtXmlPayloadChildrenIR(chunk, vv.data, std.heap.page_allocator, @constCast(el));
                        // Already appended as proper children, nothing to print here
                        continue;
                    }
                }
                // Treat other substitutions as text lines
                var k: usize = 0;
                while (k < indent + 2) : (k += 1) try w.writeByte(' ');
                try renderTextContentFromIR(chunk, &[_]IR.Node{nd}, eff_values, w);
                try w.writeByte('\n');
            },
            .Value => {
                if ((nd.vtype & 0x7f) == 0x21 and nd.vbytes.len > 0) {
                    // Append nested payload as proper element children
                    try appendEvtXmlPayloadChildrenIR(chunk, nd.vbytes, std.heap.page_allocator, @constCast(el));
                    continue;
                }
                var k: usize = 0;
                while (k < indent + 2) : (k += 1) try w.writeByte(' ');
                try renderTextContentFromIR(chunk, &[_]IR.Node{nd}, eff_values, w);
                try w.writeByte('\n');
            },
            .Text, .Pad, .CharRef, .EntityRef, .CData, .PITarget, .PIData => {
                var k: usize = 0;
                while (k < indent + 2) : (k += 1) try w.writeByte(' ');
                try renderTextContentFromIR(chunk, &[_]IR.Node{nd}, eff_values, w);
                try w.writeByte('\n');
            },
        }
    }
    // close tag
    i = 0;
    while (i < indent) : (i += 1) try w.writeByte(' ');
    try w.writeAll("</");
    try writeNameXml(chunk, el.name, w);
    try w.writeByte('>');
    try w.writeByte('\n');
}

fn writeNameXml(chunk: []const u8, name: IR.Name, w: anytype) !void {
    switch (name) {
        .NameOffset => |off| try writeNameFromOffset(chunk, off, w),
        .InlineUtf16 => |inl| try writeNameFromUtf16(w, inl.bytes, inl.num_chars),
    }
}
pub fn writeNameFromOffset(chunk: []const u8, name_offset: u32, w: anytype) !void {
    const off = @as(usize, name_offset);
    if (off + 8 > chunk.len) return BinXmlError.OutOfBounds;
    // Name: u32 unknown, u16 hash, u16 num_chars, then UTF-16LE chars
    const num_chars = std.mem.readInt(u16, chunk[off + 6 .. off + 8][0..2], .little);
    const str_start = off + 8;
    const byte_len = @as(usize, num_chars) * 2;
    if (str_start + byte_len > chunk.len) return BinXmlError.OutOfBounds;
    // Defensive: trim a trailing NUL if manifests encoded EOS in num_chars
    var num = num_chars;
    if (byte_len >= 2) {
        const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
        if (last == 0 and num > 0) num -= 1;
    }
    try writeUtf16LeXmlEscaped(w, chunk[str_start .. str_start + num * 2], num);
}

pub fn writeNameFromUtf16(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    try writeUtf16LeXmlEscaped(w, utf16le, num_chars);
}

pub fn renderXmlWithContext(ctx: *Context, chunk: []const u8, bin: []const u8, w: anytype) anyerror!void {
    // Honor per-record verbosity by bumping module level to trace for this call
    if (ctx.verbose) logger.setModuleLevel("binxml", .trace);
    var r = Reader.init(bin);

    // Optional fragment header
    if (r.rem() >= 4 and r.buf[r.pos] == TOK_FRAGMENT_HEADER) {
        _ = try r.readU8(); // token
        _ = try r.readU8(); // major
        _ = try r.readU8(); // minor
        _ = try r.readU8(); // flags
    }

    if (r.rem() == 0) {
        try w.writeAll("<Event/>");
        return;
    }

    const first = try r.peekU8();
    log.debug("first=0x{x} len={d}", .{ first, bin.len });
    if (first == TOK_TEMPLATE_INSTANCE) {
        _ = try r.readU8(); // consume 0x0c
        if (r.rem() < 1 + 4 + 4) return BinXmlError.UnexpectedEof;
        _ = try r.readU8(); // unknown (matches Rust reader)
        _ = try r.readU32le(); // template id (unused)
        const def_data_off = try r.readU32le();
        log.debug("tmpl def_off=0x{x} def_size={d}", .{ def_data_off, 0 });

        // Per Rust: template header: next_template_offset (4), guid (16), data_size (4), then payload of size data_size
        const def_off_usize: usize = @intCast(def_data_off);
        if (def_off_usize + 24 > chunk.len) return BinXmlError.OutOfBounds;
        const td_data_size = std.mem.readInt(u32, chunk[def_off_usize + 20 .. def_off_usize + 24][0..4], .little);
        const data_start = def_off_usize + 24;
        const data_end = data_start + @as(usize, td_data_size);
        if (data_end > chunk.len or data_start >= chunk.len) return BinXmlError.OutOfBounds;
        log.trace("using chunk def data at 0x{x}..0x{x}", .{ data_start, data_end });
        var def_r = Reader.init(chunk[data_start..data_end]);
        if (ctx.verbose and def_r.rem() >= 8) {
            log.trace("def_r first8: {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}", .{
                def_r.buf[0], def_r.buf[1], def_r.buf[2], def_r.buf[3], def_r.buf[4], def_r.buf[5], def_r.buf[6], def_r.buf[7],
            });
        }
        // Optional fragment header inside definition (chunk copy)
        if (def_r.rem() >= 4 and def_r.buf[def_r.pos] == TOK_FRAGMENT_HEADER) {
            _ = try def_r.readU8();
            _ = try def_r.readU8();
            _ = try def_r.readU8();
            _ = try def_r.readU8();
        }

        // Skip inline copy when def_data_off equals current record-relative cursor position
        // Match Rust: compare against cursor.position() within the record buffer
        // If the template definition header is inlined at the current record cursor, skip it deterministically
        if (def_data_off == @as(u32, @intCast(r.pos))) {
            if (r.rem() < 24) return BinXmlError.UnexpectedEof;
            _ = try r.readU32le(); // next_template_offset
            _ = try r.readGuid();
            const data_size_inline = try r.readU32le();
            if (r.rem() < data_size_inline) return BinXmlError.UnexpectedEof;
            r.pos += @as(usize, data_size_inline);
        }

        // Some records embed additional cached template definition blocks before the substitution array.
        // These blocks have a fixed 24-byte header followed by a fragment of size `data_size` beginning with 0x0f.
        // Skip any such blocks deterministically before reading substitutions.
        while (r.rem() >= 28) {
            const data_size_peek = std.mem.readInt(u32, r.buf[r.pos + 20 .. r.pos + 24][0..4], .little);
            const block_end = r.pos + 24 + @as(usize, data_size_peek);
            if (block_end > r.buf.len) break;
            const payload_first = r.buf[r.pos + 24];
            if (payload_first != TOK_FRAGMENT_HEADER) break;
            if (ctx.verbose) log.trace("skipping inline cached template def: size={d} at 0x{x}..0x{x}", .{ data_size_peek, r.pos, block_end });
            r.pos = block_end;
        }

        // Parse the template definition IR (using chunk copy) before values so we can compute expected substitutions
        const parsed_def = parseElementIR(chunk, &def_r, ctx.arena.allocator(), .def) catch |e| {
            log.err("parse def IR failed: {s}", .{@errorName(e)});
            return e;
        };
        // With the template parsed, compute expected substitution count and parse values accordingly
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const alloc = gpa.allocator();
        const expected = expectedValuesFromTemplate(parsed_def);
        log.trace("values start at rec+0x{x}; rem={d} expected={d}", .{ r.pos, r.rem(), expected });
        if (ctx.verbose and r.rem() >= 8) {
            log.trace("values first8: {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}", .{
                r.buf[r.pos + 0], r.buf[r.pos + 1], r.buf[r.pos + 2], r.buf[r.pos + 3],
                r.buf[r.pos + 4], r.buf[r.pos + 5], r.buf[r.pos + 6], r.buf[r.pos + 7],
            });
        }
        const values = parseTemplateInstanceValuesExpected(&r, alloc, expected) catch |e| {
            log.err("parse values (expected) failed: {s} rem={d}", .{ @errorName(e), r.rem() });
            return e;
        };
        if (ctx.verbose) log.trace("parsed {d} values; rec_pos=0x{x} rem={d}", .{ values.len, r.pos, r.rem() });
        // Copy value descriptors into context arena to ensure stable lifetime in Release builds
        const vals_copy = try ctx.arena.allocator().alloc(TemplateValue, values.len);
        var vi: usize = 0;
        while (vi < values.len) : (vi += 1) vals_copy[vi] = values[vi];
        defer alloc.free(values);
        // Fetch GUID from the chunk template header for cache keying
        var guid: [16]u8 = undefined;
        std.mem.copyForwards(u8, guid[0..], chunk[def_off_usize + 4 .. def_off_usize + 20]);
        const key: Context.DefKey = .{ .def_data_off = def_data_off, .guid = guid };
        const got = try ctx.cache.getOrPut(key);
        if (!got.found_existing) {
            got.value_ptr.* = parsed_def;
            if (ctx.verbose) {
                try logNameTrace(chunk, got.value_ptr.*.name, "tmpl root");
            }
        }
        // Expand substitutions into the IR using the correct scope
        const expanded = try expandElementWithValues(got.value_ptr.*, vals_copy, ctx.arena.allocator());
        renderElementIRXml(chunk, expanded, &[_]TemplateValue{}, w, 0) catch |e| {
            log.err("render tmpl failed: {s}", .{@errorName(e)});
            return e;
        };
        return;
    } else {
        // Non-template path: IR parse and render for parity
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const alloc = gpa.allocator();
        const root = parseElementIR(chunk, &r, alloc, .rec) catch |e| {
            log.err("parse root IR failed: {s} first4=0x{x} 0x{x} 0x{x} 0x{x}", .{ @errorName(e), r.buf[0], r.buf[1], r.buf[2], r.buf[3] });
            return e;
        };
        if (ctx.verbose) {
            try logNameTrace(chunk, root.name, "root");
        }
        renderElementIRXml(chunk, root, &[_]TemplateValue{}, w, 0) catch |e| {
            log.err("render root failed: {s}", .{@errorName(e)});
            return e;
        };
        return;
    }
}

fn renderAttrValueFromIR(chunk: []const u8, nodes: []const IR.Node, _: []const TemplateValue, w: anytype) !void {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const aw = fbs.writer();
    var pending_pad: usize = 0;
    for (nodes) |nd| switch (nd.tag) {
        .Text => try writeUtf16LeXmlEscaped(aw, nd.text_utf16, nd.text_num_chars),
        .Pad => pending_pad = nd.pad_width,
        .Value => {
            if (pending_pad > 0 and (nd.vtype == 0x07 or nd.vtype == 0x08 or nd.vtype == 0x09 or nd.vtype == 0x0a)) {
                switch (nd.vtype) {
                    0x07 => try writePaddedInt(aw, i32, std.mem.readInt(i32, nd.vbytes[0..4], .little), pending_pad),
                    0x08 => try writePaddedInt(aw, u32, std.mem.readInt(u32, nd.vbytes[0..4], .little), pending_pad),
                    0x09 => try writePaddedInt(aw, i64, std.mem.readInt(i64, nd.vbytes[0..8], .little), pending_pad),
                    0x0a => try writePaddedInt(aw, u64, std.mem.readInt(u64, nd.vbytes[0..8], .little), pending_pad),
                    else => {},
                }
                pending_pad = 0;
            } else {
                try writeValueXml(aw, nd.vtype, nd.vbytes);
            }
        },
        .Subst => {}, // no Subst nodes remain post-expansion
        .CharRef => try aw.print("&#{d};", .{nd.charref_value}),
        .EntityRef => {
            try aw.writeByte('&');
            try writeNameXml(chunk, nd.entity_name, aw);
            try aw.writeByte(';');
        },
        .CData => try writeUtf16LeXmlEscaped(aw, nd.text_utf16, nd.text_num_chars),
        .PITarget => {
            try aw.writeAll("<?");
            try writeNameXml(chunk, nd.pi_target, aw);
        },
        .PIData => {
            try aw.writeByte(' ');
            try writeUtf16LeRawToUtf8(aw, nd.text_utf16, nd.text_num_chars);
            try aw.writeAll("?>");
        },
        .Element => {},
    };
    // Drop '+' sentinels if any made it through
    const written = fbs.getWritten();
    var i: usize = 0;
    while (i < written.len) : (i += 1) {
        const ch = written[i];
        if (ch == '+') continue;
        try w.writeByte(ch);
    }
}

fn renderTextContentFromIR(chunk: []const u8, nodes: []const IR.Node, _: []const TemplateValue, w: anytype) !void {
    var pending_pad: usize = 0;
    var i: usize = 0;
    while (i < nodes.len) : (i += 1) {
        const nd = nodes[i];
        switch (nd.tag) {
            .Text => try writeUtf16LeXmlEscaped(w, nd.text_utf16, nd.text_num_chars),
            .Pad => pending_pad = nd.pad_width,
            .Value => {
                if (pending_pad > 0 and (nd.vtype == 0x07 or nd.vtype == 0x08 or nd.vtype == 0x09 or nd.vtype == 0x0a)) {
                    switch (nd.vtype) {
                        0x07 => try writePaddedInt(w, i32, std.mem.readInt(i32, nd.vbytes[0..4], .little), pending_pad),
                        0x08 => try writePaddedInt(w, u32, std.mem.readInt(u32, nd.vbytes[0..4], .little), pending_pad),
                        0x09 => try writePaddedInt(w, i64, std.mem.readInt(i64, nd.vbytes[0..8], .little), pending_pad),
                        0x0a => try writePaddedInt(w, u64, std.mem.readInt(u64, nd.vbytes[0..8], .little), pending_pad),
                        else => {},
                    }
                    pending_pad = 0;
                } else {
                    try writeValueXml(w, nd.vtype, nd.vbytes);
                }
            },
            .Subst => {}, // no Subst nodes remain post-expansion
            .CharRef => try w.print("&#{d};", .{nd.charref_value}),
            .EntityRef => {
                try w.writeByte('&');
                try writeNameXml(chunk, nd.entity_name, w);
                try w.writeByte(';');
            },
            .CData => {
                try w.writeAll("<![CDATA[");
                try writeUtf16LeRawToUtf8(w, nd.text_utf16, nd.text_num_chars);
                try w.writeAll("]]>");
            },
            .PITarget => {
                try w.writeAll("<?");
                try writeNameXml(chunk, nd.pi_target, w);
            },
            .PIData => {
                try w.writeByte(' ');
                try writeUtf16LeRawToUtf8(w, nd.text_utf16, nd.text_num_chars);
                try w.writeAll("?>");
            },
            .Element => {},
        }
    }
}

fn renderEvtXmlPayloadAsChildren(chunk: []const u8, data: []const u8, alloc: std.mem.Allocator, values: []const TemplateValue, w: anytype, indent: usize) anyerror!void {
    if (data.len == 0) return;
    var r = Reader.init(data);
    if (r.rem() >= 4 and r.buf[r.pos] == TOK_FRAGMENT_HEADER) {
        _ = try r.readU8();
        _ = try r.readU8();
        _ = try r.readU8();
        _ = try r.readU8();
    }
    while (r.rem() > 0) {
        const pk = r.buf[r.pos];
        if (isToken(pk, TOK_OPEN_START)) {
            // Allow offset-based names inside payloads (treat like record context)
            const child = try parseElementIR(chunk, &r, alloc, .rec);
            try renderElementIRXml(chunk, child, values, w, indent);
        } else break;
    }
}
