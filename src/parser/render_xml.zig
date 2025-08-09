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
const Context = @import("binxml.zig").Context;
const logNameTrace = @import("binxml.zig").logNameTrace;
const buildExpandedElementTree = @import("binxml.zig").buildExpandedElementTree;
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
    // First render textual tokens (if any) as indented separate line(s)
    var idx: usize = 0;
    while (idx < el.children.items.len) : (idx += 1) {
        const nd = el.children.items[idx];
        switch (nd.tag) {
            .Element => try renderElementIRXml(chunk, nd.elem.?, eff_values, w, indent + 2),
            .Subst => {},
            .Value => {
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
    if (ctx.verbose) logger.setModuleLevel("binxml", .trace);
    const root = try buildExpandedElementTree(ctx, chunk, bin);
    if (ctx.verbose) {
        try logNameTrace(chunk, root.name, "root");
    }
    try renderElementIRXml(chunk, root, &[_]TemplateValue{}, w, 0);
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

// No reader usage in renderer; all nested payloads are expanded during parse phase.
