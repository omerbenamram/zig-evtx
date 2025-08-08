const std = @import("std");

pub const RenderMode = enum { xml, json, jsonl };

pub const BinXmlError = error{
    UnexpectedEof,
    BadToken,
    OutOfBounds,
};

// Token constants (subset)
const TOK_FRAGMENT_HEADER: u8 = 0x0f;
const TOK_OPEN_START: u8 = 0x01; // or 0x41 with has-more flag
const TOK_CLOSE_START: u8 = 0x02;
const TOK_CLOSE_EMPTY: u8 = 0x03;
const TOK_END_ELEMENT: u8 = 0x04;
const TOK_VALUE: u8 = 0x05; // or 0x45 with has-more flag
const TOK_ATTRIBUTE: u8 = 0x06; // or 0x46 with has-more flag
const TOK_TEMPLATE_INSTANCE: u8 = 0x0c;
const TOK_NORMAL_SUBST: u8 = 0x0d;
const TOK_OPTIONAL_SUBST: u8 = 0x0e;
const TOK_EOF: u8 = 0x00;
const TOK_CDATA: u8 = 0x07; // or 0x47 with has-more flag
const TOK_CHARREF: u8 = 0x08; // or 0x48 with has-more flag
const TOK_ENTITYREF: u8 = 0x09; // or 0x49 with has-more flag

fn hasMore(flagged: u8, base: u8) bool {
    return (flagged & 0x1f) == base and (flagged & 0x40) != 0;
}
fn isToken(flagged: u8, base: u8) bool {
    return (flagged & 0x1f) == base;
}

// Reader drives Binary XML token parsing for one buffer slice (record or template
// definition). To safely render nested XML fragments (EvtXml, type 0x21) that can
// appear inside attributes or as substitutions, we avoid re-entrant parsing in the
// middle of an element. Instead, we maintain a stack of frames – one per open
// element – and queue any 0x21 payloads onto the current frame. When we close that
// element, we flush the queued payloads by rendering them as normal child elements
// (definition-mode names, same substitution value table). This matches observed
// EVTX layouts where <EventData> is emitted as a nested 0x21 blob after <System>.
//
// Two crucial cases handled by the queue:
// 1) VALUE 0x21 inside attribute token streams: we intercept and queue the payload
//    rather than emitting inline, then flush on element close.
// 2) Substitution 0x21 (TOK_NORMAL_SUBST/TOK_OPTIONAL_SUBST referencing a value of
//    stored type 0x21): we queue the stored payload on the current frame, which can
//    occur after a child closes (e.g., directly in <Event> content after </System>).
//    The payload is then rendered on the parent’s close (e.g., producing <EventData>
//    just before </Event>).
const Reader = struct {
    const MaxDepth: usize = 64;
    const MaxQueuedPerFrame: usize = 8;
    const Frame = struct { queued: [MaxQueuedPerFrame][]const u8, count: usize };
    buf: []const u8,
    pos: usize = 0,
    frames: [MaxDepth]Frame = undefined,
    depth: usize = 0,

    fn init(buf: []const u8) Reader {
        var r: Reader = .{ .buf = buf, .pos = 0, .frames = undefined, .depth = 0 };
        var i: usize = 0;
        while (i < MaxDepth) : (i += 1) {
            r.frames[i].count = 0;
        }
        return r;
    }

    fn pushFrame(self: *Reader) void {
        if (self.depth < MaxDepth) {
            self.frames[self.depth].count = 0;
            self.depth += 1;
        }
    }

    // Queue a nested EvtXml payload on the current open-element frame
    fn queueEvtXml(self: *Reader, data: []const u8) void {
        if (self.depth == 0) return; // not inside an element
        var f = &self.frames[self.depth - 1];
        if (f.count < MaxQueuedPerFrame) {
            f.queued[f.count] = data;
            f.count += 1;
        }
    }

    fn rem(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }

    fn peekU8(self: *const Reader) !u8 {
        if (self.pos >= self.buf.len) return BinXmlError.UnexpectedEof;
        return self.buf[self.pos];
    }

    fn readU8(self: *Reader) !u8 {
        if (self.pos >= self.buf.len) return BinXmlError.UnexpectedEof;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }

    fn readU16le(self: *Reader) !u16 {
        if (self.pos + 2 > self.buf.len) return BinXmlError.UnexpectedEof;
        const v = std.mem.readInt(u16, self.buf[self.pos .. self.pos + 2][0..2], .little);
        self.pos += 2;
        return v;
    }

    fn readU32le(self: *Reader) !u32 {
        if (self.pos + 4 > self.buf.len) return BinXmlError.UnexpectedEof;
        const v = std.mem.readInt(u32, self.buf[self.pos .. self.pos + 4][0..4], .little);
        self.pos += 4;
        return v;
    }
};

fn flushPendingNested(r: *Reader, chunk: []const u8, w: anytype, values: []const TemplateValue) anyerror!void {
    if (r.depth == 0) return;
    const idx = r.depth - 1;
    var i: usize = 0;
    while (i < r.frames[idx].count) : (i += 1) {
        const data = r.frames[idx].queued[i];
        if (data.len == 0) continue;
        var sub = Reader.init(data);
        if (sub.rem() >= 4 and sub.buf[sub.pos] == TOK_FRAGMENT_HEADER) {
            _ = try sub.readU8();
            _ = try sub.readU8();
            _ = try sub.readU8();
            _ = try sub.readU8();
        }
        while (sub.rem() > 0) {
            const pk = try sub.peekU8();
            if (isToken(pk, TOK_OPEN_START)) {
                try renderElementXml(chunk, &sub, w, values, .def);
            } else if (pk == TOK_TEMPLATE_INSTANCE) {
                _ = try sub.readU8(); // consume template instance token
                if (sub.rem() < 1 + 4 + 4 + 4 + 16 + 4) break;
                _ = try sub.readU8(); // unknown
                _ = try sub.readU32le(); // template id
                const def_data_off = try sub.readU32le();
                _ = try sub.readU32le(); // next def off
                if (sub.rem() < 16) break;
                sub.pos += 16; // GUID
                const def_size = try sub.readU32le();
                const def_off_usize: usize = @intCast(def_data_off);
                if (def_off_usize + 24 > chunk.len) break;
                const td_data_size = std.mem.readInt(u32, chunk[def_off_usize + 20 .. def_off_usize + 24][0..4], .little);
                const data_start = def_off_usize + 24;
                const data_end = data_start + @as(usize, td_data_size);
                if (data_end > chunk.len or data_start >= chunk.len) break;
                var def_r = Reader.init(chunk[data_start..data_end]);
                if (def_r.rem() >= 4 and def_r.buf[def_r.pos] == TOK_FRAGMENT_HEADER) {
                    _ = try def_r.readU8();
                    _ = try def_r.readU8();
                    _ = try def_r.readU8();
                    _ = try def_r.readU8();
                }
                if (sub.rem() >= def_size and (sub.buf[sub.pos] == TOK_FRAGMENT_HEADER or sub.buf[sub.pos] == TOK_OPEN_START)) {
                    sub.pos += @as(usize, def_size);
                }
                var gpa = std.heap.GeneralPurposeAllocator(.{}){};
                defer _ = gpa.deinit();
                const alloc = gpa.allocator();
                const vals = try parseTemplateInstanceValues(&sub, alloc);
                defer alloc.free(vals);
                try renderElementXml(chunk, &def_r, w, vals, .def);
            } else break;
        }
    }
    r.frames[idx].count = 0;
}

fn writeXmlEscaped(w: anytype, s: []const u8) !void {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        switch (c) {
            '&' => try w.writeAll("&amp;"),
            '<' => try w.writeAll("&lt;"),
            '>' => try w.writeAll("&gt;"),
            '"' => try w.writeAll("&quot;"),
            '\'' => try w.writeAll("&apos;"),
            else => try w.writeByte(c),
        }
    }
}

fn writeUtf16LeXmlEscaped(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    // Decode UTF-16LE with surrogate handling and write XML-escaped UTF-8
    var i: usize = 0;
    while (i < num_chars and (i * 2 + 1) < utf16le.len) : (i += 1) {
        const lo = @as(u16, utf16le[i * 2]) | (@as(u16, utf16le[i * 2 + 1]) << 8);
        var codepoint: u21 = lo;
        if (lo >= 0xD800 and lo <= 0xDBFF) {
            // high surrogate, need low surrogate next
            if (i + 1 >= num_chars or (i + 1) * 2 + 1 >= utf16le.len) break;
            const lo2 = @as(u16, utf16le[(i + 1) * 2]) | (@as(u16, utf16le[(i + 1) * 2 + 1]) << 8);
            if (lo2 >= 0xDC00 and lo2 <= 0xDFFF) {
                const high_ten = lo - 0xD800;
                const low_ten = lo2 - 0xDC00;
                codepoint = 0x10000 + (@as(u21, high_ten) << 10) + @as(u21, low_ten);
                i += 1; // consumed extra unit
            } else {
                // invalid, skip
                continue;
            }
        } else if (lo >= 0xDC00 and lo <= 0xDFFF) {
            // stray low surrogate, skip
            continue;
        }

        var buf: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(codepoint, &buf) catch 0;
        if (len == 0) continue;
        try writeXmlEscaped(w, buf[0..len]);
    }
}

fn writeNameFromOffset(chunk: []const u8, name_offset: u32, w: anytype) !void {
    const off = @as(usize, name_offset);
    if (off + 8 > chunk.len) return BinXmlError.OutOfBounds;
    // Name: u32 unknown, u16 hash, u16 num_chars, then UTF-16LE chars
    const num_chars = std.mem.readInt(u16, chunk[off + 6 .. off + 8][0..2], .little);
    const str_start = off + 8;
    const byte_len = @as(usize, num_chars) * 2;
    if (str_start + byte_len > chunk.len) return BinXmlError.OutOfBounds;
    try writeUtf16LeXmlEscaped(w, chunk[str_start .. str_start + byte_len], num_chars);
}

fn readFixedBytes(r: *Reader, n: usize) ![]const u8 {
    if (r.rem() < n) return BinXmlError.UnexpectedEof;
    const slice = r.buf[r.pos .. r.pos + n];
    r.pos += n;
    return slice;
}

fn valueTypeFixedSize(vtype: u8) ?usize {
    return switch (vtype) {
        0x07, // Int32
        0x08, // UInt32
        0x0d, // Bool (DWORD)
        0x14,
        => 4, // HexInt32
        0x09, // Int64
        0x0a, // UInt64
        0x11,
        => 8, // FILETIME
        0x15 => 8, // HexInt64
        0x0f, // GUID
        0x12,
        => 16, // SYSTEMTIME
        else => null, // 0x01 string (variable), 0x0e binary (variable), 0x13 SID (variable), others unknown
    };
}

fn readUnicodeTextString(r: *Reader) ![]const u8 {
    // Unicode text string: 2 bytes num chars, then UTF-16LE string without EOS
    const num_chars = try r.readU16le();
    const byte_len = @as(usize, num_chars) * 2;
    if (r.pos + byte_len > r.buf.len) return BinXmlError.UnexpectedEof;
    const slice = r.buf[r.pos .. r.pos + byte_len];
    r.pos += byte_len;
    return slice;
}

const Source = enum { rec, def };

fn writeNameFromUtf16(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    try writeUtf16LeXmlEscaped(w, utf16le, num_chars);
}

fn utf16EqualsAscii(utf16le: []const u8, num_chars: usize, ascii: []const u8) bool {
    if (ascii.len != num_chars) return false;
    var i: usize = 0;
    while (i < num_chars) : (i += 1) {
        const lo = utf16le[i * 2];
        const hi = utf16le[i * 2 + 1];
        if (hi != 0 or lo != ascii[i]) return false;
    }
    return true;
}

fn isNameSystemTimeFromOffset(chunk: []const u8, name_offset: u32) bool {
    const off = @as(usize, name_offset);
    if (off + 8 > chunk.len) return false;
    const num_chars = std.mem.readInt(u16, chunk[off + 6 .. off + 8][0..2], .little);
    const str_start = off + 8;
    const byte_len = @as(usize, num_chars) * 2;
    if (str_start + byte_len > chunk.len) return false;
    return utf16EqualsAscii(chunk[str_start .. str_start + byte_len], num_chars, "SystemTime");
}

fn normalizeAndWriteSystemTimeAscii(w: anytype, ascii: []const u8) !void {
    // Expect variants like YYYY-M-DTHH:MM:SS.ffffffZ and normalize to zero-padded YYYY-MM-DDTHH:MM:SS.ffffffZ
    // Very defensive: parse by scanning delimiters
    var year: []const u8 = &[_]u8{};
    var month: []const u8 = &[_]u8{};
    var day: []const u8 = &[_]u8{};
    var hour: []const u8 = &[_]u8{};
    var minute: []const u8 = &[_]u8{};
    var second: []const u8 = &[_]u8{};
    var micros: []const u8 = &[_]u8{};

    // Find 'T' and 'Z'
    const t_idx = std.mem.indexOfScalar(u8, ascii, 'T') orelse return w.writeAll(ascii);
    const z_idx = std.mem.lastIndexOfScalar(u8, ascii, 'Z') orelse return w.writeAll(ascii);
    const date = ascii[0..t_idx];
    const time = ascii[t_idx + 1 .. z_idx];
    // date split
    var it = std.mem.splitScalar(u8, date, '-');
    year = it.next() orelse return w.writeAll(ascii);
    month = it.next() orelse return w.writeAll(ascii);
    day = it.next() orelse return w.writeAll(ascii);
    // time split
    var it2 = std.mem.splitScalar(u8, time, ':');
    hour = it2.next() orelse return w.writeAll(ascii);
    minute = it2.next() orelse return w.writeAll(ascii);
    const sec_frac = it2.next() orelse return w.writeAll(ascii);
    if (std.mem.indexOfScalar(u8, sec_frac, '.')) |dot| {
        second = sec_frac[0..dot];
        micros = sec_frac[dot + 1 ..];
    } else {
        second = sec_frac;
        micros = &[_]u8{};
    }
    // Write padded
    try w.writeAll(year);
    try w.writeByte('-');
    if (month.len == 1) try w.writeAll("0");
    try w.writeAll(month);
    try w.writeByte('-');
    if (day.len == 1) try w.writeAll("0");
    try w.writeAll(day);
    try w.writeByte('T');
    if (hour.len == 1) try w.writeAll("0");
    try w.writeAll(hour);
    try w.writeByte(':');
    if (minute.len == 1) try w.writeAll("0");
    try w.writeAll(minute);
    try w.writeByte(':');
    if (second.len == 1) try w.writeAll("0");
    try w.writeAll(second);
    if (micros.len > 0) {
        try w.writeByte('.');
        // Pad/truncate to 6
        if (micros.len < 6) {
            try w.writeAll(micros);
            var zeros: [6]u8 = undefined;
            const need = 6 - micros.len;
            @memset(zeros[0..need], '0');
            try w.writeAll(zeros[0..need]);
        } else {
            try w.writeAll(micros[0..6]);
        }
    }
    try w.writeByte('Z');
}

// Collect attribute value tokens (including substitutions) into a buffer writer.
// Mirrors the logic used for generic attribute values, so special cases are centralized.
fn collectAttributeValue(chunk: []const u8, r: *Reader, aw: anytype, values: []const TemplateValue) !void {
    var pad2: bool = false;
    while (true) {
        if (r.rem() == 0) break;
        const at_peek = r.buf[r.pos];
        if (isToken(at_peek, TOK_ATTRIBUTE)) break; // next attribute starts
        if (isToken(at_peek, TOK_CLOSE_START) or isToken(at_peek, TOK_CLOSE_EMPTY)) break; // end of start tag
        if (isToken(at_peek, TOK_VALUE)) {
            _ = try r.readU8();
            const vtype = try r.readU8();
            if ((vtype & 0x7f) == 0x21) {
                if (r.rem() < 2) return BinXmlError.UnexpectedEof;
                const blen = try r.readU16le();
                if (r.rem() < blen) return BinXmlError.UnexpectedEof;
                r.queueEvtXml(r.buf[r.pos .. r.pos + blen]);
                r.pos += blen;
            } else if (vtype == 0x01) {
                var text = try readUnicodeTextString(r);
                var had_leading_plus = false;
                if (text.len >= 2 and text[0] == 0x2B and text[1] == 0x00) {
                    if (text.len == 2) {
                        pad2 = true;
                        continue;
                    } else {
                        text = text[2..];
                        had_leading_plus = true;
                    }
                }
                if ((pad2 or had_leading_plus) and text.len >= 2 and text[1] == 0x00 and text[0] >= '0' and text[0] <= '9') {
                    var pad_applied = false;
                    if (text.len == 2) {
                        pad_applied = true;
                    } else if (text.len >= 4) {
                        const next = text[2];
                        const next_hi = text[3];
                        if (!(next >= '0' and next <= '9' and next_hi == 0x00)) {
                            pad_applied = true;
                        }
                    }
                    if (pad_applied) {
                        try aw.writeByte('0');
                        try aw.writeByte(text[0]);
                        if (text.len > 2) try writeUtf16LeXmlEscaped(aw, text[2..], (text.len - 2) / 2);
                        pad2 = false;
                    } else {
                        try writeUtf16LeXmlEscaped(aw, text, text.len / 2);
                    }
                } else {
                    try writeUtf16LeXmlEscaped(aw, text, text.len / 2);
                    if (pad2) pad2 = false;
                }
            } else if (valueTypeFixedSize(vtype)) |sz| {
                const payload = try readFixedBytes(r, sz);
                if (pad2 and (vtype == 0x07 or vtype == 0x08 or vtype == 0x09 or vtype == 0x0a)) {
                    switch (vtype) {
                        0x07 => {
                            const num = std.mem.readInt(i32, @as(*const [4]u8, @ptrCast(payload.ptr)), .little);
                            try writePaddedInt(aw, i32, num, 2);
                        },
                        0x08 => {
                            const num = std.mem.readInt(u32, @as(*const [4]u8, @ptrCast(payload.ptr)), .little);
                            try writePaddedInt(aw, u32, num, 2);
                        },
                        0x09 => {
                            const num = std.mem.readInt(i64, @as(*const [8]u8, @ptrCast(payload.ptr)), .little);
                            try writePaddedInt(aw, i64, num, 2);
                        },
                        0x0a => {
                            const num = std.mem.readInt(u64, @as(*const [8]u8, @ptrCast(payload.ptr)), .little);
                            try writePaddedInt(aw, u64, num, 2);
                        },
                        else => unreachable,
                    }
                    pad2 = false;
                } else {
                    try writeValueXml(aw, vtype, payload);
                }
            } else if (vtype == 0x0e) {
                if (r.rem() < 2) return BinXmlError.UnexpectedEof;
                const blen = try r.readU16le();
                const payload = try readFixedBytes(r, blen);
                try writeValueXml(aw, vtype, payload);
            } else if (vtype == 0x13) {
                if (r.rem() < 8) return BinXmlError.UnexpectedEof;
                const start_pos = r.pos;
                _ = try r.readU8();
                const subc = try r.readU8();
                _ = try readFixedBytes(r, 6);
                const needed: usize = 8 + @as(usize, subc) * 4;
                r.pos = start_pos;
                const payload = try readFixedBytes(r, needed);
                try writeValueXml(aw, vtype, payload);
            } else {
                return BinXmlError.BadToken;
            }
            continue;
        } else if (isToken(at_peek, TOK_NORMAL_SUBST)) {
            _ = try r.readU8();
            const padw: usize = if (pad2) 2 else 0;
            try renderSubstitutionXml(chunk, aw, false, r, values, padw);
            pad2 = false;
            continue;
        } else if (isToken(at_peek, TOK_OPTIONAL_SUBST)) {
            _ = try r.readU8();
            const padw: usize = if (pad2) 2 else 0;
            try renderSubstitutionXml(chunk, aw, true, r, values, padw);
            pad2 = false;
            continue;
        } else if (isToken(at_peek, TOK_CHARREF)) {
            _ = try r.readU8();
            const v = try r.readU16le();
            try aw.print("&#{d};", .{v});
            continue;
        } else if (isToken(at_peek, TOK_ENTITYREF)) {
            _ = try r.readU8();
            const ent_name_off = try r.readU32le();
            try aw.writeByte('&');
            try writeNameFromOffset(chunk, ent_name_off, aw);
            try aw.writeByte(';');
            continue;
        } else if (isToken(at_peek, TOK_CDATA)) {
            _ = try r.readU8();
            const data = try readUnicodeTextString(r);
            try writeUtf16LeXmlEscaped(aw, data, data.len / 2);
            continue;
        } else {
            break;
        }
    }
}

fn writeSystemTimeAttributeValue(chunk: []const u8, r: *Reader, w: anytype, values: []const TemplateValue) !void {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const aw = fbs.writer();
    try collectAttributeValue(chunk, r, aw, values);
    const written = fbs.getWritten();
    // Drop '+' sentinels
    var tmp: [256]u8 = undefined;
    var idx: usize = 0;
    var j: usize = 0;
    while (idx < written.len and j < tmp.len) : (idx += 1) {
        const ch = written[idx];
        if (ch == '+') continue;
        tmp[j] = ch;
        j += 1;
    }
    try normalizeAndWriteSystemTimeAscii(w, tmp[0..j]);
}

fn readInlineName(r: *Reader) !struct { utf16: []const u8, num_chars: usize } {
    _ = try r.readU32le(); // unknown
    _ = try r.readU16le(); // hash
    const num = try r.readU16le();
    const bytes = @as(usize, num) * 2;
    if (r.pos + bytes > r.buf.len) return BinXmlError.UnexpectedEof;
    const slice = r.buf[r.pos .. r.pos + bytes];
    r.pos += bytes;
    return .{ .utf16 = slice, .num_chars = num };
}

fn readInlineNameDefFlexible(r: *Reader) !struct { utf16: []const u8, num_chars: usize } {
    // Variant C: u32 unknown + u32 zero/unknown + u16 hash + u16 num + UTF16 (+ optional EOS)
    if (r.rem() >= 12) {
        const saveC = r.pos;
        _ = try r.readU32le();
        _ = try r.readU32le();
        _ = try r.readU16le(); // hash
        const numC = try r.readU16le();
        const bytesC = @as(usize, numC) * 2;
        if (r.rem() >= bytesC and r.pos + bytesC <= r.buf.len) {
            const sliceC = r.buf[r.pos .. r.pos + bytesC];
            r.pos += bytesC;
            // Optional EOS (u16 0)
            if (r.rem() >= 2) {
                const eos = std.mem.readInt(u16, r.buf[r.pos .. r.pos + 2][0..2], .little);
                if (eos == 0) r.pos += 2;
            }
            return .{ .utf16 = sliceC, .num_chars = numC };
        }
        r.pos = saveC;
    }
    // Try variant A: u16 hash + u16 num + UTF16
    if (r.rem() >= 4) {
        const save = r.pos;
        _ = try r.readU16le(); // hash
        const numA = try r.readU16le();
        const bytesA = @as(usize, numA) * 2;
        if (r.rem() >= bytesA and r.pos + bytesA <= r.buf.len) {
            const slice = r.buf[r.pos .. r.pos + bytesA];
            r.pos += bytesA;
            return .{ .utf16 = slice, .num_chars = numA };
        }
        r.pos = save;
    }
    // Variant B: u16 num + UTF16
    if (r.rem() >= 2) {
        const numB = try r.readU16le();
        const bytesB = @as(usize, numB) * 2;
        if (r.rem() >= bytesB and r.pos + bytesB <= r.buf.len) {
            const slice = r.buf[r.pos .. r.pos + bytesB];
            r.pos += bytesB;
            return .{ .utf16 = slice, .num_chars = numB };
        }
    }
    // Fallback to full variant with unknown+hash
    _ = try r.readU32le(); // unknown
    _ = try r.readU16le(); // hash
    const num = try r.readU16le();
    const bytes = @as(usize, num) * 2;
    if (r.pos + bytes > r.buf.len) return BinXmlError.UnexpectedEof;
    const slice = r.buf[r.pos .. r.pos + bytes];
    r.pos += bytes;
    return .{ .utf16 = slice, .num_chars = num };
}

fn writeAttributeListXml(chunk: []const u8, r: *Reader, w: anytype, src: Source, values: []const TemplateValue) !void {
    // Attribute list: u32 size (excludes the 4 size bytes), then attributes
    const list_size = try r.readU32le();
    {
        var stderr = std.io.getStdErr().writer();
        _ = try stderr.print("[binxml] attr list_size={d} rem={d}\n", .{ list_size, r.rem() });
    }
    const list_start = r.pos;
    const list_end = list_start + list_size;
    if (list_end > r.buf.len) return BinXmlError.UnexpectedEof;

    while (r.pos < list_end) {
        if (r.rem() == 0) break;
        const tok_peek = r.buf[r.pos];
        if (!isToken(tok_peek, TOK_ATTRIBUTE)) break;
        _ = try r.readU8();
        try w.writeByte(' ');
        var name_off: u32 = 0;
        var have_name_off: bool = false;
        var def_attr_utf16: []const u8 = &[_]u8{};
        var def_attr_num_chars: usize = 0;
        var have_inline_name: bool = false;
        switch (src) {
            .rec => {
                // Attribute name offset (chunk-relative)
                name_off = try r.readU32le();
                have_name_off = true;
                try writeNameFromOffset(chunk, name_off, w);
            },
            .def => {
                const nm = try readInlineNameDefFlexible(r);
                def_attr_utf16 = nm.utf16;
                def_attr_num_chars = nm.num_chars;
                have_inline_name = true;
                try writeNameFromUtf16(w, def_attr_utf16, def_attr_num_chars);
            },
        }
        try w.writeAll("=\"");
        // Special-case TimeCreated SystemTime to render with normalized padding in a single pass
        if ((have_name_off and isNameSystemTimeFromOffset(chunk, name_off)) or (have_inline_name and utf16EqualsAscii(def_attr_utf16, def_attr_num_chars, "SystemTime"))) {
            try writeSystemTimeAttributeValue(chunk, r, w, values);
            try w.writeByte('"');
            continue;
        }
        var attr_buf: [2048]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&attr_buf);
        const aw = fbs.writer();
        try collectAttributeValue(chunk, r, aw, values);
        const written = fbs.getWritten();
        var i_norm: usize = 0;
        while (i_norm < written.len) : (i_norm += 1) {
            const ch = written[i_norm];
            if (ch == '+') continue;
            try w.writeByte(ch);
        }
        try w.writeByte('"');

        // If attribute token had has-more flag, continue; else if we're at end, loop ends naturally
        // Note: More attributes are indicated by 0x46, but we already consumed current token; loop proceeds to next
    }

    // Attribute list may include padding; ensure we align to list_end
    if (r.pos != list_end) r.pos = list_end;
}

const TemplateValue = struct {
    t: u8,
    data: []const u8,
};

fn renderNestedEvtXml(chunk: []const u8, data: []const u8, w: anytype, values: []const TemplateValue) !void {
    if (data.len == 0) return;
    var sub = Reader.init(data);
    if (sub.rem() >= 4 and sub.buf[sub.pos] == TOK_FRAGMENT_HEADER) {
        _ = try sub.readU8();
        _ = try sub.readU8();
        _ = try sub.readU8();
        _ = try sub.readU8();
    }
    while (sub.rem() > 0) {
        const pk = try sub.peekU8();
        if (isToken(pk, TOK_OPEN_START)) {
            try renderElementXml(chunk, &sub, w, values, .def);
        } else break;
    }
}

fn parseTemplateInstanceValues(r: *Reader, allocator: std.mem.Allocator) ![]TemplateValue {
    // debug: show upcoming bytes
    {
        var stderr = std.io.getStdErr().writer();
        const show = @min(r.rem(), 16);
        _ = try stderr.print("[binxml] values hdr bytes:", .{});
        var i: usize = 0;
        while (i < show) : (i += 1) {
            _ = try stderr.print(" {x:0>2}", .{r.buf[r.pos + i]});
        }
        _ = try stderr.print("\n", .{});
    }
    const start_pos = r.pos;
    const num_values = try r.readU32le();
    {
        var stderr = std.io.getStdErr().writer();
        _ = try stderr.print("[binxml] num_values={d} rem={d}\n", .{ num_values, r.rem() });
    }
    const max_reasonable: usize = 512;
    if (num_values > 0 and num_values <= max_reasonable and r.rem() >= num_values * 4) {
        var sizes = try allocator.alloc(u16, num_values);
        errdefer allocator.free(sizes);
        var types = try allocator.alloc(u8, num_values);
        errdefer allocator.free(types);

        var i: usize = 0;
        while (i < num_values) : (i += 1) {
            sizes[i] = try r.readU16le();
            types[i] = try r.readU8();
            _ = try r.readU8(); // 0x00
        }

        var values = try allocator.alloc(TemplateValue, num_values);
        i = 0;
        while (i < num_values) : (i += 1) {
            const sz = sizes[i];
            const need = @as(usize, sz);
            if (r.rem() < need) return BinXmlError.UnexpectedEof;
            const slice = r.buf[r.pos .. r.pos + need];
            r.pos += need;
            values[i] = .{ .t = types[i], .data = slice };
        }
        allocator.free(sizes);
        allocator.free(types);
        return values;
    }

    // Fallback: parse descriptors until failure (no explicit count)
    r.pos = start_pos;
    var list = std.ArrayList(TemplateValue).init(allocator);
    errdefer list.deinit();
    while (r.rem() >= 4) {
        const sz = try r.readU16le();
        const t = try r.readU8();
        const z = try r.readU8();
        if (z != 0) break;
        const need = @as(usize, sz);
        if (r.rem() < need) break;
        const slice = r.buf[r.pos .. r.pos + need];
        r.pos += need;
        try list.append(.{ .t = t, .data = slice });
        // Heuristic stop: if next byte looks like an OpenStart or EndElement, stop
        if (r.rem() > 0) {
            const pk = r.buf[r.pos];
            if (isToken(pk, TOK_OPEN_START) or isToken(pk, TOK_END_ELEMENT)) break;
        }
    }
    return list.toOwnedSlice();
}

fn writeValueXml(w: anytype, t: u8, data: []const u8) !void {
    switch (t) {
        0x04 => { // UInt8
            if (data.len < 1) return BinXmlError.UnexpectedEof;
            const v: u8 = data[0];
            try w.print("{d}", .{v});
        },
        0x05 => { // Int16
            if (data.len < 2) return BinXmlError.UnexpectedEof;
            const v = std.mem.readInt(i16, data[0..2], .little);
            try w.print("{d}", .{v});
        },
        0x06 => { // UInt16
            if (data.len < 2) return BinXmlError.UnexpectedEof;
            const v = std.mem.readInt(u16, data[0..2], .little);
            try w.print("{d}", .{v});
        },
        0x01 => { // StringType -> expect Unicode text string layout (num_chars + UTF-16LE)
            if (data.len < 2) return BinXmlError.UnexpectedEof;
            const num_chars = std.mem.readInt(u16, data[0..2], .little);
            const byte_len = @as(usize, num_chars) * 2;
            if (2 + byte_len > data.len) return BinXmlError.UnexpectedEof;
            try writeUtf16LeXmlEscaped(w, data[2 .. 2 + byte_len], num_chars);
        },
        0x02 => { // AnsiStringType (codepage) - treat as bytes, escape
            try writeXmlEscaped(w, data);
        },
        0x07 => { // Int32Type
            if (data.len < 4) return BinXmlError.UnexpectedEof;
            const v = std.mem.readInt(i32, data[0..4], .little);
            try w.print("{d}", .{v});
        },
        0x08 => { // UInt32Type
            if (data.len < 4) return BinXmlError.UnexpectedEof;
            const v = std.mem.readInt(u32, data[0..4], .little);
            try w.print("{d}", .{v});
        },
        0x09 => { // Int64Type
            if (data.len < 8) return BinXmlError.UnexpectedEof;
            const v = std.mem.readInt(i64, data[0..8], .little);
            try w.print("{d}", .{v});
        },
        0x0a => { // UInt64Type
            if (data.len < 8) return BinXmlError.UnexpectedEof;
            const v = std.mem.readInt(u64, data[0..8], .little);
            try w.print("{d}", .{v});
        },
        0x0d => { // BoolType - 32-bit 0/1
            if (data.len < 4) return BinXmlError.UnexpectedEof;
            const v = std.mem.readInt(u32, data[0..4], .little);
            try w.writeAll(if (v == 0) "false" else "true");
        },
        0x0f => { // GuidType (16 bytes, first 3 components little-endian)
            if (data.len < 16) return BinXmlError.UnexpectedEof;
            const d1 = std.mem.readInt(u32, data[0..4], .little);
            const d2 = std.mem.readInt(u16, data[4..6], .little);
            const d3 = std.mem.readInt(u16, data[6..8], .little);
            const d4 = data[8..16];
            try w.print("{{{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}}}", .{
                d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7],
            });
        },
        0x11 => { // FileTimeType (64-bit)
            if (data.len < 8) return BinXmlError.UnexpectedEof;
            const ft = std.mem.readInt(u64, data[0..8], .little);
            var buf: [40]u8 = undefined;
            const out = formatIso8601UtcFromFiletimeMicros(&buf, ft) catch {
                return try w.print("{d}", .{ft});
            };
            try w.writeAll(out);
        },
        0x12 => { // SysTimeType (128-bit)
            if (data.len < 16) return BinXmlError.UnexpectedEof;
            const year = std.mem.readInt(u16, data[0..2], .little);
            const month = std.mem.readInt(u16, data[2..4], .little);
            // data[4..6] day of week
            const day = std.mem.readInt(u16, data[6..8], .little);
            const hour = std.mem.readInt(u16, data[8..10], .little);
            const minute = std.mem.readInt(u16, data[10..12], .little);
            const second = std.mem.readInt(u16, data[12..14], .little);
            const millis = std.mem.readInt(u16, data[14..16], .little);
            var buf: [32]u8 = undefined;
            const slice = try std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
                year, month, day, hour, minute, second, millis,
            });
            try w.writeAll(slice);
        },
        0x13 => { // SidType
            if (data.len < 8) return BinXmlError.UnexpectedEof;
            const rev = data[0];
            const sub_count = data[1];
            const ida_bytes = data[2..8];
            var idauth: u64 = 0;
            // IdentifierAuthority is big-endian 48-bit
            var k: usize = 0;
            while (k < 6) : (k += 1) {
                idauth = (idauth << 8) | ida_bytes[k];
            }
            try w.print("S-{d}-{d}", .{ rev, idauth });
            var off: usize = 8;
            var i: usize = 0;
            while (i < sub_count and off + 4 <= data.len) : (i += 1) {
                const sub = std.mem.readInt(u32, data[off .. off + 4][0..4], .little);
                off += 4;
                try w.print("-{d}", .{sub});
            }
        },
        0x0e => { // BinaryType → hex
            var i: usize = 0;
            while (i < data.len) : (i += 1) {
                try w.print("{x:0>2}", .{data[i]});
            }
        },
        0x14 => { // HexInt32Type
            if (data.len < 4) return BinXmlError.UnexpectedEof;
            const v = std.mem.readInt(u32, data[0..4], .little);
            try w.print("0x{X}", .{v});
        },
        0x15 => { // HexInt64Type
            if (data.len < 8) return BinXmlError.UnexpectedEof;
            const v = std.mem.readInt(u64, data[0..8], .little);
            try w.print("0x{X}", .{v});
        },
        // 0x21 => EvtXml (nested binary XML) is not handled here to avoid re-entrant parsing in value writer
        else => {
            // TODO: implement other types; for now, no-op for unsupported
        },
    }
}

fn formatIso8601UtcFromUnixMs(buf: []u8, unix_secs: i64, ms: u32) ![]const u8 {
    // Convert unix seconds to UTC date using civil_from_days algorithm
    const z0: i64 = @divFloor(unix_secs, 86400);
    const sod: i64 = unix_secs - z0 * 86400;
    const z = z0 + 719468; // shift to civil ordinal
    const era = @divFloor(z, 146097);
    const doe = z - era * 146097; // [0, 146096]
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365); // [0, 399]
    var y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100)); // [0, 365]
    const mp = @divFloor(5 * doy + 2, 153); // [0, 11]
    const d = doy - @divFloor(153 * mp + 2, 5) + 1; // [1, 31]
    const m = mp + 3 - 12 * @as(i32, @intFromBool(mp >= 10));
    y += @as(i64, @intFromBool(m <= 2));
    const hour = @as(i32, @intCast(@divFloor(sod, 3600)));
    const sod_rem = sod - @as(i64, hour) * 3600;
    const min = @as(i32, @intCast(@divFloor(sod_rem, 60)));
    const sec = @as(i32, @intCast(sod_rem - @as(i64, min) * 60));
    const out = try std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        y, m, d, hour, min, sec, ms,
    });
    return out;
}

fn formatIso8601UtcFromFiletimeMicros(buf: []u8, filetime: u64) ![]const u8 {
    const TICKS_PER_SEC: u64 = 10_000_000;
    const TICKS_PER_MICRO: u64 = 10;
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;

    if (filetime < EPOCH_DIFF_SECS * TICKS_PER_SEC) {
        return std.fmt.bufPrint(buf, "1970-01-01T00:00:00.000000Z", .{});
    }

    const total_seconds_1601: u64 = filetime / TICKS_PER_SEC;
    const unix_seconds: u64 = total_seconds_1601 - EPOCH_DIFF_SECS;
    const ticks_remainder: u64 = filetime % TICKS_PER_SEC;
    const micros: u32 = @intCast(ticks_remainder / TICKS_PER_MICRO);

    const z0: u64 = unix_seconds / 86_400;
    const sod: u64 = unix_seconds % 86_400;
    const z: i64 = @as(i64, @intCast(z0)) + 719468;
    const era: i64 = @divFloor(z, 146097);
    const doe: i64 = z - era * 146097;
    const yoe: i64 = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    var y: i64 = yoe + era * 400;
    const doy: i64 = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp: i64 = @divFloor(5 * doy + 2, 153);
    const d: i64 = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m: i64 = mp + 3 - 12 * @as(i32, @intFromBool(mp >= 10));
    y += @as(i64, @intFromBool(m <= 2));
    const hour: u32 = @intCast(sod / 3600);
    const sod_rem: u64 = sod - @as(u64, hour) * 3600;
    const minute: u32 = @intCast(sod_rem / 60);
    const second: u32 = @intCast(sod_rem - @as(u64, minute) * 60);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z", .{
        y, m, d, hour, minute, second, micros,
    });
}

fn writePaddedInt(w: anytype, comptime T: type, value: T, pad_width: usize) !void {
    if (pad_width == 0) {
        try w.print("{d}", .{value});
        return;
    }
    var buf: [64]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{d}", .{value});
    if (s.len >= pad_width) {
        try w.writeAll(s);
        return;
    }
    var zeros: [32]u8 = undefined;
    const need = @min(pad_width - s.len, zeros.len);
    @memset(zeros[0..need], '0');
    try w.writeAll(zeros[0..need]);
    try w.writeAll(s);
}

fn renderSubstitutionXml(_chunk: []const u8, w: anytype, is_optional: bool, r: *Reader, values: []const TemplateValue, pad_width: usize) anyerror!void {
    _ = _chunk;
    const id = try r.readU16le();
    const vtype = try r.readU8();
    if (id >= values.len) return BinXmlError.OutOfBounds;
    const v = values[id];
    // debug
    {
        var stderr = std.io.getStdErr().writer();
        _ = stderr.print("[binxml] subst id={d} vtype=0x{x} store.t=0x{x} len={d} opt={d} pad={d}\n", .{ id, vtype, v.t, v.data.len, @intFromBool(is_optional), pad_width }) catch {};
    }
    if (is_optional and (v.t == 0x00 or v.data.len == 0)) {
        // Skip emitting anything for NULL optional
        return;
    }
    // Array handling: if MSB set, repeat for each element
    if ((vtype & 0x80) != 0) {
        const base = vtype & 0x7F;
        switch (base) {
            0x01 => { // array of Unicode strings: emit comma-separated; trim trailing empty items
                // First pass: identify item ranges and last non-empty index
                var ranges = std.ArrayList(struct { start: usize, end: usize }).init(std.heap.page_allocator);
                defer ranges.deinit();
                var i: usize = 0;
                while (i <= v.data.len) {
                    const start = i;
                    var end = i;
                    while (end + 1 < v.data.len) : (end += 2) {
                        const u = std.mem.readInt(u16, v.data[end .. end + 2][0..2], .little);
                        if (u == 0) break;
                    }
                    try ranges.append(.{ .start = start, .end = end });
                    if (end + 1 < v.data.len) {
                        i = end + 2;
                        continue;
                    } else break;
                }
                var last_non_empty: isize = -1;
                var idx_scan: usize = 0;
                while (idx_scan < ranges.items.len) : (idx_scan += 1) {
                    const rr = ranges.items[idx_scan];
                    if (rr.end > rr.start) last_non_empty = @as(isize, @intCast(idx_scan));
                }
                if (last_non_empty >= 0) {
                    var out_idx: usize = 0;
                    while (out_idx <= @as(usize, @intCast(last_non_empty))) : (out_idx += 1) {
                        if (out_idx > 0) try w.writeByte(',');
                        const rr2 = ranges.items[out_idx];
                        if (rr2.end > rr2.start) {
                            const num_chars = (rr2.end - rr2.start) / 2;
                            try writeUtf16LeXmlEscaped(w, v.data[rr2.start..rr2.end], num_chars);
                        }
                    }
                }
            },
            else => {
                // TODO: implement arrays for other base types
            },
        }
        return;
    }
    // Queue nested EvtXml (0x21) from substitutions
    if ((v.t & 0x7F) == 0x21 and v.data.len > 0) {
        // If a child element just closed, this substitution arrives in the parent
        // content. Queue onto the current frame so it flushes on the parent’s close.
        r.queueEvtXml(v.data);
        return;
    }

    // If padding requested and base type is integer, pad
    const base = vtype & 0x7F;
    if (pad_width > 0) {
        switch (base) {
            0x07 => { // Int32
                if (v.data.len < 4) return BinXmlError.UnexpectedEof;
                const num = std.mem.readInt(i32, v.data[0..4], .little);
                try writePaddedInt(w, i32, num, pad_width);
                return;
            },
            0x08 => { // UInt32
                if (v.data.len < 4) return BinXmlError.UnexpectedEof;
                const num = std.mem.readInt(u32, v.data[0..4], .little);
                try writePaddedInt(w, u32, num, pad_width);
                return;
            },
            0x09 => { // Int64
                if (v.data.len < 8) return BinXmlError.UnexpectedEof;
                const num = std.mem.readInt(i64, v.data[0..8], .little);
                try writePaddedInt(w, i64, num, pad_width);
                return;
            },
            0x0a => { // UInt64
                if (v.data.len < 8) return BinXmlError.UnexpectedEof;
                const num = std.mem.readInt(u64, v.data[0..8], .little);
                try writePaddedInt(w, u64, num, pad_width);
                return;
            },
            else => {},
        }
    }
    try writeValueXml(w, v.t, v.data);
}

fn renderElementXml(chunk: []const u8, r: *Reader, w: anytype, values: []const TemplateValue, src: Source) anyerror!void {
    {
        var stderr = std.io.getStdErr().writer();
        const show = @min(r.rem(), 12);
        _ = try stderr.print("[binxml] elem start peek src={s} bytes:", .{if (src == .rec) "rec" else "def"});
        var i: usize = 0;
        while (i < show) : (i += 1) {
            _ = try stderr.print(" {x:0>2}", .{r.buf[r.pos + i]});
        }
        _ = try stderr.print("\n", .{});
    }
    const element_start_pos = r.pos;
    const start_tok = try r.readU8();
    {
        var stderr = std.io.getStdErr().writer();
        _ = try stderr.print("[binxml] elem start_tok=0x{x} src={s}\n", .{ start_tok, if (src == .rec) "rec" else "def" });
    }
    if (!isToken(start_tok, TOK_OPEN_START)) return BinXmlError.BadToken;
    // dependency id
    if (r.rem() < 2) return BinXmlError.UnexpectedEof;
    const dep_id = try r.readU16le();
    {
        var stderr = std.io.getStdErr().writer();
        _ = try stderr.print("[binxml] dep_id=0x{x}\n", .{dep_id});
    }
    const data_size = try r.readU32le();
    const element_end_pos = element_start_pos + 7 + @as(usize, data_size);
    var name_off: u32 = 0;
    var def_name: []const u8 = &[_]u8{};
    var def_name_chars: usize = 0;
    var use_name_offset: bool = (src == .rec);
    switch (src) {
        .rec => {
            name_off = try r.readU32le();
            use_name_offset = true;
        },
        .def => {
            {
                var stderr = std.io.getStdErr().writer();
                const show = @min(r.rem(), 24);
                _ = try stderr.print("[binxml] def name bytes:", .{});
                var i: usize = 0;
                while (i < show) : (i += 1) {
                    _ = try stderr.print(" {x:0>2}", .{r.buf[r.pos + i]});
                }
                _ = try stderr.print("\n", .{});
            }
            const nm = try readInlineNameDefFlexible(r);
            def_name = nm.utf16;
            def_name_chars = nm.num_chars;
            use_name_offset = false;
        },
    }
    // New element scope
    r.pushFrame();
    try w.writeByte('<');
    if (use_name_offset) try writeNameFromOffset(chunk, name_off, w) else try writeNameFromUtf16(w, def_name, def_name_chars);
    const has_attrs = hasMore(start_tok, TOK_OPEN_START);
    var pad: usize = 0;
    if (has_attrs) {
        try writeAttributeListXml(chunk, r, w, src, values);
        if (r.pos > element_end_pos) r.pos = element_end_pos;
        // Some definitions include padding (up to 4 zero bytes) after attribute list
        while (pad < 4 and r.rem() > 0 and r.buf[r.pos] == 0) : (pad += 1) {
            r.pos += 1;
        }
    }
    if (r.pos >= element_end_pos) return BinXmlError.UnexpectedEof;
    const nxt = try r.readU8();
    {
        var stderr = std.io.getStdErr().writer();
        _ = try stderr.print("[binxml] after attrs nxt=0x{x} pad={d}\n", .{ nxt, pad });
    }
    if (isToken(nxt, TOK_CLOSE_EMPTY)) {
        try w.writeAll("/>");
        return;
    }
    if (!isToken(nxt, TOK_CLOSE_START)) return BinXmlError.BadToken;
    try w.writeByte('>');

    // content
    var content_pad2: bool = false;
    while (true) {
        const t = try r.peekU8();
        {
            var stderr = std.io.getStdErr().writer();
            _ = try stderr.print("[binxml] content tok=0x{x} rem={d}\n", .{ t, r.rem() });
        }
        if (isToken(t, TOK_END_ELEMENT)) {
            _ = try r.readU8();
            // Before writing the closing tag, flush any queued nested EvtXml so they appear as children
            try flushPendingNested(r, chunk, w, values);
            try w.writeAll("</");
            if (use_name_offset) try writeNameFromOffset(chunk, name_off, w) else try writeNameFromUtf16(w, def_name, def_name_chars);
            try w.writeByte('>');
            // Pop scope after closing tag
            if (r.depth > 0) r.depth -= 1;
            return;
        } else if (isToken(t, TOK_OPEN_START)) {
            try renderElementXml(chunk, r, w, values, src);
        } else if (isToken(t, TOK_VALUE)) {
            // Concatenate value tokens sequence
            while (true) {
                _ = try r.readU8();
                const vtype = try r.readU8();
                {
                    var stderr = std.io.getStdErr().writer();
                    _ = try stderr.print("[binxml] value vtype=0x{x}\n", .{vtype});
                }
                if ((vtype & 0x7f) == 0x21) {
                    // Nested EvtXml payload embedded directly in content
                    if (r.rem() < 2) return BinXmlError.UnexpectedEof;
                    const blen = try r.readU16le();
                    if (r.rem() < blen) return BinXmlError.UnexpectedEof;
                    r.queueEvtXml(r.buf[r.pos .. r.pos + blen]);
                    r.pos += blen;
                } else if (vtype == 0x01) {
                    var text = try readUnicodeTextString(r);
                    // Handle '+' formatting sentinel like in attributes: a standalone '+' (UTF-16LE) requests zero-padding for the next number
                    if (text.len >= 2 and text[0] == 0x2B and text[1] == 0x00) {
                        if (text.len == 2) {
                            content_pad2 = true;
                            // Do not emit this sentinel
                            // fallthrough to next token
                        } else {
                            // Strip leading '+' and emit the rest
                            text = text[2..];
                            try writeUtf16LeXmlEscaped(w, text, text.len / 2);
                        }
                    } else {
                        try writeUtf16LeXmlEscaped(w, text, text.len / 2);
                    }
                } else if (valueTypeFixedSize(vtype)) |sz| {
                    const payload = try readFixedBytes(r, sz);
                    if (content_pad2 and (vtype == 0x07 or vtype == 0x08 or vtype == 0x09 or vtype == 0x0a)) {
                        switch (vtype) {
                            0x07 => {
                                const num = std.mem.readInt(i32, @as(*const [4]u8, @ptrCast(payload.ptr)), .little);
                                try writePaddedInt(w, i32, num, 2);
                            },
                            0x08 => {
                                const num = std.mem.readInt(u32, @as(*const [4]u8, @ptrCast(payload.ptr)), .little);
                                try writePaddedInt(w, u32, num, 2);
                            },
                            0x09 => {
                                const num = std.mem.readInt(i64, @as(*const [8]u8, @ptrCast(payload.ptr)), .little);
                                try writePaddedInt(w, i64, num, 2);
                            },
                            0x0a => {
                                const num = std.mem.readInt(u64, @as(*const [8]u8, @ptrCast(payload.ptr)), .little);
                                try writePaddedInt(w, u64, num, 2);
                            },
                            else => unreachable,
                        }
                        content_pad2 = false;
                    } else {
                        try writeValueXml(w, vtype, payload);
                    }
                } else if (vtype == 0x0e) {
                    if (r.rem() < 2) return BinXmlError.UnexpectedEof;
                    const blen = try r.readU16le();
                    const payload = try readFixedBytes(r, blen);
                    try writeValueXml(w, vtype, payload);
                } else if (vtype == 0x13) {
                    if (r.rem() < 8) return BinXmlError.UnexpectedEof;
                    const start_pos = r.pos;
                    _ = try r.readU8(); // rev
                    const subc = try r.readU8();
                    _ = try readFixedBytes(r, 6);
                    const needed: usize = 8 + @as(usize, subc) * 4;
                    r.pos = start_pos;
                    const payload = try readFixedBytes(r, needed);
                    try writeValueXml(w, vtype, payload);
                } else {
                    return BinXmlError.BadToken;
                }
                if (r.rem() == 0) break;
                const pk = try r.peekU8();
                if (!isToken(pk, TOK_VALUE)) break;
            }
        } else if (isToken(t, TOK_CDATA)) {
            _ = try r.readU8();
            const data = try readUnicodeTextString(r);
            try w.writeAll("<![CDATA[");
            // Emit raw UTF-8; CDATA must not be escaped; here we best-effort convert to UTF-8
            try writeUtf16LeXmlEscaped(w, data, data.len / 2);
            try w.writeAll("]]>");
        } else if (isToken(t, TOK_CHARREF)) {
            _ = try r.readU8();
            // 16-bit value
            const v = try r.readU16le();
            try w.print("&#{d};", .{v});
        } else if (isToken(t, TOK_ENTITYREF)) {
            _ = try r.readU8();
            // Name offset variant for entity. Read name-offset like a Name and output &name;
            const ent_name_off = try r.readU32le();
            try w.writeByte('&');
            try writeNameFromOffset(chunk, ent_name_off, w);
            try w.writeByte(';');
        } else if (isToken(t, TOK_NORMAL_SUBST)) {
            _ = try r.readU8();
            const padw: usize = if (content_pad2) 2 else 0;
            try renderSubstitutionXml(chunk, w, false, r, values, padw);
            content_pad2 = false;
        } else if (isToken(t, TOK_OPTIONAL_SUBST)) {
            _ = try r.readU8();
            const padw: usize = if (content_pad2) 2 else 0;
            try renderSubstitutionXml(chunk, w, true, r, values, padw);
            content_pad2 = false;
        } else if (t == TOK_EOF) {
            return BinXmlError.UnexpectedEof;
        } else {
            return BinXmlError.BadToken;
        }
    }
}

fn renderXml(chunk: []const u8, bin: []const u8, w: anytype) anyerror!void {
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
    // debug
    {
        var stderr = std.io.getStdErr().writer();
        _ = try stderr.print("[binxml] first=0x{x} len={d}\n", .{ first, bin.len });
    }
    if (first == TOK_TEMPLATE_INSTANCE) {
        _ = try r.readU8(); // consume
        // Template definition (header within the record, data in chunk at def_data_off)
        if (r.rem() < 1 + 4 + 4 + 4 + 16 + 4) return BinXmlError.UnexpectedEof;
        _ = try r.readU8(); // unknown
        _ = try r.readU32le(); // template id (unused)
        const def_data_off = try r.readU32le();
        _ = try r.readU32le(); // next def off (unused)
        // GUID
        if (r.rem() < 16) return BinXmlError.UnexpectedEof;
        r.pos += 16;
        const def_size = try r.readU32le();
        {
            var stderr = std.io.getStdErr().writer();
            _ = try stderr.print("[binxml] tmpl def_off=0x{x} def_size={d}\n", .{ def_data_off, def_size });
        }

        // Use alternative TemplateDefinition header layout: [4 bytes unknown][16 bytes GUID][4 bytes data_size][data...]
        const def_off_usize: usize = @intCast(def_data_off);
        if (def_off_usize + 24 > chunk.len) return BinXmlError.OutOfBounds;
        const td_data_size = std.mem.readInt(u32, chunk[def_off_usize + 20 .. def_off_usize + 24][0..4], .little);
        const data_start = def_off_usize + 24;
        const data_end = data_start + @as(usize, td_data_size);
        if (data_end > chunk.len or data_start >= chunk.len) return BinXmlError.OutOfBounds;
        {
            var stderr = std.io.getStdErr().writer();
            _ = try stderr.print("[binxml] using chunk def data at 0x{x}..0x{x}\n", .{ data_start, data_end });
        }
        var def_r = Reader.init(chunk[data_start..data_end]);
        // Optional fragment header inside definition
        if (def_r.rem() >= 4 and def_r.buf[def_r.pos] == TOK_FRAGMENT_HEADER) {
            _ = try def_r.readU8();
            _ = try def_r.readU8();
            _ = try def_r.readU8();
            _ = try def_r.readU8();
        }

        // Skip inline copy of template definition data in the record if present
        if (r.rem() >= def_size and (r.buf[r.pos] == TOK_FRAGMENT_HEADER or r.buf[r.pos] == TOK_OPEN_START)) {
            const start = r.pos;
            const end = start + @as(usize, def_size);
            r.pos = end;
            {
                var stderr = std.io.getStdErr().writer();
                _ = try stderr.print("[binxml] skipped inline def at rec+0x{x}..0x{x}\n", .{ start, end });
            }
        }

        // Values follow in the record after the header we just read (and possible inline data)
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const alloc = gpa.allocator();
        const values = try parseTemplateInstanceValues(&r, alloc);
        defer alloc.free(values);
        try renderElementXml(chunk, &def_r, w, values, .def);
        // Final safety flush for any residual queued nested payloads
        try flushPendingNested(&def_r, chunk, w, values);
        return;
    } else {
        try renderElementXml(chunk, &r, w, &[_]TemplateValue{}, .rec);
        try flushPendingNested(&r, chunk, w, &[_]TemplateValue{});
        return;
    }
}

pub fn render(chunk: []const u8, bin: []const u8, mode: RenderMode, w: anytype) !void {
    switch (mode) {
        .xml => try renderXml(chunk, bin, w),
        .json => try w.writeAll("{}"),
        .jsonl => try w.writeAll("{}"),
    }
}
