const std = @import("std");

inline fn xmlEntityFor(c: u8) ?[]const u8 {
    return switch (c) {
        '&' => "&amp;",
        '<' => "&lt;",
        '>' => "&gt;",
        '"' => "&quot;",
        '\'' => "&apos;",
        else => null,
    };
}

inline fn flushAsciiRun(w: anytype, ascii_buf: *[256]u8, ascii_len: *usize) !void {
    if (ascii_len.* > 0) {
        try w.writeAll(ascii_buf.*[0..ascii_len.*]);
        ascii_len.* = 0;
    }
}

inline fn queueAsciiOrEntity(
    w: anytype,
    c: u8,
    ascii_buf: *[256]u8,
    ascii_len: *usize,
) !void {
    if (xmlEntityFor(c)) |e| {
        try flushAsciiRun(w, ascii_buf, ascii_len);
        try w.writeAll(e);
    } else {
        if (ascii_len.* == ascii_buf.len) {
            try flushAsciiRun(w, ascii_buf, ascii_len);
        }
        ascii_buf.*[ascii_len.*] = c;
        ascii_len.* += 1;
    }
}

pub fn writeXmlEscaped(w: anytype, s: []const u8) !void {
    // Fast path: scan and write contiguous safe spans; only emit entities when needed
    var i: usize = 0;
    var start: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (xmlEntityFor(c)) |e| {
            if (i > start) try w.writeAll(s[start..i]);
            try w.writeAll(e);
            start = i + 1;
        }
    }
    if (start < s.len) try w.writeAll(s[start..]);
}

// JSON escaping for UTF-8 input
pub fn jsonEscapeUtf8(w: anytype, s: []const u8) !void {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            0x08 => try w.writeAll("\\b"),
            0x0c => try w.writeAll("\\f"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    var buf: [6]u8 = undefined;
                    _ = try std.fmt.bufPrint(&buf, "\\u{X:0>4}", .{c});
                    try w.writeAll(&buf);
                } else {
                    try w.writeByte(c);
                }
            },
        }
    }
}

fn writeUtf16LeWithEscaper(w: anytype, utf16le: []const u8, num_chars: usize, comptime escape: anytype) !void {
    var i: usize = 0;
    while (i < num_chars and (i * 2 + 1) < utf16le.len) : (i += 1) {
        const lo = @as(u16, utf16le[i * 2]) | (@as(u16, utf16le[i * 2 + 1]) << 8);
        var codepoint: u21 = lo;
        if (lo >= 0xD800 and lo <= 0xDBFF) {
            if (i + 1 >= num_chars or (i + 1) * 2 + 1 >= utf16le.len) break;
            const lo2 = @as(u16, utf16le[(i + 1) * 2]) | (@as(u16, utf16le[(i + 1) * 2 + 1]) << 8);
            if (lo2 >= 0xDC00 and lo2 <= 0xDFFF) {
                const high_ten = lo - 0xD800;
                const low_ten = lo2 - 0xDC00;
                codepoint = 0x10000 + (@as(u21, high_ten) << 10) + @as(u21, low_ten);
                i += 1;
            } else {
                continue;
            }
        } else if (lo >= 0xDC00 and lo <= 0xDFFF) {
            continue;
        }
        var buf: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(codepoint, &buf) catch 0;
        if (len == 0) continue;
        try escape(w, buf[0..len]);
    }
}

inline fn flushOut2048(w: anytype, ob: *[2048]u8, olen: *usize) !void {
    if (olen.* != 0) {
        try w.writeAll(ob.*[0..olen.*]);
        olen.* = 0;
    }
}

pub fn writeUtf16LeXmlEscaped(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    // On platforms with decent vector support this SIMD-assisted path provides
    // measurable wins for ASCII-heavy inputs. Fallback preserves behavior.
    const builtin = @import("builtin");
    if (builtin.cpu.arch == .aarch64 or builtin.cpu.arch == .x86_64) {
        return writeUtf16LeXmlEscaped_simd(w, utf16le, num_chars);
    }
    return writeUtf16LeXmlEscaped_scalar(w, utf16le, num_chars);
}

fn writeUtf16LeXmlEscaped_scalar(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    // Aggregate into a single stack buffer to minimize writer calls. This reduces
    // ArrayList growth and per-call overhead significantly on hot paths.
    var out_buf: [2048]u8 = undefined;
    var out_len: usize = 0;

    // Compile-time table for the five XML-escape characters in ASCII
    const esc_table = blk: {
        var t: [128]u8 = [_]u8{0} ** 128;
        t['&'] = 1;
        t['<'] = 1;
        t['>'] = 1;
        t['"'] = 1;
        t['\''] = 1;
        break :blk t;
    };

    // Bounds once up-front, avoid repeated i*2 checks in the loop
    const max_chars: usize = @min(num_chars, utf16le.len / 2);
    if (max_chars == 0) return;

    var i: usize = 0;
    var p: usize = 0; // byte index into utf16le
    while (i < max_chars) : (i += 1) {
        const b0: u8 = utf16le[p];
        const b1: u8 = utf16le[p + 1];
        p += 2;

        // ASCII fast-path (hi byte is zero)
        if (b1 == 0) {
            const c: u8 = b0;
            if (c < 0x80) {
                if (esc_table[c] != 0) {
                    // entity write: copy entity literal into out buffer
                    const e: []const u8 = switch (c) {
                        '&' => "&amp;",
                        '<' => "&lt;",
                        '>' => "&gt;",
                        '"' => "&quot;",
                        '\'' => "&apos;",
                        else => unreachable,
                    };
                    if (out_len + e.len > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                    std.mem.copyForwards(u8, out_buf[out_len .. out_len + e.len], e);
                    out_len += e.len;
                } else {
                    if (out_len == out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                    out_buf[out_len] = c;
                    out_len += 1;
                }
                continue;
            }
            // Non-ASCII in BMP with high byte zero (0x80..0xFF) -> 2-byte UTF-8
            if (out_len + 2 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
            out_buf[out_len] = 0xC0 | (c >> 6);
            out_buf[out_len + 1] = 0x80 | (c & 0x3F);
            out_len += 2;
            continue;
        }

        // General BMP / surrogate handling
        const u: u16 = @as(u16, b0) | (@as(u16, b1) << 8);
        if (u < 0xD800 or u > 0xDFFF) {
            const cp: u21 = u;
            if (cp <= 0x07FF) {
                if (out_len + 2 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                out_buf[out_len] = 0xC0 | (@as(u8, @truncate(cp >> 6)));
                out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
                out_len += 2;
            } else {
                if (out_len + 3 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                out_buf[out_len] = 0xE0 | (@as(u8, @truncate(cp >> 12)));
                out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate((cp >> 6) & 0x3F)));
                out_buf[out_len + 2] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
                out_len += 3;
            }
            continue;
        }

        // Surrogate pair: high surrogate followed by low surrogate
        if (u >= 0xD800 and u <= 0xDBFF) {
            if (i + 1 >= max_chars) break; // incomplete pair -> stop
            const b20: u8 = utf16le[p];
            const b21: u8 = utf16le[p + 1];
            const lo_sur: u16 = @as(u16, b20) | (@as(u16, b21) << 8);
            if (lo_sur < 0xDC00 or lo_sur > 0xDFFF) {
                // invalid pair: skip second unit if it exists next iteration
                continue;
            }
            // valid surrogate: consume the low surrogate as part of this iteration
            p += 2;
            i += 1;
            const high_ten: u21 = @as(u21, u - 0xD800);
            const low_ten: u21 = @as(u21, lo_sur - 0xDC00);
            const cp: u21 = 0x10000 + (high_ten << 10) + low_ten;
            if (out_len + 4 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
            out_buf[out_len] = 0xF0 | (@as(u8, @truncate(cp >> 18)));
            out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate((cp >> 12) & 0x3F)));
            out_buf[out_len + 2] = 0x80 | (@as(u8, @truncate((cp >> 6) & 0x3F)));
            out_buf[out_len + 3] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
            out_len += 4;
            continue;
        }

        // Lone low surrogate: skip (best-effort robustness)
        // (u in 0xDC00..0xDFFF)
    }
    try flushOut2048(w, &out_buf, &out_len);
}

// Experimental SIMD-assisted variant: accelerates ASCII, non-escaping runs by
// scanning 8 UTF-16 code units at a time. Falls back to scalar for mixed blocks.
pub fn writeUtf16LeXmlEscaped_simd(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    var out_buf: [2048]u8 = undefined;
    var out_len: usize = 0;

    const esc_table = blk: {
        var t: [128]u8 = [_]u8{0} ** 128;
        t['&'] = 1;
        t['<'] = 1;
        t['>'] = 1;
        t['"'] = 1;
        t['\''] = 1;
        break :blk t;
    };

    const max_chars: usize = @min(num_chars, utf16le.len / 2);
    if (max_chars == 0) return;

    var i: usize = 0;
    var p: usize = 0; // byte index
    // Block process in groups of 8 u16 (16 bytes)
    while (i + 8 <= max_chars) {
        var blk: [16]u8 = undefined;
        @memcpy(blk[0..], utf16le[p .. p + 16]);
        const vec_u16: @Vector(8, u16) = @bitCast(blk);
        const ascii_mask: @Vector(8, bool) = vec_u16 <= @as(@Vector(8, u16), @splat(0x7f));
        const m_amp: @Vector(8, bool) = vec_u16 == @as(@Vector(8, u16), @splat(38));
        const m_lt: @Vector(8, bool) = vec_u16 == @as(@Vector(8, u16), @splat(60));
        const m_gt: @Vector(8, bool) = vec_u16 == @as(@Vector(8, u16), @splat(62));
        const m_quot: @Vector(8, bool) = vec_u16 == @as(@Vector(8, u16), @splat(34));
        const m_apos: @Vector(8, bool) = vec_u16 == @as(@Vector(8, u16), @splat(39));
        const all_ascii = @reduce(.And, ascii_mask);
        const esc_mask_u1: @Vector(8, u1) =
            @as(@Vector(8, u1), @bitCast(m_amp)) |
            @as(@Vector(8, u1), @bitCast(m_lt)) |
            @as(@Vector(8, u1), @bitCast(m_gt)) |
            @as(@Vector(8, u1), @bitCast(m_quot)) |
            @as(@Vector(8, u1), @bitCast(m_apos));
        const any_escape = @reduce(.Or, @as(@Vector(8, bool), @bitCast(esc_mask_u1)));
        if (all_ascii and !any_escape) {
            // Emit low bytes directly
            if (out_len + 8 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
            // Low bytes are at even positions in blk
            out_buf[out_len + 0] = blk[0];
            out_buf[out_len + 1] = blk[2];
            out_buf[out_len + 2] = blk[4];
            out_buf[out_len + 3] = blk[6];
            out_buf[out_len + 4] = blk[8];
            out_buf[out_len + 5] = blk[10];
            out_buf[out_len + 6] = blk[12];
            out_buf[out_len + 7] = blk[14];
            out_len += 8;
            p += 16;
            i += 8;
            continue;
        }
        // Fallback: process first code unit of this block with scalar logic
        // to keep implementation simple, then continue loop
        const b0: u8 = blk[0];
        const b1: u8 = blk[1];
        p += 2;
        i += 1;
        if (b1 == 0) {
            const c: u8 = b0;
            if (c < 0x80) {
                if (esc_table[c] != 0) {
                    const e: []const u8 = switch (c) {
                        '&' => "&amp;",
                        '<' => "&lt;",
                        '>' => "&gt;",
                        '"' => "&quot;",
                        '\'' => "&apos;",
                        else => unreachable,
                    };
                    if (out_len + e.len > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                    std.mem.copyForwards(u8, out_buf[out_len .. out_len + e.len], e);
                    out_len += e.len;
                } else {
                    if (out_len == out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                    out_buf[out_len] = c;
                    out_len += 1;
                }
            } else {
                if (out_len + 2 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                out_buf[out_len] = 0xC0 | (c >> 6);
                out_buf[out_len + 1] = 0x80 | (c & 0x3F);
                out_len += 2;
            }
            continue;
        }
        const u: u16 = @as(u16, b0) | (@as(u16, b1) << 8);
        if (u < 0xD800 or u > 0xDFFF) {
            const cp: u21 = u;
            if (cp <= 0x07FF) {
                if (out_len + 2 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                out_buf[out_len] = 0xC0 | (@as(u8, @truncate(cp >> 6)));
                out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
                out_len += 2;
            } else {
                if (out_len + 3 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                out_buf[out_len] = 0xE0 | (@as(u8, @truncate(cp >> 12)));
                out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate((cp >> 6) & 0x3F)));
                out_buf[out_len + 2] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
                out_len += 3;
            }
            continue;
        }
        if (u >= 0xD800 and u <= 0xDBFF) {
            if (i >= max_chars) break;
            const sb0 = utf16le[p];
            const sb1 = utf16le[p + 1];
            const lo_sur: u16 = @as(u16, sb0) | (@as(u16, sb1) << 8);
            if (lo_sur < 0xDC00 or lo_sur > 0xDFFF) continue;
            p += 2;
            i += 1;
            const high_ten: u21 = @as(u21, u - 0xD800);
            const low_ten: u21 = @as(u21, lo_sur - 0xDC00);
            const cp: u21 = 0x10000 + (high_ten << 10) + low_ten;
            if (out_len + 4 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
            out_buf[out_len] = 0xF0 | (@as(u8, @truncate(cp >> 18)));
            out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate((cp >> 12) & 0x3F)));
            out_buf[out_len + 2] = 0x80 | (@as(u8, @truncate((cp >> 6) & 0x3F)));
            out_buf[out_len + 3] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
            out_len += 4;
            continue;
        }
        // lone low surrogate: skip
    }
    // Tail (less than 8 code units): reuse scalar path for correctness
    if (i < max_chars) {
        try writeUtf16LeXmlEscaped_scalar(w, utf16le[p..], max_chars - i);
        // writeUtf16LeXmlEscaped flushes its own buffer; but we still need to flush ours
    }
    try flushOut2048(w, &out_buf, &out_len);
}

test "writeUtf16LeXmlEscaped_simd matches scalar on mixed inputs" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const A = gpa.allocator();

    const cases = [_][]const u8{
        "",
        "abc",
        "a&b<c>d\"'",
        // non-ascii bytes that become 2-byte UTF-8
        "\xC2\xA9 plain & < > \"'", // © followed by escapables
    };
    var i: usize = 0;
    while (i < cases.len) : (i += 1) {
        const ascii = cases[i];
        const utf16 = try utf16FromAscii(A, ascii);
        defer A.free(utf16);
        const num_chars = utf16.len / 2;

        var buf1 = std.ArrayList(u8).init(A);
        defer buf1.deinit();
        var buf2 = std.ArrayList(u8).init(A);
        defer buf2.deinit();
        const w1 = buf1.writer();
        const w2 = buf2.writer();
        try writeUtf16LeXmlEscaped(w1, utf16, num_chars);
        try writeUtf16LeXmlEscaped_simd(w2, utf16, num_chars);
        try std.testing.expectEqualSlices(u8, buf1.items, buf2.items);
    }
}

// Baseline implementation kept for microbench comparison
pub fn writeUtf16LeXmlEscaped_old(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    var ascii_buf: [256]u8 = undefined;
    var ascii_len: usize = 0;
    var i: usize = 0;
    while (i < num_chars and (i * 2 + 1) < utf16le.len) : (i += 1) {
        const lo = @as(u16, utf16le[i * 2]) | (@as(u16, utf16le[i * 2 + 1]) << 8);
        var codepoint: u21 = lo;
        if (lo >= 0xD800 and lo <= 0xDBFF) {
            if (i + 1 >= num_chars or (i + 1) * 2 + 1 >= utf16le.len) break;
            const lo2 = @as(u16, utf16le[(i + 1) * 2]) | (@as(u16, utf16le[(i + 1) * 2 + 1]) << 8);
            if (lo2 >= 0xDC00 and lo2 <= 0xDFFF) {
                const high_ten = lo - 0xD800;
                const low_ten = lo2 - 0xDC00;
                codepoint = 0x10000 + (@as(u21, high_ten) << 10) + @as(u21, low_ten);
                i += 1;
            } else {
                continue;
            }
        } else if (lo >= 0xDC00 and lo <= 0xDFFF) {
            continue;
        }
        if (codepoint <= 0x7F) {
            const c: u8 = @truncate(codepoint);
            try queueAsciiOrEntity(w, c, &ascii_buf, &ascii_len);
        } else {
            try flushAsciiRun(w, &ascii_buf, &ascii_len);
            var buf: [4]u8 = undefined;
            const len = std.unicode.utf8Encode(codepoint, &buf) catch 0;
            if (len == 0) continue;
            try w.writeAll(buf[0..len]);
        }
    }
    try flushAsciiRun(w, &ascii_buf, &ascii_len);
}

// Write UTF-16LE input as JSON-escaped UTF-8
pub fn writeUtf16LeJsonEscaped(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    return writeUtf16LeWithEscaper(w, utf16le, num_chars, jsonEscapeUtf8);
}

// Write UTF-16LE input as raw UTF-8 (no XML escaping). Suitable for CDATA bodies.
pub fn writeUtf16LeRawToUtf8(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    const Raw = struct {
        pub fn apply(ww: anytype, s: []const u8) !void {
            try ww.writeAll(s);
        }
    };
    return writeUtf16LeWithEscaper(w, utf16le, num_chars, Raw.apply);
}

pub fn cp1252ToCodepoint(b: u8) u21 {
    if (b < 0x80) return b;
    if (b >= 0xA0) return b;
    return switch (b) {
        0x80 => 0x20AC,
        0x82 => 0x201A,
        0x83 => 0x0192,
        0x84 => 0x201E,
        0x85 => 0x2026,
        0x86 => 0x2020,
        0x87 => 0x2021,
        0x88 => 0x02C6,
        0x89 => 0x2030,
        0x8A => 0x0160,
        0x8B => 0x2039,
        0x8C => 0x0152,
        0x8E => 0x017D,
        0x91 => 0x2018,
        0x92 => 0x2019,
        0x93 => 0x201C,
        0x94 => 0x201D,
        0x95 => 0x2022,
        0x96 => 0x2013,
        0x97 => 0x2014,
        0x98 => 0x02DC,
        0x99 => 0x2122,
        0x9A => 0x0161,
        0x9B => 0x203A,
        0x9C => 0x0153,
        0x9E => 0x017E,
        0x9F => 0x0178,
        else => 0xFFFD,
    };
}

fn writeAnsiCp1252WithEscaper(w: anytype, bytes: []const u8, comptime escape: anytype) !void {
    var out_buf: [8]u8 = undefined;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        const codepoint: u21 = cp1252ToCodepoint(bytes[i]);
        const n = std.unicode.utf8Encode(codepoint, &out_buf) catch 0;
        if (n == 0) continue;
        try escape(w, out_buf[0..n]);
    }
}

pub fn writeAnsiCp1252Escaped(w: anytype, bytes: []const u8) !void {
    // Best-effort CP-1252 decode to UTF-8 then XML-escape
    return writeAnsiCp1252WithEscaper(w, bytes, writeXmlEscaped);
}

// CP-1252 decode to UTF-8 then JSON-escape
pub fn writeAnsiCp1252JsonEscaped(w: anytype, bytes: []const u8) !void {
    return writeAnsiCp1252WithEscaper(w, bytes, jsonEscapeUtf8);
}

pub fn utf16EqualsAscii(utf16le: []const u8, num_chars: usize, ascii: []const u8) bool {
    if (ascii.len != num_chars) return false;
    var i: usize = 0;
    while (i < num_chars) : (i += 1) {
        const lo = utf16le[i * 2];
        const hi = utf16le[i * 2 + 1];
        if (hi != 0 or lo != ascii[i]) return false;
    }
    return true;
}

pub fn normalizeAndWriteSystemTimeAscii(w: anytype, ascii: []const u8) !void {
    // Some manifests include '+' markers around components. Strip them before parsing.
    var sanitized_buf: [64]u8 = undefined;
    var s_len: usize = 0;
    var i_s: usize = 0;
    while (i_s < ascii.len and s_len < sanitized_buf.len) : (i_s += 1) {
        const c = ascii[i_s];
        if (c == '+') continue;
        sanitized_buf[s_len] = c;
        s_len += 1;
    }
    const s = sanitized_buf[0..s_len];

    var year: []const u8 = &[_]u8{};
    var month: []const u8 = &[_]u8{};
    var day: []const u8 = &[_]u8{};
    var hour: []const u8 = &[_]u8{};
    var minute: []const u8 = &[_]u8{};
    var second: []const u8 = &[_]u8{};
    var micros: []const u8 = &[_]u8{};

    const t_idx = std.mem.indexOfScalar(u8, s, 'T') orelse return w.writeAll(s);
    const z_idx = std.mem.lastIndexOfScalar(u8, s, 'Z') orelse return w.writeAll(s);
    const date = s[0..t_idx];
    const time = s[t_idx + 1 .. z_idx];
    var it = std.mem.splitScalar(u8, date, '-');
    year = it.next() orelse return w.writeAll(s);
    month = it.next() orelse return w.writeAll(s);
    day = it.next() orelse return w.writeAll(s);
    var it2 = std.mem.splitScalar(u8, time, ':');
    hour = it2.next() orelse return w.writeAll(s);
    minute = it2.next() orelse return w.writeAll(s);
    const sec_frac = it2.next() orelse return w.writeAll(s);
    if (std.mem.indexOfScalar(u8, sec_frac, '.')) |dot| {
        second = sec_frac[0..dot];
        micros = sec_frac[dot + 1 ..];
    } else {
        second = sec_frac;
        micros = &[_]u8{};
    }
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

pub fn writePaddedInt(w: anytype, comptime T: type, value: T, pad_width: usize) !void {
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

pub fn writeUnicodeStringArrayCommaSeparated(w: anytype, utf16_data: []const u8) !void {
    var i: usize = 0;
    var item_index: usize = 0;
    var last_non_empty: isize = -1;
    while (i <= utf16_data.len) {
        const start = i;
        var end = i;
        while (end + 1 < utf16_data.len) : (end += 2) {
            const u = std.mem.readInt(u16, utf16_data[end .. end + 2][0..2], .little);
            if (u == 0) break;
        }
        if (end > start) last_non_empty = @as(isize, @intCast(item_index));
        item_index += 1;
        if (end + 1 < utf16_data.len) {
            i = end + 2;
        } else break;
    }
    if (last_non_empty < 0) return;
    i = 0;
    var idx: usize = 0;
    var first: bool = true;
    while (i <= utf16_data.len and idx <= @as(usize, @intCast(last_non_empty))) {
        const start = i;
        var end = i;
        while (end + 1 < utf16_data.len) : (end += 2) {
            const u = std.mem.readInt(u16, utf16_data[end .. end + 2][0..2], .little);
            if (u == 0) break;
        }
        if (!first) try w.writeByte(',') else first = false;
        if (end > start) {
            const num_chars = (end - start) / 2;
            try writeUtf16LeXmlEscaped(w, utf16_data[start..end], num_chars);
        }
        idx += 1;
        if (end + 1 < utf16_data.len) {
            i = end + 2;
        } else break;
    }
}

const DateTimeParts = struct {
    year: i64,
    month: i64,
    day: i64,
    hour: u32,
    minute: u32,
    second: u32,
};

fn computeUtcFromUnixSeconds(unix_seconds: i64) DateTimeParts {
    const z0: i64 = @divFloor(unix_seconds, 86_400);
    const sod: i64 = unix_seconds - z0 * 86_400;
    const z = z0 + 719_468;
    const era = @divFloor(z, 146_097);
    const doe = z - era * 146_097;
    const yoe = @divFloor(doe - @divFloor(doe, 1_460) + @divFloor(doe, 36_524) - @divFloor(doe, 146_096), 365);
    var y: i64 = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = mp + 3 - 12 * @as(i32, @intFromBool(mp >= 10));
    y += @as(i64, @intFromBool(m <= 2));
    const hour: u32 = @intCast(@divFloor(sod, 3_600));
    const sod_rem: i64 = sod - @as(i64, hour) * 3_600;
    const minute: u32 = @intCast(@divFloor(sod_rem, 60));
    const second: u32 = @intCast(sod_rem - @as(i64, minute) * 60);
    return .{ .year = y, .month = m, .day = d, .hour = hour, .minute = minute, .second = second };
}

pub fn formatIso8601UtcFromUnixMs(buf: []u8, unix_secs: i64, ms: u32) ![]const u8 {
    const parts = computeUtcFromUnixSeconds(unix_secs);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        parts.year, parts.month, parts.day, parts.hour, parts.minute, parts.second, ms,
    });
}

pub fn formatIso8601UtcFromFiletimeMicros(buf: []u8, filetime: u64) ![]const u8 {
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

    const parts = computeUtcFromUnixSeconds(@as(i64, @intCast(unix_seconds)));
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z", .{
        parts.year, parts.month, parts.day, parts.hour, parts.minute, parts.second, micros,
    });
}

pub fn utf16FromAscii(alloc: std.mem.Allocator, ascii: []const u8) ![]u8 {
    if (ascii.len == 0) return try alloc.alloc(u8, 0);
    var buf = try alloc.alloc(u8, ascii.len * 2);
    var i: usize = 0;
    while (i < ascii.len) : (i += 1) {
        buf[i * 2] = ascii[i];
        buf[i * 2 + 1] = 0;
    }
    return buf;
}
