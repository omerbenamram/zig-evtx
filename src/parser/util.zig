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
        return writeUtf16LeXmlEscaped_simd_utf16(w, utf16le, num_chars);
    }
    return writeUtf16LeXmlEscaped_scalar(w, utf16le, num_chars);
}

pub fn writeUtf16LeXmlEscaped_scalar(w: anytype, utf16le: []const u8, num_chars: usize) !void {
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

// (removed experimental SIMD variants and legacy baseline to keep only wrapper vs scalar)

// SIMD classification per block without an ASCII-only fast path.
// Processes all 8 lanes with scalar emission guided by vector masks.
const EscapeMode = enum { xml, json };

fn writeUtf16LeEscaped_simd_utf16(
    w: anytype,
    utf16le: []const u8,
    num_chars: usize,
    comptime mode: EscapeMode,
) !void {
    var out_buf: [2048]u8 = undefined;
    var out_len: usize = 0;

    const max_chars: usize = @min(num_chars, utf16le.len / 2);
    if (max_chars == 0) return;

    var i: usize = 0;
    var p: usize = 0; // byte index
    while (i + 8 <= max_chars) {
        var blk: [16]u8 = undefined;
        @memcpy(blk[0..], utf16le[p .. p + 16]);
        const v: @Vector(8, u16) = @bitCast(blk);

        const is_ascii: @Vector(8, bool) = v <= @as(@Vector(8, u16), @splat(0x7F));
        const esc_mask: @Vector(8, bool) = switch (mode) {
            .xml => blk_xml: {
                const m_amp: @Vector(8, bool) = v == @as(@Vector(8, u16), @splat(38));
                const m_lt: @Vector(8, bool) = v == @as(@Vector(8, u16), @splat(60));
                const m_gt: @Vector(8, bool) = v == @as(@Vector(8, u16), @splat(62));
                const m_quot: @Vector(8, bool) = v == @as(@Vector(8, u16), @splat(34));
                const m_apos: @Vector(8, bool) = v == @as(@Vector(8, u16), @splat(39));
                const esc_any_u1: @Vector(8, u1) =
                    @as(@Vector(8, u1), @bitCast(m_amp)) |
                    @as(@Vector(8, u1), @bitCast(m_lt)) |
                    @as(@Vector(8, u1), @bitCast(m_gt)) |
                    @as(@Vector(8, u1), @bitCast(m_quot)) |
                    @as(@Vector(8, u1), @bitCast(m_apos));
                break :blk_xml @as(@Vector(8, bool), @bitCast(@as(@Vector(8, u1), @bitCast(is_ascii)) & esc_any_u1));
            },
            .json => blk_json: {
                // JSON: escape '"', '\\', and all ASCII < 0x20
                const m_quote: @Vector(8, bool) = v == @as(@Vector(8, u16), @splat(34));
                const m_bslash: @Vector(8, bool) = v == @as(@Vector(8, u16), @splat(92));
                const le_001f: @Vector(8, bool) = v <= @as(@Vector(8, u16), @splat(0x001F));
                const esc_any_u1: @Vector(8, u1) =
                    @as(@Vector(8, u1), @bitCast(m_quote)) |
                    @as(@Vector(8, u1), @bitCast(m_bslash)) |
                    @as(@Vector(8, u1), @bitCast(le_001f));
                break :blk_json @as(@Vector(8, bool), @bitCast(@as(@Vector(8, u1), @bitCast(is_ascii)) & esc_any_u1));
            },
        };

        const ge_d800: @Vector(8, bool) = v >= @as(@Vector(8, u16), @splat(0xD800));
        const le_dbff: @Vector(8, bool) = v <= @as(@Vector(8, u16), @splat(0xDBFF));
        const ge_dc00: @Vector(8, bool) = v >= @as(@Vector(8, u16), @splat(0xDC00));
        const le_dfff: @Vector(8, bool) = v <= @as(@Vector(8, u16), @splat(0xDFFF));
        const is_hi_sur: @Vector(8, bool) = @as(@Vector(8, bool), @bitCast(@as(@Vector(8, u1), @bitCast(ge_d800)) & @as(@Vector(8, u1), @bitCast(le_dbff))));
        const is_lo_sur: @Vector(8, bool) = @as(@Vector(8, bool), @bitCast(@as(@Vector(8, u1), @bitCast(ge_dc00)) & @as(@Vector(8, u1), @bitCast(le_dfff))));
        const not_sur_u1: @Vector(8, u1) = ~@as(@Vector(8, u1), @bitCast(is_hi_sur)) & ~@as(@Vector(8, u1), @bitCast(is_lo_sur));
        const not_sur: @Vector(8, bool) = @as(@Vector(8, bool), @bitCast(not_sur_u1));

        const gt_7f: @Vector(8, bool) = v > @as(@Vector(8, u16), @splat(0x7F));
        const le_07ff: @Vector(8, bool) = v <= @as(@Vector(8, u16), @splat(0x07FF));
        const is_two: @Vector(8, bool) = @as(@Vector(8, bool), @bitCast(@as(@Vector(8, u1), @bitCast(not_sur)) &
            @as(@Vector(8, u1), @bitCast(gt_7f)) &
            @as(@Vector(8, u1), @bitCast(le_07ff))));
        const is_three: @Vector(8, bool) = @as(@Vector(8, bool), @bitCast(@as(@Vector(8, u1), @bitCast(not_sur)) &
            ~@as(@Vector(8, u1), @bitCast(is_ascii)) &
            ~@as(@Vector(8, u1), @bitCast(is_two))));

        var k: usize = 0;
        var extra_bytes: usize = 0;
        var extra_chars: usize = 0;
        while (k < 8) : (k += 1) {
            const b0: u8 = blk[k * 2];
            const b1: u8 = blk[k * 2 + 1];
            if (is_ascii[k]) {
                const c: u8 = b0;
                if (esc_mask[k]) {
                    if (comptime mode == .xml) {
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
                        // JSON escaping for ASCII
                        if (c == '"' or c == '\\') {
                            if (out_len + 2 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                            out_buf[out_len] = '\\';
                            out_buf[out_len + 1] = c;
                            out_len += 2;
                        } else {
                            // c < 0x20
                            const pair: u8 = switch (c) {
                                0x08 => 'b',
                                0x0c => 'f',
                                '\n' => 'n',
                                '\r' => 'r',
                                '\t' => 't',
                                else => 0,
                            };
                            if (pair != 0) {
                                if (out_len + 2 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                                out_buf[out_len] = '\\';
                                out_buf[out_len + 1] = @as(u8, pair);
                                out_len += 2;
                            } else {
                                // \u00XX
                                if (out_len + 6 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                                const HEX = "0123456789ABCDEF";
                                const hi_n: usize = @as(usize, @intCast((c >> 4) & 0xF));
                                const lo_n: usize = @as(usize, @intCast(c & 0xF));
                                out_buf[out_len] = '\\';
                                out_buf[out_len + 1] = 'u';
                                out_buf[out_len + 2] = '0';
                                out_buf[out_len + 3] = '0';
                                out_buf[out_len + 4] = HEX[hi_n];
                                out_buf[out_len + 5] = HEX[lo_n];
                                out_len += 6;
                            }
                        }
                    }
                } else {
                    if (out_len == out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                    out_buf[out_len] = c;
                    out_len += 1;
                }
                continue;
            }
            const u: u16 = @as(u16, b0) | (@as(u16, b1) << 8);
            if (is_two[k]) {
                if (out_len + 2 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                out_buf[out_len] = 0xC0 | (@as(u8, @truncate(u >> 6)));
                out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate(u & 0x3F)));
                out_len += 2;
                continue;
            }
            if (is_three[k]) {
                if (out_len + 3 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                out_buf[out_len] = 0xE0 | (@as(u8, @truncate(u >> 12)));
                out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate((u >> 6) & 0x3F)));
                out_buf[out_len + 2] = 0x80 | (@as(u8, @truncate(u & 0x3F)));
                out_len += 3;
                continue;
            }
            if (is_hi_sur[k]) {
                if (k + 1 < 8) {
                    const sb0: u8 = blk[(k + 1) * 2];
                    const sb1: u8 = blk[(k + 1) * 2 + 1];
                    const lo_sur: u16 = @as(u16, sb0) | (@as(u16, sb1) << 8);
                    if (lo_sur >= 0xDC00 and lo_sur <= 0xDFFF) {
                        const high_ten: u21 = @as(u21, u - 0xD800);
                        const low_ten: u21 = @as(u21, lo_sur - 0xDC00);
                        const cp: u21 = 0x10000 + (high_ten << 10) + low_ten;
                        if (out_len + 4 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                        out_buf[out_len] = 0xF0 | (@as(u8, @truncate(cp >> 18)));
                        out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate((cp >> 12) & 0x3F)));
                        out_buf[out_len + 2] = 0x80 | (@as(u8, @truncate((cp >> 6) & 0x3F)));
                        out_buf[out_len + 3] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
                        out_len += 4;
                        k += 1;
                        continue;
                    } else {
                        // invalid pair; skip
                        continue;
                    }
                } else {
                    if (i + 9 > max_chars) break; // incomplete at end
                    const sb0 = utf16le[p + 16 + extra_bytes];
                    const sb1 = utf16le[p + 16 + extra_bytes + 1];
                    const lo_sur: u16 = @as(u16, sb0) | (@as(u16, sb1) << 8);
                    if (lo_sur < 0xDC00 or lo_sur > 0xDFFF) {
                        // invalid pair; skip
                        continue;
                    }
                    const high_ten: u21 = @as(u21, u - 0xD800);
                    const low_ten: u21 = @as(u21, lo_sur - 0xDC00);
                    const cp: u21 = 0x10000 + (high_ten << 10) + low_ten;
                    if (out_len + 4 > out_buf.len) try flushOut2048(w, &out_buf, &out_len);
                    out_buf[out_len] = 0xF0 | (@as(u8, @truncate(cp >> 18)));
                    out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate((cp >> 12) & 0x3F)));
                    out_buf[out_len + 2] = 0x80 | (@as(u8, @truncate((cp >> 6) & 0x3F)));
                    out_buf[out_len + 3] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
                    out_len += 4;
                    extra_bytes += 2;
                    extra_chars += 1;
                    continue;
                }
            }
            // lone low surrogate: skip
        }
        p += 16 + extra_bytes;
        i += 8 + extra_chars;
    }
    // Ensure vector-emitted bytes are written before handling the tail using the scalar path.
    // Writing the remainder first would reorder output (tail at the front), as seen in tests.
    try flushOut2048(w, &out_buf, &out_len);
    if (i < max_chars) {
        if (comptime mode == .xml) {
            try writeUtf16LeXmlEscaped_scalar(w, utf16le[p..], max_chars - i);
        } else {
            try writeUtf16LeWithEscaper(w, utf16le[p..], max_chars - i, jsonEscapeUtf8);
        }
    }
}

pub fn writeUtf16LeXmlEscaped_simd_utf16(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    return writeUtf16LeEscaped_simd_utf16(w, utf16le, num_chars, .xml);
}

pub fn writeUtf16LeJsonEscaped_simd_utf16(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    return writeUtf16LeEscaped_simd_utf16(w, utf16le, num_chars, .json);
}

// Baseline implementation kept for microbench comparison

// Write UTF-16LE input as JSON-escaped UTF-8
pub fn writeUtf16LeJsonEscaped(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    const builtin = @import("builtin");
    if (builtin.cpu.arch == .aarch64 or builtin.cpu.arch == .x86_64) {
        return writeUtf16LeJsonEscaped_simd_utf16(w, utf16le, num_chars);
    }
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

const CaseId = enum {
    ascii,
    euro,
    e_acute,
    two_byte_max,
    grinning,
    hi_only,
    lo_only,
    ctrl_1f,
    newline,
    long_ascii,
};

fn buildUtf16Case(alloc: std.mem.Allocator, id: CaseId) ![]u8 {
    switch (id) {
        .ascii => return utf16FromAscii(alloc, "Hello &<>\"' World"),
        .long_ascii => return utf16FromAscii(alloc, "aaaaaaa&bbbbbbb&ccccccc<dddddd>eeeeee\"fffffff'gggggg"),
        .euro => return alloc.dupe(u8, &[_]u8{ 0xAC, 0x20 }),
        .e_acute => return alloc.dupe(u8, &[_]u8{ 0xE9, 0x00 }),
        .two_byte_max => return alloc.dupe(u8, &[_]u8{ 0xFF, 0x07 }),
        .grinning => return alloc.dupe(u8, &[_]u8{ 0x3D, 0xD8, 0x00, 0xDE }),
        .hi_only => return alloc.dupe(u8, &[_]u8{ 0x00, 0xD8 }),
        .lo_only => return alloc.dupe(u8, &[_]u8{ 0x00, 0xDC }),
        .ctrl_1f => return alloc.dupe(u8, &[_]u8{ 0x1F, 0x00 }),
        .newline => return alloc.dupe(u8, &[_]u8{ '\n', 0x00 }),
    }
}

const Mode = enum { xml, json };

fn modeName(mode: Mode) []const u8 {
    return switch (mode) {
        .xml => "XML",
        .json => "JSON",
    };
}

fn runMatrixCase(mode: Mode, id: CaseId) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const bytes = try buildUtf16Case(alloc, id);
    defer alloc.free(bytes);
    const num_chars = bytes.len / 2;

    var out_a = std.ArrayList(u8).init(alloc);
    defer out_a.deinit();
    var out_b = std.ArrayList(u8).init(alloc);
    defer out_b.deinit();

    switch (mode) {
        .xml => {
            try writeUtf16LeXmlEscaped_simd_utf16(out_a.writer(), bytes, num_chars);
            try writeUtf16LeXmlEscaped_scalar(out_b.writer(), bytes, num_chars);
        },
        .json => {
            try writeUtf16LeJsonEscaped_simd_utf16(out_a.writer(), bytes, num_chars);
            try writeUtf16LeWithEscaper(out_b.writer(), bytes, num_chars, jsonEscapeUtf8);
        },
    }
    try std.testing.expectEqualStrings(out_b.items, out_a.items);
    const case_name = switch (id) {
        .ascii => "ascii",
        .euro => "euro",
        .e_acute => "e_acute",
        .two_byte_max => "two_byte_max",
        .grinning => "grinning",
        .hi_only => "hi_only",
        .lo_only => "lo_only",
        .ctrl_1f => "ctrl_1f",
        .newline => "newline",
        .long_ascii => "long_ascii",
    };
    std.debug.print("PASS {s} - {s}\n", .{ modeName(mode), case_name });
}

// XML cases
test "XML - ascii" {
    try runMatrixCase(.xml, .ascii);
}
test "XML - euro" {
    try runMatrixCase(.xml, .euro);
}
test "XML - e_acute" {
    try runMatrixCase(.xml, .e_acute);
}
test "XML - two_byte_max" {
    try runMatrixCase(.xml, .two_byte_max);
}
test "XML - grinning" {
    try runMatrixCase(.xml, .grinning);
}
test "XML - hi_only" {
    try runMatrixCase(.xml, .hi_only);
}
test "XML - lo_only" {
    try runMatrixCase(.xml, .lo_only);
}
test "XML - ctrl_1f" {
    try runMatrixCase(.xml, .ctrl_1f);
}
test "XML - newline" {
    try runMatrixCase(.xml, .newline);
}
test "XML - long_ascii" {
    try runMatrixCase(.xml, .long_ascii);
}

// JSON cases
test "JSON - ascii" {
    try runMatrixCase(.json, .ascii);
}
test "JSON - euro" {
    try runMatrixCase(.json, .euro);
}
test "JSON - e_acute" {
    try runMatrixCase(.json, .e_acute);
}
test "JSON - two_byte_max" {
    try runMatrixCase(.json, .two_byte_max);
}
test "JSON - grinning" {
    try runMatrixCase(.json, .grinning);
}
test "JSON - hi_only" {
    try runMatrixCase(.json, .hi_only);
}
test "JSON - lo_only" {
    try runMatrixCase(.json, .lo_only);
}
test "JSON - ctrl_1f" {
    try runMatrixCase(.json, .ctrl_1f);
}
test "JSON - newline" {
    try runMatrixCase(.json, .newline);
}
test "JSON - long_ascii" {
    try runMatrixCase(.json, .long_ascii);
}
