//! String encoding utilities for BinXML output rendering.
//!
//! Provides UTF-16LE to UTF-8 conversion with XML/JSON escaping,
//! CP-1252 decoding, and timestamp formatting.

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

pub fn utf16EqualsAscii(utf16le: []const u8, num_chars: usize, ascii: []const u8) bool {
    if (ascii.len != num_chars) return false;
    for (ascii, 0..) |c, i| {
        const lo = utf16le[i * 2];
        const hi = utf16le[i * 2 + 1];
        if (hi != 0 or lo != c) return false;
    }
    return true;
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
    // Cast signed date components to unsigned to ensure proper zero-padding without sign prefixes
    const year: u32 = @intCast(parts.year);
    const month: u32 = @intCast(parts.month);
    const day: u32 = @intCast(parts.day);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z", .{
        year, month, day, parts.hour, parts.minute, parts.second, micros,
    });
}

pub fn utf16FromAscii(alloc: std.mem.Allocator, ascii: []const u8) ![]u8 {
    if (ascii.len == 0) return try alloc.alloc(u8, 0);
    const buf = try alloc.alloc(u8, ascii.len * 2);
    for (ascii, 0..) |c, i| {
        buf[i * 2] = c;
        buf[i * 2 + 1] = 0;
    }
    return buf;
}

// ============================================================================
// Concrete std.Io.Writer Variants (Zig 0.15+)
// ============================================================================
// These functions use the non-generic std.Io.Writer interface for better
// debug-mode performance and reduced code bloat.

/// Writer error type for concrete Io functions.
pub const WriterError = std.Io.Writer.Error;

/// SIMD threshold: use SIMD for inputs >= 16 UTF-16 code units (32 bytes).
const SIMD_THRESHOLD: usize = 16;

/// Write UTF-16LE input as XML-escaped UTF-8 to concrete std.Io.Writer.
/// Uses SIMD acceleration for larger inputs.
pub fn writeUtf16LeXmlEscaped(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    const max_chars = @min(num_chars, utf16le.len / 2);
    if (max_chars >= SIMD_THRESHOLD) {
        return writeUtf16LeXmlEscaped_simd_utf16(w, utf16le, num_chars);
    }
    return writeUtf16LeXmlEscaped_scalar(w, utf16le, num_chars);
}

/// SIMD-accelerated UTF-16LE to XML-escaped UTF-8 conversion.
/// Processes 8 UTF-16 code units per iteration using vector operations.
/// Public for benchmarking; prefer writeUtf16LeXmlEscaped for automatic dispatch.
pub fn writeUtf16LeXmlEscaped_simd_utf16(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    var out_buf: [2048]u8 = undefined;
    var out_len: usize = 0;

    const max_chars: usize = @min(num_chars, utf16le.len / 2);
    if (max_chars == 0) return;

    var i: usize = 0;
    var p: usize = 0;

    // Process 8 UTF-16 code units at a time
    while (i + 8 <= max_chars) {
        var blk: [16]u8 = undefined;
        @memcpy(blk[0..], utf16le[p .. p + 16]);
        const v: @Vector(8, u16) = @bitCast(blk);

        // Classify each lane
        const is_ascii: @Vector(8, bool) = v <= @as(@Vector(8, u16), @splat(0x7F));

        // XML escape characters: & < > " '
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
        const esc_mask: @Vector(8, bool) = @as(@Vector(8, bool), @bitCast(@as(@Vector(8, u1), @bitCast(is_ascii)) & esc_any_u1));

        // Surrogate detection
        const ge_d800: @Vector(8, bool) = v >= @as(@Vector(8, u16), @splat(0xD800));
        const le_dbff: @Vector(8, bool) = v <= @as(@Vector(8, u16), @splat(0xDBFF));
        const ge_dc00: @Vector(8, bool) = v >= @as(@Vector(8, u16), @splat(0xDC00));
        const le_dfff: @Vector(8, bool) = v <= @as(@Vector(8, u16), @splat(0xDFFF));
        const is_hi_sur: @Vector(8, bool) = @as(@Vector(8, bool), @bitCast(@as(@Vector(8, u1), @bitCast(ge_d800)) & @as(@Vector(8, u1), @bitCast(le_dbff))));
        const is_lo_sur: @Vector(8, bool) = @as(@Vector(8, bool), @bitCast(@as(@Vector(8, u1), @bitCast(ge_dc00)) & @as(@Vector(8, u1), @bitCast(le_dfff))));
        const not_sur_u1: @Vector(8, u1) = ~@as(@Vector(8, u1), @bitCast(is_hi_sur)) & ~@as(@Vector(8, u1), @bitCast(is_lo_sur));
        const not_sur: @Vector(8, bool) = @as(@Vector(8, bool), @bitCast(not_sur_u1));

        // UTF-8 length classification
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
                    const e: []const u8 = switch (c) {
                        '&' => "&amp;",
                        '<' => "&lt;",
                        '>' => "&gt;",
                        '"' => "&quot;",
                        '\'' => "&apos;",
                        else => unreachable,
                    };
                    if (out_len + e.len > out_buf.len) {
                        try w.writeAll(out_buf[0..out_len]);
                        out_len = 0;
                    }
                    @memcpy(out_buf[out_len..][0..e.len], e);
                    out_len += e.len;
                } else {
                    if (out_len == out_buf.len) {
                        try w.writeAll(out_buf[0..out_len]);
                        out_len = 0;
                    }
                    out_buf[out_len] = c;
                    out_len += 1;
                }
                continue;
            }
            const u: u16 = @as(u16, b0) | (@as(u16, b1) << 8);
            if (is_two[k]) {
                if (out_len + 2 > out_buf.len) {
                    try w.writeAll(out_buf[0..out_len]);
                    out_len = 0;
                }
                out_buf[out_len] = 0xC0 | (@as(u8, @truncate(u >> 6)));
                out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate(u & 0x3F)));
                out_len += 2;
                continue;
            }
            if (is_three[k]) {
                if (out_len + 3 > out_buf.len) {
                    try w.writeAll(out_buf[0..out_len]);
                    out_len = 0;
                }
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
                        if (out_len + 4 > out_buf.len) {
                            try w.writeAll(out_buf[0..out_len]);
                            out_len = 0;
                        }
                        out_buf[out_len] = 0xF0 | (@as(u8, @truncate(cp >> 18)));
                        out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate((cp >> 12) & 0x3F)));
                        out_buf[out_len + 2] = 0x80 | (@as(u8, @truncate((cp >> 6) & 0x3F)));
                        out_buf[out_len + 3] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
                        out_len += 4;
                        k += 1;
                        continue;
                    }
                } else {
                    if (i + 9 > max_chars) break;
                    const sb0 = utf16le[p + 16 + extra_bytes];
                    const sb1 = utf16le[p + 16 + extra_bytes + 1];
                    const lo_sur: u16 = @as(u16, sb0) | (@as(u16, sb1) << 8);
                    if (lo_sur >= 0xDC00 and lo_sur <= 0xDFFF) {
                        const high_ten: u21 = @as(u21, u - 0xD800);
                        const low_ten: u21 = @as(u21, lo_sur - 0xDC00);
                        const cp: u21 = 0x10000 + (high_ten << 10) + low_ten;
                        if (out_len + 4 > out_buf.len) {
                            try w.writeAll(out_buf[0..out_len]);
                            out_len = 0;
                        }
                        out_buf[out_len] = 0xF0 | (@as(u8, @truncate(cp >> 18)));
                        out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate((cp >> 12) & 0x3F)));
                        out_buf[out_len + 2] = 0x80 | (@as(u8, @truncate((cp >> 6) & 0x3F)));
                        out_buf[out_len + 3] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
                        out_len += 4;
                        extra_bytes += 2;
                        extra_chars += 1;
                    }
                }
            }
            // lone low surrogate: skip
        }
        p += 16 + extra_bytes;
        i += 8 + extra_chars;
    }

    // Flush SIMD output before scalar tail
    if (out_len > 0) {
        try w.writeAll(out_buf[0..out_len]);
    }

    // Handle remaining characters with scalar path
    if (i < max_chars) {
        return writeUtf16LeXmlEscaped_scalar(w, utf16le[p..], max_chars - i);
    }
}

/// Scalar UTF-16LE to XML-escaped UTF-8 conversion.
/// Scalar UTF-16LE to XML-escaped UTF-8 conversion.
/// Public for benchmarking; prefer writeUtf16LeXmlEscaped for automatic dispatch.
pub fn writeUtf16LeXmlEscaped_scalar(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    // Use buffered approach for performance - aggregate into local buffer then write
    var out_buf: [2048]u8 = undefined;
    var out_len: usize = 0;

    const esc_table = comptime blk: {
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
    var p: usize = 0;
    while (i < max_chars) : (i += 1) {
        const b0: u8 = utf16le[p];
        const b1: u8 = utf16le[p + 1];
        p += 2;

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
                    if (out_len + e.len > out_buf.len) {
                        try w.writeAll(out_buf[0..out_len]);
                        out_len = 0;
                    }
                    @memcpy(out_buf[out_len..][0..e.len], e);
                    out_len += e.len;
                } else {
                    if (out_len == out_buf.len) {
                        try w.writeAll(out_buf[0..out_len]);
                        out_len = 0;
                    }
                    out_buf[out_len] = c;
                    out_len += 1;
                }
                continue;
            }
            if (out_len + 2 > out_buf.len) {
                try w.writeAll(out_buf[0..out_len]);
                out_len = 0;
            }
            out_buf[out_len] = 0xC0 | (c >> 6);
            out_buf[out_len + 1] = 0x80 | (c & 0x3F);
            out_len += 2;
            continue;
        }

        const u: u16 = @as(u16, b0) | (@as(u16, b1) << 8);
        if (u < 0xD800 or u > 0xDFFF) {
            const cp: u21 = u;
            if (cp <= 0x07FF) {
                if (out_len + 2 > out_buf.len) {
                    try w.writeAll(out_buf[0..out_len]);
                    out_len = 0;
                }
                out_buf[out_len] = 0xC0 | (@as(u8, @truncate(cp >> 6)));
                out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
                out_len += 2;
            } else {
                if (out_len + 3 > out_buf.len) {
                    try w.writeAll(out_buf[0..out_len]);
                    out_len = 0;
                }
                out_buf[out_len] = 0xE0 | (@as(u8, @truncate(cp >> 12)));
                out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate((cp >> 6) & 0x3F)));
                out_buf[out_len + 2] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
                out_len += 3;
            }
            continue;
        }

        if (u >= 0xD800 and u <= 0xDBFF) {
            if (i + 1 >= max_chars) break;
            const b20: u8 = utf16le[p];
            const b21: u8 = utf16le[p + 1];
            const lo_sur: u16 = @as(u16, b20) | (@as(u16, b21) << 8);
            if (lo_sur < 0xDC00 or lo_sur > 0xDFFF) continue;
            p += 2;
            i += 1;
            const high_ten: u21 = @as(u21, u - 0xD800);
            const low_ten: u21 = @as(u21, lo_sur - 0xDC00);
            const cp: u21 = 0x10000 + (high_ten << 10) + low_ten;
            if (out_len + 4 > out_buf.len) {
                try w.writeAll(out_buf[0..out_len]);
                out_len = 0;
            }
            out_buf[out_len] = 0xF0 | (@as(u8, @truncate(cp >> 18)));
            out_buf[out_len + 1] = 0x80 | (@as(u8, @truncate((cp >> 12) & 0x3F)));
            out_buf[out_len + 2] = 0x80 | (@as(u8, @truncate((cp >> 6) & 0x3F)));
            out_buf[out_len + 3] = 0x80 | (@as(u8, @truncate(cp & 0x3F)));
            out_len += 4;
            continue;
        }
    }
    if (out_len > 0) try w.writeAll(out_buf[0..out_len]);
}

/// Write UTF-16LE input as raw UTF-8 (no escaping) to concrete std.Io.Writer.
pub fn writeUtf16LeRawToUtf8(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    var out_buf: [512]u8 = undefined;
    var out_len: usize = 0;

    const max_chars: usize = @min(num_chars, utf16le.len / 2);
    if (max_chars == 0) return;

    var i: usize = 0;
    while (i < max_chars and (i * 2 + 1) < utf16le.len) : (i += 1) {
        const lo = @as(u16, utf16le[i * 2]) | (@as(u16, utf16le[i * 2 + 1]) << 8);
        var codepoint: u21 = lo;
        if (lo >= 0xD800 and lo <= 0xDBFF) {
            if (i + 1 >= max_chars or (i + 1) * 2 + 1 >= utf16le.len) break;
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
        if (out_len + len > out_buf.len) {
            try w.writeAll(out_buf[0..out_len]);
            out_len = 0;
        }
        @memcpy(out_buf[out_len..][0..len], buf[0..len]);
        out_len += len;
    }
    if (out_len > 0) try w.writeAll(out_buf[0..out_len]);
}

/// Write UTF-16LE input as JSON-escaped UTF-8 to concrete std.Io.Writer.
/// Write UTF-16LE input as JSON-escaped UTF-8 to concrete std.Io.Writer.
/// Alias for writeUtf16LeJsonEscaped_scalar (no SIMD version currently).
pub fn writeUtf16LeJsonEscaped(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    return writeUtf16LeJsonEscaped_scalar(w, utf16le, num_chars);
}

/// Scalar UTF-16LE to JSON-escaped UTF-8 conversion.
/// Public for benchmarking and testing.
pub fn writeUtf16LeJsonEscaped_scalar(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    var out_buf: [2048]u8 = undefined;
    var out_len: usize = 0;

    const max_chars: usize = @min(num_chars, utf16le.len / 2);
    if (max_chars == 0) return;

    var i: usize = 0;
    while (i < max_chars and (i * 2 + 1) < utf16le.len) : (i += 1) {
        const lo = @as(u16, utf16le[i * 2]) | (@as(u16, utf16le[i * 2 + 1]) << 8);
        var codepoint: u21 = lo;

        if (lo >= 0xD800 and lo <= 0xDBFF) {
            if (i + 1 >= max_chars or (i + 1) * 2 + 1 >= utf16le.len) break;
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

        // JSON escape each UTF-8 byte
        for (buf[0..len]) |c| {
            const esc: ?[]const u8 = switch (c) {
                '"' => "\\\"",
                '\\' => "\\\\",
                0x08 => "\\b",
                0x0c => "\\f",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                else => null,
            };
            if (esc) |e| {
                if (out_len + e.len > out_buf.len) {
                    try w.writeAll(out_buf[0..out_len]);
                    out_len = 0;
                }
                @memcpy(out_buf[out_len..][0..e.len], e);
                out_len += e.len;
            } else if (c < 0x20) {
                if (out_len + 6 > out_buf.len) {
                    try w.writeAll(out_buf[0..out_len]);
                    out_len = 0;
                }
                const HEX = "0123456789ABCDEF";
                out_buf[out_len] = '\\';
                out_buf[out_len + 1] = 'u';
                out_buf[out_len + 2] = '0';
                out_buf[out_len + 3] = '0';
                out_buf[out_len + 4] = HEX[@as(usize, c >> 4)];
                out_buf[out_len + 5] = HEX[@as(usize, c & 0xF)];
                out_len += 6;
            } else {
                if (out_len == out_buf.len) {
                    try w.writeAll(out_buf[0..out_len]);
                    out_len = 0;
                }
                out_buf[out_len] = c;
                out_len += 1;
            }
        }
    }
    if (out_len > 0) try w.writeAll(out_buf[0..out_len]);
}

/// Normalize and write SystemTime ASCII string to concrete std.Io.Writer.
pub fn normalizeAndWriteSystemTimeAscii(w: *std.Io.Writer, ascii: []const u8) WriterError!void {
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

/// Write ANSI CP-1252 bytes as XML-escaped UTF-8 to concrete std.Io.Writer.
pub fn writeAnsiCp1252Escaped(w: *std.Io.Writer, bytes: []const u8) WriterError!void {
    var out_buf: [8]u8 = undefined;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        const codepoint: u21 = cp1252ToCodepoint(bytes[i]);
        const n = std.unicode.utf8Encode(codepoint, &out_buf) catch 0;
        if (n == 0) continue;
        // XML escape inline
        for (out_buf[0..n]) |c| {
            if (xmlEntityFor(c)) |e| {
                try w.writeAll(e);
            } else {
                try w.writeByte(c);
            }
        }
    }
}
