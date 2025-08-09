const std = @import("std");

pub fn writeXmlEscaped(w: anytype, s: []const u8) !void {
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

pub fn writeUtf16LeXmlEscaped(w: anytype, utf16le: []const u8, num_chars: usize) !void {
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
        try writeXmlEscaped(w, buf[0..len]);
    }
}

// Write UTF-16LE input as JSON-escaped UTF-8
pub fn writeUtf16LeJsonEscaped(w: anytype, utf16le: []const u8, num_chars: usize) !void {
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
        try jsonEscapeUtf8(w, buf[0..len]);
    }
}

// Write UTF-16LE input as raw UTF-8 (no XML escaping). Suitable for CDATA bodies.
pub fn writeUtf16LeRawToUtf8(w: anytype, utf16le: []const u8, num_chars: usize) !void {
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
        try w.writeAll(buf[0..len]);
    }
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

pub fn writeAnsiCp1252Escaped(w: anytype, bytes: []const u8) !void {
    // Best-effort CP-1252 decode to UTF-8 then XML-escape
    var out_buf: [8]u8 = undefined;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        const codepoint: u21 = cp1252ToCodepoint(bytes[i]);
        const n = std.unicode.utf8Encode(codepoint, &out_buf) catch 0;
        if (n == 0) continue;
        try writeXmlEscaped(w, out_buf[0..n]);
    }
}

// CP-1252 decode to UTF-8 then JSON-escape
pub fn writeAnsiCp1252JsonEscaped(w: anytype, bytes: []const u8) !void {
    var out_buf: [8]u8 = undefined;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        const codepoint: u21 = cp1252ToCodepoint(bytes[i]);
        const n = std.unicode.utf8Encode(codepoint, &out_buf) catch 0;
        if (n == 0) continue;
        try jsonEscapeUtf8(w, out_buf[0..n]);
    }
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
    var year: []const u8 = &[_]u8{};
    var month: []const u8 = &[_]u8{};
    var day: []const u8 = &[_]u8{};
    var hour: []const u8 = &[_]u8{};
    var minute: []const u8 = &[_]u8{};
    var second: []const u8 = &[_]u8{};
    var micros: []const u8 = &[_]u8{};

    const t_idx = std.mem.indexOfScalar(u8, ascii, 'T') orelse return w.writeAll(ascii);
    const z_idx = std.mem.lastIndexOfScalar(u8, ascii, 'Z') orelse return w.writeAll(ascii);
    const date = ascii[0..t_idx];
    const time = ascii[t_idx + 1 .. z_idx];
    var it = std.mem.splitScalar(u8, date, '-');
    year = it.next() orelse return w.writeAll(ascii);
    month = it.next() orelse return w.writeAll(ascii);
    day = it.next() orelse return w.writeAll(ascii);
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

pub fn formatIso8601UtcFromUnixMs(buf: []u8, unix_secs: i64, ms: u32) ![]const u8 {
    const z0: i64 = @divFloor(unix_secs, 86400);
    const sod: i64 = unix_secs - z0 * 86400;
    const z = z0 + 719468;
    const era = @divFloor(z, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    var y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
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
