const std = @import("std");
const Reader = @import("../reader.zig").Reader;
const tokens = @import("tokens.zig");

pub fn skipFragmentHeaderIfPresent(r: *Reader) !void {
    if (r.rem() >= 4 and r.buf[r.pos] == tokens.TOK_FRAGMENT_HEADER) {
        _ = try r.readU8();
        _ = try r.readU8();
        _ = try r.readU8();
        _ = try r.readU8();
    }
}

pub fn skipInlineCachedTemplateDefs(r: *Reader) void {
    while (r.rem() >= 28) {
        const data_size_peek = std.mem.readInt(u32, r.buf[r.pos + 20 .. r.pos + 24][0..4], .little);
        const block_end = r.pos + 24 + @as(usize, data_size_peek);
        if (block_end > r.buf.len) break;
        const payload_first = r.buf[r.pos + 24];
        if (payload_first != tokens.TOK_FRAGMENT_HEADER) break;
        r.pos = block_end;
    }
}

// utf16FromAscii moved to util.zig
