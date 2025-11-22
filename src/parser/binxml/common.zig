const std = @import("std");
const Reader = @import("../reader.zig").Reader;
const tokens = @import("tokens.zig");
const types = @import("types.zig");

pub fn skipFragmentHeaderIfPresent(r: *Reader) !void {
    if (r.rem() >= 4 and r.buf[r.pos] == tokens.TOK_FRAGMENT_HEADER) {
        _ = try r.readStruct(types.FragmentHeader);
    }
}

pub fn skipInlineCachedTemplateDefs(r: *Reader) void {
    while (r.rem() >= @sizeOf(types.TemplateDefinitionHeader) + 1) {
        const save_pos = r.pos;
        if (r.readStruct(types.TemplateDefinitionHeader)) |hdr| {
            if (r.rem() < hdr.data_size) {
                r.pos = save_pos;
                break;
            }
            if (r.buf[r.pos] == tokens.TOK_FRAGMENT_HEADER) {
                r.pos += @as(usize, hdr.data_size);
                continue;
            }
        } else |_| {}
        r.pos = save_pos;
        break;
    }
}

// utf16FromAscii moved to util.zig
