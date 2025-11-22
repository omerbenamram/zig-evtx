const std = @import("std");
const Reader = @import("../reader.zig").Reader;
const tokens = @import("tokens.zig");
const types = @import("types.zig");
const BinXmlError = @import("../err.zig").BinXmlError;

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

pub fn skipInlineTemplateDefinition(r: *Reader, def_data_off: u32) !void {
    // Inline template definition: definition data is embedded immediately after the header.
    // def_data_off then points to the current reader position.
    if (def_data_off == @as(u32, @intCast(r.pos))) {
        // TemplateDefinition data header:
        //   4 bytes : next_offset
        //   16 bytes: GUID
        //   4 bytes : data_size
        if (r.rem() < 24) return BinXmlError.UnexpectedEof;
        _ = try r.readU32le(); // next_offset
        _ = try r.readGuid(); // GUID (16 bytes)
        const data_size_inline = try r.readU32le();
        if (r.rem() < data_size_inline) return BinXmlError.UnexpectedEof;
        r.pos += @as(usize, data_size_inline);
    }
}

// utf16FromAscii moved to util.zig
