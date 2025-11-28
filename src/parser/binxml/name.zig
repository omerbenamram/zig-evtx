const std = @import("std");
const util = @import("../util.zig");
const utf16EqualsAscii = util.utf16EqualsAscii;
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const BinXmlError = @import("../err.zig").BinXmlError;
const Reader = @import("../reader.zig").Reader;
const types = @import("types.zig");
const logger = @import("../../logger.zig");
const log = logger.scoped("binxml.name");

// Local name writers for tracing (avoid renderer dependency)
pub fn writeNameFromOffset(chunk: []const u8, name_offset: u32, w: anytype) !void {
    if (name_offset >= chunk.len) return BinXmlError.OutOfBounds;
    var reader = Reader.init(chunk);
    reader.pos = name_offset;

    const header = try reader.readStruct(types.NameHeader);
    const num_chars = header.num_chars;
    const byte_len = @as(usize, num_chars) * 2;

    if (reader.rem() < byte_len) return BinXmlError.OutOfBounds;
    const str_start = reader.pos;
    const raw_slice = chunk[str_start .. str_start + byte_len];

    var num = num_chars;
    if (byte_len >= 2) {
        const last = std.mem.readInt(u16, raw_slice[byte_len - 2 .. byte_len][0..2], .little);
        if (last == 0 and num > 0) num -= 1;
    }
    try util.writeUtf16LeXmlEscaped(w, raw_slice[0 .. num * 2], num);
}

pub fn writeNameFromUtf16(w: anytype, utf16le: []const u8, num_chars: usize) !void {
    try util.writeUtf16LeXmlEscaped(w, utf16le, num_chars);
}

pub fn attrNameIsSystemTime(name: IR.Name) bool {
    return utf16EqualsAscii(name.bytes, name.num_chars, "SystemTime");
}

pub fn logNameTrace(name: IR.Name, label: []const u8) !void {
    if (!log.enabled(.trace)) return;
    var tmp: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&tmp);
    const w = fbs.writer();
    try w.writeAll("[");
    try w.writeAll(label);
    try w.writeAll("] ");
    try writeNameFromUtf16(w, name.bytes, name.num_chars);
    log.trace("{s}", .{fbs.getWritten()});
}
