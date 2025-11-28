const std = @import("std");
const util = @import("../util.zig");
const utf16EqualsAscii = util.utf16EqualsAscii;
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const logger = @import("../../logger.zig");
const log = logger.scoped("binxml.name");

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
