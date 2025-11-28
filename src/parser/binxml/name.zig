const std = @import("std");
const util = @import("../util.zig");
const utf16EqualsAscii = util.utf16EqualsAscii;
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const logger = @import("../../logger.zig");
const log = logger.scoped("binxml.name");

pub fn attrNameIsSystemTime(name: IR.Name) bool {
    return utf16EqualsAscii(name.bytes, name.num_chars, "SystemTime");
}

pub fn logNameTrace(name: IR.Name, label: []const u8) !void {
    if (!log.enabled(.trace)) return;
    var tmp: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&tmp);
    try w.writeAll("[");
    try w.writeAll(label);
    try w.writeAll("] ");
    try util.writeUtf16LeXmlEscaped(&w, name.bytes, name.num_chars);
    log.trace("{s}", .{tmp[0..w.end]});
}
