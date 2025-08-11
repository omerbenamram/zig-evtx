const std = @import("std");

// Shared BinXML types and helpers. Keep renderer-free to avoid cycles.

pub const TemplateValue = struct {
    t: u8,
    data: []const u8,
};

pub fn valueTypeFixedSize(vtype: u8) ?usize {
    return switch (vtype) {
        0x03, // Int8
        0x04, // UInt8
        => 1,
        0x05, // Int16
        0x06, // UInt16
        => 2,
        0x07, // Int32
        0x08, // UInt32
        0x0d, // Bool (DWORD)
        0x14, // HexInt32
        => 4,
        0x09, // Int64
        0x0a, // UInt64
        0x0b, // Real32
        0x0c, // Real64
        0x11, // FILETIME
        0x15, // HexInt64
        => 8,
        0x0f, // GUID
        0x12, // SYSTEMTIME
        => 16,
        else => null,
    };
}

