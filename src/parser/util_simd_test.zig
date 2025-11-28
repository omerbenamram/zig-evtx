//! SIMD vs Scalar parity tests for UTF-16LE encoding functions.
//! Verifies that SIMD-optimized paths produce identical output to scalar paths.

const std = @import("std");
const util = @import("util.zig");

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
        .ascii => return util.utf16FromAscii(alloc, "Hello &<>\"' World"),
        .long_ascii => return util.utf16FromAscii(alloc, "aaaaaaa&bbbbbbb&ccccccc<dddddd>eeeeee\"fffffff'gggggg"),
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

fn runMatrixCase(mode: Mode, id: CaseId) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const bytes = try buildUtf16Case(alloc, id);
    defer alloc.free(bytes);
    const num_chars = bytes.len / 2;

    var out_a: std.ArrayList(u8) = .empty;
    defer out_a.deinit(alloc);
    var out_b: std.ArrayList(u8) = .empty;
    defer out_b.deinit(alloc);

    switch (mode) {
        .xml => {
            try util.writeUtf16LeXmlEscaped_simd_utf16(out_a.writer(alloc), bytes, num_chars);
            try util.writeUtf16LeXmlEscaped_scalar(out_b.writer(alloc), bytes, num_chars);
        },
        .json => {
            try util.writeUtf16LeJsonEscaped_simd_utf16(out_a.writer(alloc), bytes, num_chars);
            // Use the scalar JSON escaper path
            try util.writeUtf16LeJsonEscaped_scalar(out_b.writer(alloc), bytes, num_chars);
        },
    }
    try std.testing.expectEqualStrings(out_b.items, out_a.items);
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
