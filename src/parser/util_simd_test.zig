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

/// Convert ASCII string to UTF-16LE bytes (test helper)
fn asciiToUtf16(alloc: std.mem.Allocator, ascii: []const u8) ![]u8 {
    const buf = try alloc.alloc(u8, ascii.len * 2);
    for (ascii, 0..) |c, i| {
        buf[i * 2] = c;
        buf[i * 2 + 1] = 0;
    }
    return buf;
}

fn buildUtf16Case(alloc: std.mem.Allocator, id: CaseId) ![]u8 {
    switch (id) {
        .ascii => return asciiToUtf16(alloc, "Hello &<>\"' World"),
        .long_ascii => return asciiToUtf16(alloc, "aaaaaaa&bbbbbbb&ccccccc<dddddd>eeeeee\"fffffff'gggggg"),
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

fn runXmlCase(id: CaseId) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const bytes = try buildUtf16Case(alloc, id);
    defer alloc.free(bytes);
    const num_chars = bytes.len / 2;

    // Use fixed buffers with std.Io.Writer
    var buf_simd: [4096]u8 = undefined;
    var buf_scalar: [4096]u8 = undefined;

    var writer_simd = std.Io.Writer.fixed(&buf_simd);
    var writer_scalar = std.Io.Writer.fixed(&buf_scalar);

    try util.writeUtf16LeXmlEscaped_simd_utf16(&writer_simd, bytes, num_chars);
    try util.writeUtf16LeXmlEscaped_scalar(&writer_scalar, bytes, num_chars);

    const out_simd = writer_simd.buffer[0..writer_simd.end];
    const out_scalar = writer_scalar.buffer[0..writer_scalar.end];

    try std.testing.expectEqualStrings(out_scalar, out_simd);
}

fn runJsonCase(id: CaseId) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const bytes = try buildUtf16Case(alloc, id);
    defer alloc.free(bytes);
    const num_chars = bytes.len / 2;

    // Use fixed buffers with std.Io.Writer
    var buf_simd: [4096]u8 = undefined;
    var buf_scalar: [4096]u8 = undefined;

    var writer_simd = std.Io.Writer.fixed(&buf_simd);
    var writer_scalar = std.Io.Writer.fixed(&buf_scalar);

    try util.writeUtf16LeJsonEscaped_simd(&writer_simd, bytes, num_chars);
    try util.writeUtf16LeJsonEscaped_scalar(&writer_scalar, bytes, num_chars);

    const out_simd = writer_simd.buffer[0..writer_simd.end];
    const out_scalar = writer_scalar.buffer[0..writer_scalar.end];

    // Note: lone surrogates (hi_only, lo_only) produce no output - that's expected
    try std.testing.expectEqualStrings(out_scalar, out_simd);
}

// XML SIMD vs Scalar parity tests
test "XML - ascii" {
    try runXmlCase(.ascii);
}
test "XML - euro" {
    try runXmlCase(.euro);
}
test "XML - e_acute" {
    try runXmlCase(.e_acute);
}
test "XML - two_byte_max" {
    try runXmlCase(.two_byte_max);
}
test "XML - grinning" {
    try runXmlCase(.grinning);
}
test "XML - hi_only" {
    try runXmlCase(.hi_only);
}
test "XML - lo_only" {
    try runXmlCase(.lo_only);
}
test "XML - ctrl_1f" {
    try runXmlCase(.ctrl_1f);
}
test "XML - newline" {
    try runXmlCase(.newline);
}
test "XML - long_ascii" {
    try runXmlCase(.long_ascii);
}

// JSON SIMD vs Scalar parity tests
test "JSON - ascii" {
    try runJsonCase(.ascii);
}
test "JSON - euro" {
    try runJsonCase(.euro);
}
test "JSON - e_acute" {
    try runJsonCase(.e_acute);
}
test "JSON - two_byte_max" {
    try runJsonCase(.two_byte_max);
}
test "JSON - grinning" {
    try runJsonCase(.grinning);
}
test "JSON - hi_only" {
    try runJsonCase(.hi_only);
}
test "JSON - lo_only" {
    try runJsonCase(.lo_only);
}
test "JSON - ctrl_1f" {
    try runJsonCase(.ctrl_1f);
}
test "JSON - newline" {
    try runJsonCase(.newline);
}
test "JSON - long_ascii" {
    try runJsonCase(.long_ascii);
}
