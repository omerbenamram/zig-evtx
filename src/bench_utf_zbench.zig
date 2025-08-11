const std = @import("std");
const zbench = @import("zbench");
const util = @import("parser/util.zig");

fn makeUtf16FromAscii(alloc: std.mem.Allocator, ascii: []const u8) ![]u8 {
    var buf = try alloc.alloc(u8, ascii.len * 2);
    for (ascii, 0..) |c, i| {
        buf[i * 2] = c;
        buf[i * 2 + 1] = 0;
    }
    return buf;
}

const DevNullWriter = struct {
    pub const Error = error{};
    pub const Writer = std.io.Writer(*DevNullWriter, Error, write);
    pub fn writer(self: *DevNullWriter) Writer {
        return .{ .context = self };
    }
    fn write(self: *DevNullWriter, bytes: []const u8) Error!usize {
        _ = self;
        if (bytes.len > 0) {
            var tmp: u8 = 0;
            const vp: *volatile u8 = &tmp;
            vp.* = bytes[bytes.len - 1];
        }
        return bytes.len;
    }
};

// Prebuilt input and writer to avoid per-iteration allocations
var g_dev: DevNullWriter = .{};
var g_writer: DevNullWriter.Writer = undefined;
var g_utf: []u8 = &[_]u8{};
var g_num_chars: usize = 0;
var g_utf_mixed: []u8 = &[_]u8{};
var g_num_chars_mixed: usize = 0;

fn beforeAll() void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    g_writer = g_dev.writer();
    const ascii_text = "A & B < C > D 'E' \"F\" and a long ASCII paragraph to stress escaping. ";
    var list = std.ArrayList(u8).init(alloc);
    // build once, reuse across iterations
    for (0..16384) |_| list.appendSlice(ascii_text) catch @panic("alloc");
    g_utf = makeUtf16FromAscii(alloc, list.items) catch @panic("alloc");
    g_num_chars = g_utf.len / 2;

    // Mixed BMP/surrogates sequence to stress non-ASCII path
    const mixed = "© α β γ Ω 中文 😀 emojis & < > \" ' more";
    var list2 = std.ArrayList(u8).init(alloc);
    for (0..8192) |_| list2.appendSlice(mixed) catch @panic("alloc");
    g_utf_mixed = makeUtf16FromAscii(alloc, list2.items) catch @panic("alloc");
    g_num_chars_mixed = g_utf_mixed.len / 2;
}

fn afterAll() void {
    // If arena is used, freeing is optional; keep function for completeness
    // Intentionally leaking benchmark data to keep hooks simple
}

fn bench_new_ascii(_: std.mem.Allocator) void {
    util.writeUtf16LeXmlEscaped_scalar(g_writer, g_utf, g_num_chars) catch unreachable;
}

fn bench_old_ascii(_: std.mem.Allocator) void {
    util.writeUtf16LeXmlEscaped_old(g_writer, g_utf, g_num_chars) catch unreachable;
}

fn bench_simd_ascii(_: std.mem.Allocator) void {
    util.writeUtf16LeXmlEscaped(g_writer, g_utf, g_num_chars) catch unreachable;
}

fn bench_simd_ascii_2(_: std.mem.Allocator) void {
    util.writeUtf16LeXmlEscaped_simd_2(g_writer, g_utf, g_num_chars) catch unreachable;
}

fn bench_simd_utf16_mixed(_: std.mem.Allocator) void {
    util.writeUtf16LeXmlEscaped_simd_utf16(g_writer, g_utf_mixed, g_num_chars_mixed) catch unreachable;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var bench = zbench.Benchmark.init(arena.allocator(), .{
        .time_budget_ns = 5_000_000_000,
        .hooks = .{ .before_all = beforeAll, .after_all = afterAll },
    });
    defer bench.deinit();
    try bench.add("utf16 xml escaped new ascii", bench_new_ascii, .{});
    try bench.add("utf16 xml escaped old ascii", bench_old_ascii, .{});
    try bench.add("utf16 xml escaped simd ascii", bench_simd_ascii, .{});
    try bench.add("utf16 xml escaped simd ascii (more)", bench_simd_ascii_2, .{});
    try bench.add("utf16 xml escaped simd utf16 mixed", bench_simd_utf16_mixed, .{});
    try bench.run(std.io.getStdOut().writer());
}
