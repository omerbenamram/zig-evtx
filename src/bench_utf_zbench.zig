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

// Prebuilt input to avoid per-iteration allocations
var g_utf: []u8 = &[_]u8{};
var g_num_chars: usize = 0;

fn beforeAll() void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const ascii_text = "A & B < C > D 'E' \"F\" and a long ASCII paragraph to stress escaping. ";
    var list: std.ArrayList(u8) = .empty;
    // build once, reuse across iterations
    for (0..16384) |_| list.appendSlice(alloc, ascii_text) catch @panic("alloc");
    g_utf = makeUtf16FromAscii(alloc, list.items) catch @panic("alloc");
    g_num_chars = g_utf.len / 2;
}

fn afterAll() void {
    // Intentionally leaking benchmark data to keep hooks simple
}

fn bench_scalar(_: std.mem.Allocator) void {
    // Use a fixed buffer writer for benchmarking
    var buf: [1024 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    util.writeUtf16LeXmlEscaped_scalar(&writer, g_utf, g_num_chars) catch unreachable;
}

fn bench_simd(_: std.mem.Allocator) void {
    // Use a fixed buffer writer for benchmarking
    var buf: [1024 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    util.writeUtf16LeXmlEscaped_simd_utf16(&writer, g_utf, g_num_chars) catch unreachable;
}

fn bench_auto(_: std.mem.Allocator) void {
    // Use a fixed buffer writer for benchmarking
    var buf: [1024 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    util.writeUtf16LeXmlEscaped(&writer, g_utf, g_num_chars) catch unreachable;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var bench = zbench.Benchmark.init(arena.allocator(), .{
        .time_budget_ns = 5_000_000_000,
        .hooks = .{ .before_all = beforeAll, .after_all = afterAll },
    });
    defer bench.deinit();
    try bench.add("utf16 xml escaped scalar", bench_scalar, .{});
    try bench.add("utf16 xml escaped simd", bench_simd, .{});
    try bench.add("utf16 xml escaped auto", bench_auto, .{});
    var write_buf: [8192]u8 = undefined;
    var stdout_file = std.fs.File.stdout();
    var stdout_writer = stdout_file.writer(&write_buf);
    try bench.run(&stdout_writer.interface);
}
