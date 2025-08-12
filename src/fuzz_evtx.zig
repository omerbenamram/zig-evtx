const std = @import("std");
const alloc = @import("alloc");
const evtx = @import("parser/evtx.zig");
const binxml = @import("parser/binxml/mod.zig");
const render_xml = @import("parser/render_xml.zig");
const render_json = @import("parser/render_json.zig");

const Stats = struct {
    iters: u64 = 0,
    ok_full_evtx: u64 = 0,
    ok_build_tree: u64 = 0,
    ok_xml_ser: u64 = 0,
    ok_jsonl_ser: u64 = 0,
    last_log_ms: i128 = 0,
    log_every_ms: i128 = 0,
    log_every_iters: u64 = 0,
};
var g_stats: Stats = .{};

fn initLoggingOnce() void {
    if (g_stats.log_every_ms != 0 or g_stats.log_every_iters != 0) return;
    const ms_str = std.process.getEnvVarOwned(alloc.get(), "EVTX_FUZZ_LOG_MS") catch null;
    if (ms_str) |s| {
        defer alloc.get().free(s);
        g_stats.log_every_ms = std.fmt.parseInt(i128, s, 10) catch 0;
        g_stats.last_log_ms = std.time.milliTimestamp();
    }
    const iters_str = std.process.getEnvVarOwned(alloc.get(), "EVTX_FUZZ_LOG_ITERS") catch null;
    if (iters_str) |s2| {
        defer alloc.get().free(s2);
        g_stats.log_every_iters = std.fmt.parseInt(u64, s2, 10) catch 0;
    }
}

fn maybeLogProgress() void {
    if (g_stats.log_every_iters != 0 and (g_stats.iters % g_stats.log_every_iters) == 0) {
        std.debug.print("fuzz: iters={d} ok_full={d} ok_build={d} ok_xml={d} ok_jsonl={d}\n", .{ g_stats.iters, g_stats.ok_full_evtx, g_stats.ok_build_tree, g_stats.ok_xml_ser, g_stats.ok_jsonl_ser });
        return;
    }
    if (g_stats.log_every_ms != 0) {
        const now = std.time.milliTimestamp();
        if (now - g_stats.last_log_ms >= g_stats.log_every_ms) {
            std.debug.print("fuzz: iters={d} ok_full={d} ok_build={d} ok_xml={d} ok_jsonl={d}\n", .{ g_stats.iters, g_stats.ok_full_evtx, g_stats.ok_build_tree, g_stats.ok_xml_ser, g_stats.ok_jsonl_ser });
            g_stats.last_log_ms = now;
        }
    }
}

fn runOnce(data_in: []const u8) void {
    initLoggingOnce();
    var data = data_in;
    if (data.len == 0) return;
    if (data.len > 60000) data = data[0..60000];

    const allocator = alloc.get();

    // Prepare a synthetic 64 KiB chunk buffer; copy fuzz data to help offset-based name lookups hit something.
    var chunk_buf: [65536]u8 = undefined;
    @memset(&chunk_buf, 0);
    const copy_len: usize = if (data.len > chunk_buf.len) chunk_buf.len else data.len;
    if (copy_len > 0) std.mem.copyForwards(u8, chunk_buf[0..copy_len], data[0..copy_len]);

    // Initialize BinXML context
    var ctx = binxml.Context.init(allocator) catch return;
    defer ctx.deinit();

    // 0) Full EVTX parser path with synthetic header+chunk containing fuzz payload as a single record
    if (synthAndParseFullEvtx(allocator, data)) |_| {
        g_stats.ok_full_evtx += 1;
    } else |_| {}

    // 1) Try render XML directly using context (parses + expands internally)
    if (render_xml.renderXmlWithContext(&ctx, &chunk_buf, data, std.io.null_writer)) |_| {
        g_stats.ok_xml_ser += 1;
    } else |_| {}

    // 2) Parse + expand explicitly, then render JSON
    const root = blk: {
        var b = binxml.Builder.init(&ctx, ctx.allocator);
        break :blk b.buildExpandedElementTree(&chunk_buf, data) catch null;
    };
    if (root) |r| {
        g_stats.ok_build_tree += 1;
        if (render_json.renderElementJson(&chunk_buf, r, ctx.arena.allocator(), std.io.null_writer)) |_| {
            g_stats.ok_jsonl_ser += 1;
        } else |_| {}
    }

    // 3) Exercise evtx.Output serializer paths on a fabricated record view
    const rec = evtx.EventRecordView{ .id = 1, .timestamp_filetime = 0, .raw_xml = data, .chunk_buf = &chunk_buf };
    var out_xml = evtx.Output.xml(std.io.null_writer);
    _ = out_xml.serializeRecord(rec) catch {};
    var out_jsonl = evtx.Output.json(std.io.null_writer, .lines);
    _ = out_jsonl.serializeRecord(rec) catch {};

    g_stats.iters += 1;
    maybeLogProgress();
}

fn synthAndParseFullEvtx(allocator: std.mem.Allocator, payload: []const u8) !void {
    // Build: [4096-byte file header][65536-byte chunk]
    var image: [4096 + 65536]u8 = undefined;
    @memset(&image, 0);

    // File header at 0..4096
    var hdr = image[0..4096];
    // Signature "ElfFile\x00"
    hdr[0..8].* = "ElfFile\x00".*;
    // first_chunk: 4096
    std.mem.writeInt(u64, hdr[8..16][0..8], 4096, .little);
    // last_chunk: 4096
    std.mem.writeInt(u64, hdr[16..24][0..8], 4096, .little);
    // next_record_id
    std.mem.writeInt(u64, hdr[24..32][0..8], 1, .little);
    // header_size
    std.mem.writeInt(u32, hdr[32..36][0..4], 4096, .little);
    // minor/major
    std.mem.writeInt(u16, hdr[36..38][0..2], 1, .little);
    std.mem.writeInt(u16, hdr[38..40][0..2], 3, .little);
    // header_block_size
    std.mem.writeInt(u16, hdr[40..42][0..2], 4096, .little);
    // num_chunks
    std.mem.writeInt(u16, hdr[42..44][0..2], 1, .little);
    // flags (unused)
    std.mem.writeInt(u32, hdr[120..124][0..4], 0, .little);
    // checksum over first 120 bytes
    var fh = std.hash.crc.Crc32.init();
    fh.update(hdr[0..120]);
    std.mem.writeInt(u32, hdr[124..128][0..4], fh.final(), .little);

    // Chunk at 4096..4096+65536
    var chunk = image[4096 .. 4096 + 65536];
    @memset(chunk, 0);
    // Chunk signature "ElfChnk\x00"
    chunk[0..8].* = "ElfChnk\x00".*;
    // header_size (we use fixed 512)
    std.mem.writeInt(u32, chunk[40..44][0..4], 512, .little);

    // Build a single record at offset 512.
    const rec_start: usize = 512;
    var rec = chunk[rec_start..];
    // magic **\x00\x00
    rec[0..4].* = .{ 0x2a, 0x2a, 0x00, 0x00 };
    // event payload = fuzz bytes (trim if too big to fit)
    const max_payload: usize = 65536 - rec_start - 32; // keep room for header/tail
    const take: usize = @min(payload.len, max_payload);
    const total_size: usize = 24 + take + 4; // header(24) + data + tail size u32
    std.mem.writeInt(u32, rec[4..8][0..4], @intCast(total_size), .little);
    // identifier, written
    std.mem.writeInt(u64, rec[8..16][0..8], 1, .little);
    std.mem.writeInt(u64, rec[16..24][0..8], 0, .little);
    if (take > 0) std.mem.copyForwards(u8, rec[24 .. 24 + take], payload[0..take]);
    // tail size copy
    std.mem.writeInt(u32, rec[24 + take .. 24 + take + 4][0..4], @intCast(total_size), .little);

    const free_space_off: u32 = @intCast(rec_start + total_size);
    // last_event_record_offset can point to start of our record
    std.mem.writeInt(u32, chunk[44..48][0..4], @intCast(rec_start), .little);
    std.mem.writeInt(u32, chunk[48..52][0..4], free_space_off, .little);

    // Fill CRC32s
    var hc = std.hash.crc.Crc32.init();
    hc.update(chunk[0..120]);
    hc.update(chunk[128..512]);
    std.mem.writeInt(u32, chunk[124..128][0..4], hc.final(), .little);

    var ec = std.hash.crc.Crc32.init();
    ec.update(chunk[512..@intCast(free_space_off)]);
    std.mem.writeInt(u32, chunk[52..56][0..4], ec.final(), .little);

    // Parse via full EvtxParser
    var fbs = std.io.fixedBufferStream(&image);
    var rdr = fbs.reader();
    var parser = try evtx.EvtxParser.init(allocator, .{ .validate_checksums = true, .verbosity = 0 });
    defer parser.deinit();
    var out = evtx.Output.json(std.io.null_writer, .lines);
    parser.parse(&rdr, &out) catch {};
}

// Native fuzzer entrypoint (if available in this Zig version)
// Falls back to a no-op test when fuzz infra is unavailable, so normal builds still succeed.

test "fuzz evtx binxml renderers" {
    if (comptime @hasDecl(std.testing, "fuzzInput")) {
        const input = std.testing.fuzzInput();
        runOnce(input);
    } else {
        // Provide a couple of tiny smoke seeds so the test does something under non-fuzz runs
        const seeds = [_][]const u8{
            &.{},
            &.{ 0x41, 0x00, 0x42, 0x00 }, // small UTF-16 fragment
            &.{ 0x01, 0x00, 0x00, 0x00 }, // minimal token-ish bytes
        };
        var i: usize = 0;
        while (i < seeds.len) : (i += 1) runOnce(seeds[i]);
    }
}