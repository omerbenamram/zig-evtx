//! Micro-benchmark for record serialization (XML and JSON).
//!
//! This benchmark measures the hot path identified via flame graph analysis:
//! OutputWriter.serializeRecord() which dominates ~70% of execution time.
//!
//! Usage: make bench-serialize

const std = @import("std");
const zbench = @import("zbench");
const alloc_mod = @import("alloc");

const format = @import("parser/evtx/format.zig");
const output = @import("parser/evtx/output.zig");
const binxml = @import("parser/binxml/mod.zig");

const EventRecordRaw = format.EventRecordRaw;
const Chunk = format.Chunk;
const FileHeader = format.FileHeader;
const OutputWriter = output.OutputWriter;

// ============================================================================
// Global Fixture Data
// ============================================================================

/// Store chunk buffers (64KB each). Records reference these.
var g_chunk_bufs: std.ArrayList([65536]u8) = undefined;

/// Pre-parsed records ready for serialization benchmarking.
var g_records: std.ArrayList(EventRecordRaw) = undefined;

/// Allocator for fixture setup.
var g_alloc: std.mem.Allocator = undefined;

/// Number of records to collect for benchmarking.
const NUM_RECORDS: usize = 100;

/// Sample file to load.
const SAMPLE_FILE = "samples/security_big_sample.evtx";

// ============================================================================
// Fixture Setup/Teardown
// ============================================================================

fn beforeAll() void {
    g_alloc = alloc_mod.get();
    g_chunk_bufs = .empty;
    g_records = .empty;

    // Open the EVTX file
    const file = std.fs.cwd().openFile(SAMPLE_FILE, .{}) catch |err| {
        std.debug.print("Failed to open {s}: {}\n", .{ SAMPLE_FILE, err });
        @panic("Cannot open sample file");
    };
    defer file.close();

    // Create a buffered reader
    var read_buf: [65536]u8 = undefined;
    var reader = file.reader(&read_buf);

    // Read file header
    _ = FileHeader.read(&reader) catch |err| {
        std.debug.print("Failed to read file header: {}\n", .{err});
        @panic("Cannot read file header");
    };

    // Read chunks and collect records until we have enough
    var records_collected: usize = 0;
    while (records_collected < NUM_RECORDS) {
        const chunk = Chunk.read(&reader) catch |err| {
            if (err == error.EndOfStream) break;
            std.debug.print("Failed to read chunk: {}\n", .{err});
            break;
        };

        // Store chunk buffer (records will reference it)
        const chunk_idx = g_chunk_bufs.items.len;
        g_chunk_bufs.append(g_alloc, chunk.buf) catch @panic("alloc");

        // Get pointer to the stored chunk buffer
        const stored_buf: *const [65536]u8 = &g_chunk_bufs.items[chunk_idx];

        // Re-parse chunk header from stored buffer to get iterator
        const stored_chunk = Chunk{
            .header = format.ChunkHeader.parse(stored_buf) catch @panic("chunk parse"),
            .buf = stored_buf.*,
        };

        // Collect records from this chunk
        var iter = stored_chunk.records();
        while (iter.next() catch null) |rec| {
            // Calculate offset of binxml slice within chunk buffer
            const binxml_offset = @intFromPtr(rec.binxml.ptr) - @intFromPtr(rec.chunk_buf);
            // Create record pointing to our stored buffer
            const stored_rec = EventRecordRaw{
                .identifier = rec.identifier,
                .written_time = rec.written_time,
                .binxml = g_chunk_bufs.items[chunk_idx][binxml_offset..][0..rec.binxml.len],
                .chunk_buf = stored_buf,
            };
            g_records.append(g_alloc, stored_rec) catch @panic("alloc");
            records_collected += 1;
            if (records_collected >= NUM_RECORDS) break;
        }
    }

    std.debug.print("Loaded {} records from {} chunks\n", .{ g_records.items.len, g_chunk_bufs.items.len });
}

fn afterAll() void {
    // Intentionally leak - keeps hooks simple and zbench lifetime is program lifetime
}

// ============================================================================
// Benchmark Functions
// ============================================================================

fn bench_serialize_xml(_: std.mem.Allocator) void {
    var ctx = binxml.Context.init(g_alloc) catch @panic("ctx init");
    defer ctx.deinit();

    var writer = OutputWriter.initSerializeOnly(.xml);
    defer writer.deinit();

    for (g_records.items) |rec| {
        ctx.resetPerChunk();
        _ = writer.serializeRecord(rec, &ctx) catch continue;
    }
}

fn bench_serialize_json(_: std.mem.Allocator) void {
    var ctx = binxml.Context.init(g_alloc) catch @panic("ctx init");
    defer ctx.deinit();

    var writer = OutputWriter.initSerializeOnly(.json_lines);
    defer writer.deinit();

    for (g_records.items) |rec| {
        ctx.resetPerChunk();
        _ = writer.serializeRecord(rec, &ctx) catch continue;
    }
}

// ============================================================================
// Main
// ============================================================================

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var bench = zbench.Benchmark.init(arena.allocator(), .{
        .time_budget_ns = 5_000_000_000, // 5 seconds per benchmark
        .hooks = .{ .before_all = beforeAll, .after_all = afterAll },
    });
    defer bench.deinit();

    try bench.add("serialize_xml (100 records)", bench_serialize_xml, .{});
    try bench.add("serialize_json (100 records)", bench_serialize_json, .{});

    // Create buffered writer for stdout
    var write_buf: [8192]u8 = undefined;
    var stdout_file = std.fs.File.stdout();
    var stdout_writer = stdout_file.writer(&write_buf);

    try bench.run(&stdout_writer.interface);
    try stdout_writer.interface.flush();
}
