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
const Serializer = output.Serializer;

// ============================================================================
// Global Fixture Data
// ============================================================================

/// Store chunk buffers (64KB each, heap-allocated). Records reference these.
var g_chunk_bufs: std.ArrayList([]u8) = undefined;

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
    _ = FileHeader.read(&reader.interface) catch |err| {
        std.debug.print("Failed to read file header: {}\n", .{err});
        @panic("Cannot read file header");
    };

    // Read chunks and collect records until we have enough
    var records_collected: usize = 0;
    while (records_collected < NUM_RECORDS) {
        const chunk = Chunk.read(g_alloc, &reader.interface) catch |err| {
            if (err == error.EndOfStream) break;
            std.debug.print("Failed to read chunk: {}\n", .{err});
            break;
        };

        // Record the chunk's owned buffer. Records below reference it.
        const chunk_idx = g_chunk_bufs.items.len;
        g_chunk_bufs.append(g_alloc, chunk.buf) catch @panic("alloc");
        const stored_buf: []const u8 = g_chunk_bufs.items[chunk_idx];

        // Collect records from this chunk
        var iter = chunk.records();
        while (iter.next() catch |err| {
            std.debug.print("Record iterator error: {}\n", .{err});
            @panic("record iterator failed");
        }) |rec| {
            const binxml_offset = @intFromPtr(rec.binxml.ptr) - @intFromPtr(rec.chunk_buf.ptr);
            const stored_rec = EventRecordRaw{
                .identifier = rec.identifier,
                .written_time = rec.written_time,
                .binxml = stored_buf[binxml_offset..][0..rec.binxml.len],
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
    var ctx = binxml.Context.init(g_alloc);
    defer ctx.deinit();

    var writer = Serializer.init(g_alloc, .xml) catch |err| {
        std.debug.print("Serializer.init(xml) failed: {s}\n", .{@errorName(err)});
        @panic("Serializer.init failed");
    };
    defer writer.deinit();

    for (g_records.items) |rec| {
        ctx.resetPerChunk();
        _ = writer.serializeRecord(rec, &ctx) catch |err| {
            std.debug.print("serializeRecord(xml) failed: {s}\n", .{@errorName(err)});
            @panic("serializeRecord failed");
        };
    }
}

fn bench_serialize_json(_: std.mem.Allocator) void {
    var ctx = binxml.Context.init(g_alloc);
    defer ctx.deinit();

    var writer = Serializer.init(g_alloc, .json_lines) catch |err| {
        std.debug.print("Serializer.init(json) failed: {s}\n", .{@errorName(err)});
        @panic("Serializer.init failed");
    };
    defer writer.deinit();

    for (g_records.items) |rec| {
        ctx.resetPerChunk();
        _ = writer.serializeRecord(rec, &ctx) catch |err| {
            std.debug.print("serializeRecord(json) failed: {s}\n", .{@errorName(err)});
            @panic("serializeRecord failed");
        };
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
