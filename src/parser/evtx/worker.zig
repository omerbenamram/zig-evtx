//! Concurrent EVTX parsing with std.Thread.Pool.

const std = @import("std");
const binxml = @import("../binxml/mod.zig");
const alloc_mod = @import("alloc");
const logger = @import("../../logger.zig");
const log = logger.scoped("evtx");

const format = @import("format.zig");
const output = @import("output.zig");

pub const FileHeader = format.FileHeader;
pub const Chunk = format.Chunk;
pub const EventRecordView = format.EventRecordView;
pub const Output = output.Output;

pub const OutKind = enum { xml, json_single, json_lines };

pub const ParserOptions = struct {
    validate_checksums: bool = true,
    verbosity: u8 = 0,
    max_records: usize = 0,
    skip_first: usize = 0,
};

/// Shared state for concurrent chunk processing.
const SharedState = struct {
    allocator: std.mem.Allocator,
    opts: ParserOptions,
    out_kind: OutKind,
    stdout_file: *std.fs.File,
    write_mutex: *std.Thread.Mutex,
    emitted: *usize,
    skipped: *usize,
};

/// Process a single chunk - called by thread pool workers.
fn processChunk(shared: *SharedState, chunk_index: usize, chunk: Chunk) void {
    const allocator = shared.allocator;
    const opts = shared.opts;

    // Use a null writer for serialization - we'll write the result directly
    const null_writer = std.io.null_writer;

    // Per-task output and context
    var out = switch (shared.out_kind) {
        .xml => Output.xml(null_writer),
        .json_single => Output.json(null_writer, .single),
        .json_lines => Output.json(null_writer, .lines),
    };
    var ctx = binxml.Context.init(allocator) catch return;
    defer ctx.deinit();

    // Mutable copy for validation
    var mutable_chunk = chunk;

    if (opts.verbosity >= 1) log.info("chunk {d}: free_off=0x{x}, last_rec_off=0x{x}", .{ chunk_index, mutable_chunk.header.free_space_offset, mutable_chunk.header.last_event_record_offset });

    if (opts.validate_checksums) {
        mutable_chunk.validateChecksums() catch |e| {
            log.err("chunk {d} checksum error: {s}", .{ chunk_index, @errorName(e) });
            return;
        };
    }

    ctx.resetPerChunk();
    ctx.preCacheFromChunkHeader(&mutable_chunk.buf, &mutable_chunk.header.common_string_offsets);
    ctx.verbose = (opts.verbosity >= 3);
    out.setContext(&ctx);

    var rec_iter = mutable_chunk.records();
    const has_limits = (opts.max_records != 0) or (opts.skip_first > 0);

    if (!has_limits) {
        // Fast path: no global limits, render the whole chunk to a local buffer, then single write
        var chunk_out: std.ArrayList(u8) = .empty;
        defer chunk_out.deinit(alloc_mod.get());
        chunk_out.ensureTotalCapacityPrecise(alloc_mod.get(), 96 * 1024) catch {};

        while (rec_iter.next() catch null) |rec| {
            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
            const view = EventRecordView{ .id = rec.identifier, .timestamp_filetime = rec.written_time, .raw_xml = rec.binxml, .chunk_buf = rec.chunk_buf };
            const bytes = out.serializeRecord(view) catch |e| {
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };
            chunk_out.appendSlice(alloc_mod.get(), bytes) catch continue;
        }

        shared.write_mutex.lock();
        // Write directly to stdout fd, bypassing buffering issues
        _ = std.posix.write(shared.stdout_file.handle, chunk_out.items) catch {};
        shared.write_mutex.unlock();
    } else {
        // Slow path: global skip/max limits require per-record locking
        var selected_including_skips: usize = 0;
        while (rec_iter.next() catch null) |rec| {
            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });

            if (opts.skip_first > 0) {
                shared.write_mutex.lock();
                const should_skip = (shared.skipped.* < opts.skip_first);
                if (should_skip) shared.skipped.* += 1;
                shared.write_mutex.unlock();
                if (should_skip) continue;
            }

            selected_including_skips += 1;
            const view = EventRecordView{ .id = rec.identifier, .timestamp_filetime = rec.written_time, .raw_xml = rec.binxml, .chunk_buf = rec.chunk_buf };
            const bytes = out.serializeRecord(view) catch |e| {
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };

            shared.write_mutex.lock();
            defer shared.write_mutex.unlock();

            if (opts.max_records != 0 and shared.emitted.* >= opts.max_records) {
                continue;
            }
            _ = std.posix.write(shared.stdout_file.handle, bytes) catch continue;
            if (opts.max_records != 0) {
                shared.emitted.* += 1;
            }
        }
    }
}

/// Run concurrent parsing with std.Thread.Pool.
pub fn parseConcurrent(
    allocator: std.mem.Allocator,
    reader: anytype,
    opts: ParserOptions,
    out_kind: OutKind,
    num_threads: usize,
) !void {
    // Logging levels
    switch (opts.verbosity) {
        0 => {},
        1 => {
            logger.setModuleLevel("evtx", .info);
            logger.setModuleLevel("binxml", .warn);
            log.info("reading file header...", .{});
        },
        2 => {
            logger.setModuleLevel("evtx", .debug);
            logger.setModuleLevel("binxml", .debug);
            log.info("reading file header...", .{});
        },
        else => {
            logger.setModuleLevel("evtx", .trace);
            logger.setModuleLevel("binxml", .trace);
            log.info("reading file header...", .{});
        },
    }

    var hdr: FileHeader = try FileHeader.read(reader);
    if (opts.validate_checksums) try hdr.validateChecksum();

    // Initialize thread pool
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = allocator, .n_jobs = num_threads });
    defer pool.deinit();

    var wg: std.Thread.WaitGroup = .{};

    var stdout_file = std.fs.File.stdout();
    var write_mutex: std.Thread.Mutex = .{};

    // Shared counters for skip and max limits
    var emitted_count: usize = 0;
    var skipped_count: usize = 0;

    var shared = SharedState{
        .allocator = allocator,
        .opts = opts,
        .out_kind = out_kind,
        .stdout_file = &stdout_file,
        .write_mutex = &write_mutex,
        .emitted = &emitted_count,
        .skipped = &skipped_count,
    };

    // Producer: read chunks sequentially and dispatch to pool
    var chunk_index: usize = 0;
    while (chunk_index < hdr.core.num_chunks) : (chunk_index += 1) {
        const chunk = Chunk.read(reader) catch |e| {
            log.err("failed to read chunk {d}: {s}", .{ chunk_index, @errorName(e) });
            break;
        };

        // Dispatch to thread pool with WaitGroup tracking
        pool.spawnWg(&wg, processChunk, .{ &shared, chunk_index, chunk });

        // Early stop if max_records reached
        if (opts.max_records != 0 and emitted_count >= opts.max_records) break;
    }

    // Main thread helps process chunks while waiting (work stealing)
    pool.waitAndWork(&wg);

    // No final flush needed - using direct posix writes

    if (opts.verbosity >= 1) log.info("done. emitted~={d}", .{emitted_count});
}
