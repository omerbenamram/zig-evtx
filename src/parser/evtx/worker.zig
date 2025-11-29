//! Concurrent EVTX parsing with std.Thread.Pool.

const std = @import("std");
const builtin = @import("builtin");
const binxml = @import("../binxml/mod.zig");
const alloc_mod = @import("alloc");
const logger = @import("../../logger.zig");
const log = logger.scoped("evtx");

/// Ignore SIGPIPE to prevent crashes when stdout is closed (e.g., piped to head/hyperfine).
fn ignoreSigpipe() void {
    if (comptime builtin.os.tag != .windows) {
        const act = std.posix.Sigaction{
            .handler = .{ .handler = std.posix.SIG.IGN },
            .mask = std.mem.zeroes(std.posix.sigset_t),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.PIPE, &act, null);
    }
}

const format = @import("format.zig");
const output = @import("output.zig");
const parser_mod = @import("parser.zig");

pub const FileHeader = format.FileHeader;
pub const Chunk = format.Chunk;
pub const OutputWriter = output.OutputWriter;
pub const ParserOptions = parser_mod.ParserOptions;

pub const OutKind = enum { xml, json_single, json_lines };

/// Output slot for ordered chunk output.
/// Each slot holds the serialized output for one chunk.
const OutputSlot = struct {
    /// Serialized output bytes (owned by allocator)
    data: []u8 = &.{},
    /// Set to true when the worker has finished processing this chunk
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

/// Shared state for concurrent chunk processing.
const SharedState = struct {
    allocator: std.mem.Allocator,
    opts: ParserOptions,
    out_kind: OutKind,
    json_opts: output.JsonOptions,
    stdout_file: *std.fs.File,
    write_mutex: *std.Thread.Mutex,
    emitted: *usize,
    skipped: *usize,
    /// Output slots for ordered mode (null in unordered mode)
    output_slots: ?[]OutputSlot = null,
};

/// Process a single chunk - called by thread pool workers.
fn processChunk(shared: *SharedState, chunk_index: usize, chunk: Chunk) void {
    const allocator = shared.allocator;
    const opts = shared.opts;

    // Serialize-only mode: we get bytes from serializeRecord and write them manually
    var out = OutputWriter.initSerializeOnlyWithOptions(switch (shared.out_kind) {
        .xml => .xml,
        .json_single => .json_single,
        .json_lines => .json_lines,
    }, shared.json_opts);
    defer out.deinit();
    var ctx = binxml.Context.init(allocator) catch return;
    defer ctx.deinit();

    // Mutable copy for validation
    var mutable_chunk = chunk;

    if (opts.verbosity >= 1) log.info("chunk {d}: free_off=0x{x}, last_rec_off=0x{x}", .{ chunk_index, mutable_chunk.header.free_space_offset, mutable_chunk.header.last_event_record_offset });

    if (opts.validate_checksums) {
        mutable_chunk.validateChecksums() catch |e| {
            log.err("chunk {d} checksum error: {s}", .{ chunk_index, @errorName(e) });
            // In ordered mode, mark slot ready with empty data so drain doesn't hang
            if (shared.output_slots) |slots| {
                slots[chunk_index].ready.store(true, .release);
            }
            return;
        };
    }

    ctx.resetPerChunk();
    ctx.preCacheFromChunkHeader(&mutable_chunk.buf, &mutable_chunk.header.common_string_offsets);

    var rec_iter = mutable_chunk.records();
    const has_limits = (opts.max_records != 0) or (opts.skip_first > 0);

    // Ordered mode: always buffer to chunk_out, store in slot when done
    if (shared.output_slots != null or !has_limits) {
        // Buffer all records for this chunk
        var chunk_out: std.ArrayList(u8) = .empty;
        defer if (shared.output_slots == null) chunk_out.deinit(alloc_mod.get());
        chunk_out.ensureTotalCapacityPrecise(alloc_mod.get(), 96 * 1024) catch {};

        while (rec_iter.next() catch null) |rec| {
            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
            const bytes = out.serializeRecord(rec, &ctx) catch |e| {
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };
            chunk_out.appendSlice(alloc_mod.get(), bytes) catch continue;
        }

        if (shared.output_slots) |slots| {
            // Ordered mode: store in slot for later ordered drain
            slots[chunk_index].data = chunk_out.toOwnedSlice(alloc_mod.get()) catch &.{};
            slots[chunk_index].ready.store(true, .release);
        } else {
            // Unordered mode without limits: write immediately with mutex
            shared.write_mutex.lock();
            shared.stdout_file.writeAll(chunk_out.items) catch {};
            shared.write_mutex.unlock();
        }
    } else {
        // Unordered mode with limits: per-record locking for skip/max
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
            const bytes = out.serializeRecord(rec, &ctx) catch |e| {
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };

            shared.write_mutex.lock();
            defer shared.write_mutex.unlock();

            if (opts.max_records != 0 and shared.emitted.* >= opts.max_records) {
                continue;
            }
            shared.stdout_file.writeAll(bytes) catch continue;
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
    json_opts: output.JsonOptions,
    num_threads: usize,
) !void {
    // Ignore SIGPIPE so we don't crash when stdout closes (e.g., piping to head)
    ignoreSigpipe();

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

    // Set trace level for binxml if highest verbosity - done here once before spawning threads
    if (opts.verbosity >= 3) logger.setModuleLevel("binxml", .trace);

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

    // Allocate output slots for ordered mode
    const num_chunks: usize = hdr.core.num_chunks;
    var output_slots: ?[]OutputSlot = null;
    if (opts.ordered and num_chunks > 0) {
        output_slots = try allocator.alloc(OutputSlot, num_chunks);
        for (output_slots.?) |*slot| {
            slot.* = .{};
        }
    }
    defer if (output_slots) |slots| {
        for (slots) |slot| {
            if (slot.data.len > 0) allocator.free(slot.data);
        }
        allocator.free(slots);
    };

    var shared = SharedState{
        .allocator = allocator,
        .opts = opts,
        .out_kind = out_kind,
        .json_opts = json_opts,
        .stdout_file = &stdout_file,
        .write_mutex = &write_mutex,
        .emitted = &emitted_count,
        .skipped = &skipped_count,
        .output_slots = output_slots,
    };

    // Producer: read chunks sequentially and dispatch to pool
    // In carve mode, scan all valid chunks until EOF or invalid signature.
    // Otherwise, trust the header's num_chunks field.
    var chunk_index: usize = 0;
    var actual_chunks: usize = 0;
    while (opts.carve or chunk_index < num_chunks) : (chunk_index += 1) {
        const chunk = Chunk.read(reader) catch |e| switch (e) {
            error.EndOfStream, error.BadChunkSignature => break,
            else => {
                log.err("failed to read chunk {d}: {s}", .{ chunk_index, @errorName(e) });
                break;
            },
        };
        actual_chunks += 1;

        // Dispatch to thread pool with WaitGroup tracking
        pool.spawnWg(&wg, processChunk, .{ &shared, chunk_index, chunk });

        // Early stop if max_records reached (only relevant in unordered mode)
        if (!opts.ordered and opts.max_records != 0 and emitted_count >= opts.max_records) break;
    }

    // Main thread helps process chunks while waiting (work stealing)
    pool.waitAndWork(&wg);

    // Ordered mode: drain slots in order
    if (output_slots) |slots| {
        var skipped: usize = 0;
        for (slots[0..actual_chunks]) |slot| {
            // Slot should already be ready since we waited for all workers
            if (!slot.ready.load(.acquire)) continue;
            if (slot.data.len == 0) continue;

            // Handle skip/max limits during ordered drain
            if (opts.skip_first > 0 and skipped < opts.skip_first) {
                // For ordered mode, we skip entire chunks (simplification)
                // A more precise implementation would parse record boundaries
                skipped += 1;
                continue;
            }

            stdout_file.writeAll(slot.data) catch {};
            emitted_count += 1;

            if (opts.max_records != 0 and emitted_count >= opts.max_records) break;
        }
    }

    if (opts.verbosity >= 1) log.info("done. emitted~={d}", .{emitted_count});
}
