//! Concurrent EVTX parsing with std.Thread.Pool.

const std = @import("std");
const builtin = @import("builtin");
const binxml = @import("../binxml/mod.zig");
const logger = @import("../../logger.zig");
const log = logger.scoped("evtx");

const format = @import("format.zig");
const output = @import("output.zig");
const parser_mod = @import("parser.zig");

pub const FileHeader = format.FileHeader;
pub const Chunk = format.Chunk;
pub const OutputWriter = output.OutputWriter;
pub const ParserOptions = parser_mod.ParserOptions;
pub const OutKind = output.OutputMode;
pub const EventRecordRaw = format.EventRecordRaw;
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

/// Output slot for ordered chunk output.
/// Each slot holds individually serialized records from one chunk.
const RecordSpan = struct {
    start: u32,
    len: u32,
};

const OutputSlot = struct {
    /// Concatenated serialized bytes for all records in this chunk.
    data: std.ArrayList(u8) = .empty,
    /// Record boundaries within `data`.
    spans: std.ArrayList(RecordSpan) = .empty,
    /// Set to true when the worker has finished processing this chunk
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

/// Shared state for concurrent chunk processing.
const SharedState = struct {
    allocator: std.mem.Allocator,
    opts: ParserOptions,
    out_kind: OutKind,
    stdout_file: *std.fs.File,
    write_mutex: *std.Thread.Mutex,
    fatal_mutex: *std.Thread.Mutex,
    fatal_error: *?anyerror,
    cancelled: *std.atomic.Value(bool),
    broken_pipe: *std.atomic.Value(bool),
    emitted: *usize,
    skipped: *usize,
    /// Atomic counter for records skipped (ordered mode uses this for precise record skipping)
    records_skipped: *std.atomic.Value(usize),
    /// Output slots for ordered mode (null in unordered mode)
    output_slots: ?[]OutputSlot = null,
};

fn setFatal(shared: *SharedState, err: anyerror) void {
    shared.fatal_mutex.lock();
    defer shared.fatal_mutex.unlock();
    if (shared.fatal_error.* == null) {
        shared.fatal_error.* = err;
        shared.cancelled.store(true, .release);
    }
}

fn setBrokenPipe(shared: *SharedState) void {
    shared.broken_pipe.store(true, .release);
    shared.cancelled.store(true, .release);
}

fn handleWriteError(shared: *SharedState, err: anyerror) void {
    switch (err) {
        error.BrokenPipe => setBrokenPipe(shared),
        else => setFatal(shared, err),
    }
}

fn nextRecord(shared: *SharedState, iter: *format.RecordIterator) ?EventRecordRaw {
    if (shared.cancelled.load(.acquire)) return null;
    return iter.next() catch |err| {
        setFatal(shared, err);
        return null;
    };
}

fn appendToOutputSlot(shared: *SharedState, slot: *OutputSlot, bytes: []const u8) bool {
    const allocator = shared.allocator;

    const start_usize = slot.data.items.len;
    if (start_usize > std.math.maxInt(u32) or bytes.len > std.math.maxInt(u32)) {
        setFatal(shared, error.OutOfBounds);
        return false;
    }

    const start: u32 = @intCast(start_usize);
    const len: u32 = @intCast(bytes.len);

    slot.data.appendSlice(allocator, bytes) catch |err| {
        setFatal(shared, err);
        return false;
    };
    slot.spans.append(allocator, .{ .start = start, .len = len }) catch |err| {
        slot.data.shrinkRetainingCapacity(start_usize);
        setFatal(shared, err);
        return false;
    };

    return true;
}

/// Process a single chunk - called by thread pool workers.
fn processChunk(shared: *SharedState, chunk_index: usize, chunk: Chunk) void {
    if (shared.cancelled.load(.acquire)) return;

    var ordered_slot: ?*OutputSlot = null;
    if (shared.output_slots) |slots| ordered_slot = &slots[chunk_index];
    defer if (ordered_slot) |slot| slot.ready.store(true, .release);

    const allocator = shared.allocator;
    const opts = shared.opts;

    // Serialize-only mode: we get bytes from serializeRecord and write them manually
    var out = OutputWriter.initSerializeOnly(allocator, shared.out_kind) catch |err| {
        setFatal(shared, err);
        return;
    };
    defer out.deinit();
    var ctx = binxml.Context.init(allocator);
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
    ctx.preCacheFromChunkHeader(&mutable_chunk.buf, &mutable_chunk.header.common_string_offsets) catch |err| {
        setFatal(shared, err);
        return;
    };

    var rec_iter = mutable_chunk.records();
    const has_limits = (opts.max_records != 0) or (opts.skip_first > 0);

    // Ordered mode: store chunk output for ordered draining
    if (ordered_slot) |slot| {
        while (nextRecord(shared, &rec_iter)) |rec| {
            // For ordered mode with skip_first, use atomic counter for precise record skipping
            if (opts.skip_first > 0) {
                const prev = shared.records_skipped.fetchAdd(1, .monotonic);
                if (prev < opts.skip_first) continue; // Skip this record
            }

            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
            const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &mutable_chunk.buf };
            const bytes = out.serializeRecord(view, &ctx) catch |e| {
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };
            if (!appendToOutputSlot(shared, slot, bytes)) return;
        }
    } else if (!has_limits) {
        // Unordered mode without limits: buffer and write immediately
        var chunk_out: std.ArrayList(u8) = .empty;
        defer chunk_out.deinit(allocator);
        chunk_out.ensureTotalCapacityPrecise(allocator, 96 * 1024) catch |err| {
            setFatal(shared, err);
            return;
        };

        while (nextRecord(shared, &rec_iter)) |rec| {
            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
            const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &mutable_chunk.buf };
            const bytes = out.serializeRecord(view, &ctx) catch |e| {
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };
            chunk_out.appendSlice(allocator, bytes) catch |err| {
                setFatal(shared, err);
                return;
            };
        }

        if (shared.cancelled.load(.acquire)) return;
        shared.write_mutex.lock();
        defer shared.write_mutex.unlock();
        shared.stdout_file.writeAll(chunk_out.items) catch |err| {
            handleWriteError(shared, err);
            return;
        };
    } else {
        // Unordered mode with limits: per-record locking for skip/max
        var selected_including_skips: usize = 0;
        while (nextRecord(shared, &rec_iter)) |rec| {
            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });

            if (opts.skip_first > 0) {
                shared.write_mutex.lock();
                const should_skip = (shared.skipped.* < opts.skip_first);
                if (should_skip) shared.skipped.* += 1;
                shared.write_mutex.unlock();
                if (should_skip) continue;
            }

            selected_including_skips += 1;
            const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &mutable_chunk.buf };
            const bytes = out.serializeRecord(view, &ctx) catch |e| {
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };

            shared.write_mutex.lock();
            defer shared.write_mutex.unlock();

            if (opts.max_records != 0 and shared.emitted.* >= opts.max_records) {
                continue;
            }
            shared.stdout_file.writeAll(bytes) catch |err| {
                handleWriteError(shared, err);
                return;
            };
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

    const hdr: FileHeader = try FileHeader.read(reader);

    // Initialize thread pool
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = allocator, .n_jobs = num_threads });
    defer pool.deinit();

    var wg: std.Thread.WaitGroup = .{};

    var stdout_file = std.fs.File.stdout();
    var write_mutex: std.Thread.Mutex = .{};

    var fatal_mutex: std.Thread.Mutex = .{};
    var fatal_error: ?anyerror = null;
    var cancelled = std.atomic.Value(bool).init(false);
    var broken_pipe = std.atomic.Value(bool).init(false);

    // Shared counters for skip and max limits
    var emitted_count: usize = 0;
    var skipped_count: usize = 0;
    var records_skipped_count = std.atomic.Value(usize).init(0);

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
        for (slots) |*slot| {
            slot.data.deinit(allocator);
            slot.spans.deinit(allocator);
        }
        allocator.free(slots);
    };

    var shared = SharedState{
        .allocator = allocator,
        .opts = opts,
        .out_kind = out_kind,
        .stdout_file = &stdout_file,
        .write_mutex = &write_mutex,
        .fatal_mutex = &fatal_mutex,
        .fatal_error = &fatal_error,
        .cancelled = &cancelled,
        .broken_pipe = &broken_pipe,
        .emitted = &emitted_count,
        .skipped = &skipped_count,
        .records_skipped = &records_skipped_count,
        .output_slots = output_slots,
    };

    // Producer: read chunks sequentially and dispatch to pool
    // In carve mode, scan all valid chunks until EOF or invalid signature.
    // Otherwise, trust the header's num_chunks field.
    var chunk_index: usize = 0;
    var actual_chunks: usize = 0;
    while (opts.carve or chunk_index < num_chunks) : (chunk_index += 1) {
        if (cancelled.load(.acquire)) break;
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

        if (cancelled.load(.acquire)) break;
        // Early stop if max_records reached (only relevant in unordered mode)
        if (!opts.ordered and opts.max_records != 0 and emitted_count >= opts.max_records) break;
    }

    // Main thread helps process chunks while waiting (work stealing)
    pool.waitAndWork(&wg);

    // Propagate fatal worker errors (allocation, reader errors, etc.).
    if (fatal_error) |e| return e;
    // Treat BrokenPipe as successful early termination.
    if (broken_pipe.load(.acquire)) return;

    // Ordered mode: drain slots in order, respecting max_records per record
    if (output_slots) |slots| {
        drain_loop: for (slots[0..actual_chunks]) |slot| {
            // Slot should already be ready since we waited for all workers
            if (!slot.ready.load(.acquire)) continue;

            for (slot.spans.items) |span| {
                const start: usize = span.start;
                const end: usize = start + span.len;
                if (end > slot.data.items.len) return error.OutOfBounds;

                stdout_file.writeAll(slot.data.items[start..end]) catch |err| switch (err) {
                    error.BrokenPipe => {
                        broken_pipe.store(true, .release);
                        break :drain_loop;
                    },
                    else => return err,
                };
                emitted_count += 1;

                if (opts.max_records != 0 and emitted_count >= opts.max_records) break :drain_loop;
            }
        }
    }

    if (broken_pipe.load(.acquire)) return;
    if (opts.verbosity >= 1) log.info("done. emitted~={d}", .{emitted_count});
}

// ============================================================================
// Tests
// ============================================================================

/// Count records in an EVTX file using single-threaded parsing.
fn countRecordsSingleThreaded(file_path: []const u8, skip_first: usize) !usize {
    var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_only });
    defer file.close();

    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(&read_buf);

    const hdr = try FileHeader.read(&reader);
    var count: usize = 0;
    var skipped: usize = 0;

    var chunk_index: usize = 0;
    while (chunk_index < hdr.core.num_chunks) : (chunk_index += 1) {
        const chunk = Chunk.read(&reader) catch |e| switch (e) {
            error.EndOfStream, error.BadChunkSignature => break,
            else => return e,
        };

        var rec_iter = chunk.records();
        while (try rec_iter.next()) |_| {
            if (skip_first > 0 and skipped < skip_first) {
                skipped += 1;
                continue;
            }
            count += 1;
        }
    }

    return count;
}

const test_util = @import("../../test/util.zig");

fn getProjectRoot() []const u8 {
    return comptime test_util.getProjectRoot(@src().file);
}

const project_root = getProjectRoot();
const test_evtx_path = project_root ++ "/samples/security.evtx";

test "skip: single-threaded skip_first skips exact number of records" {
    // First, count total records without skipping
    const total = try countRecordsSingleThreaded(test_evtx_path, 0);
    try std.testing.expect(total > 10); // Sanity check: file should have records

    // Now count with skip=5
    const skip_count: usize = 5;
    const after_skip = try countRecordsSingleThreaded(test_evtx_path, skip_count);

    // Verify exactly skip_count records were skipped
    try std.testing.expectEqual(total - skip_count, after_skip);
}

test "skip: single-threaded skip_first larger than total returns zero" {
    // Count total records
    const total = try countRecordsSingleThreaded(test_evtx_path, 0);

    // Skip more than total
    const after_skip = try countRecordsSingleThreaded(test_evtx_path, total + 100);
    try std.testing.expectEqual(@as(usize, 0), after_skip);
}
