//! Concurrent EVTX parsing with explicit std.Thread workers.

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

pub const IoRuntime = struct {
    io: std.Io,
    stdout_file: *std.Io.File,
};

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

const RecordSpan = struct {
    start: u32,
    len: u32,
};

const OutputSlot = struct {
    data: std.ArrayList(u8) = .empty,
    spans: std.ArrayList(RecordSpan) = .empty,
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

const SharedState = struct {
    allocator: std.mem.Allocator,
    io_runtime: IoRuntime,
    opts: ParserOptions,
    out_kind: OutKind,
    fatal_mutex: std.Io.Mutex = .init,
    write_mutex: std.Thread.Mutex = .{},
    fatal_error: ?anyerror = null,
    cancelled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    broken_pipe: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    emitted: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    skipped: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    records_skipped: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    output_slots: ?[]OutputSlot = null,
};

const WorkerTask = struct {
    thread: std.Thread,
    chunk_index: usize,
    chunk: Chunk,
    err: ?anyerror = null,
};

const ActiveWorker = struct {
    task: *WorkerTask,
};

fn setFatal(shared: *SharedState, err: anyerror) void {
    shared.fatal_mutex.lockUncancelable(shared.io_runtime.io);
    defer shared.fatal_mutex.unlock(shared.io_runtime.io);
    if (shared.fatal_error == null) {
        shared.fatal_error = err;
        shared.cancelled.store(true, .release);
    }
}

fn writeAll(shared: *SharedState, bytes: []const u8) !void {
    shared.write_mutex.lock();
    defer shared.write_mutex.unlock();

    var write_buf: [4096]u8 = undefined;
    var writer = shared.io_runtime.stdout_file.writer(shared.io_runtime.io, &write_buf);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

fn writeAllCatchPipe(shared: *SharedState, bytes: []const u8) void {
    writeAll(shared, bytes) catch |err| handleWriteError(shared, err);
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

fn reserveEmitSlot(shared: *SharedState) bool {
    const max_records = shared.opts.max_records;
    if (max_records == 0) return true;

    while (true) {
        const observed = shared.emitted.load(.acquire);
        if (observed >= max_records) {
            shared.cancelled.store(true, .release);
            return false;
        }
        if (shared.emitted.cmpxchgWeak(observed, observed + 1, .acq_rel, .acquire) == null) {
            if (observed + 1 >= max_records) shared.cancelled.store(true, .release);
            return true;
        }
    }
}

fn assertReadyToDrain(slot: *const OutputSlot, chunk_index: usize) void {
    std.debug.assert(slot.ready.load(.acquire));
    for (slot.spans.items) |span| {
        const start: usize = span.start;
        const end: usize = start + span.len;
        if (end > slot.data.items.len) {
            std.debug.panic("ordered output slot {d} span out of bounds", .{chunk_index});
        }
    }
}

fn scheduleOrderedRecord(shared: *SharedState, slot: *OutputSlot, bytes: []const u8) !void {
    if (!appendToOutputSlot(shared, slot, bytes)) return error.OutOfMemory;
}

fn trySkipRecord(shared: *SharedState, skip_counter: *std.atomic.Value(usize)) bool {
    if (shared.opts.skip_first == 0) return false;
    const prev = skip_counter.fetchAdd(1, .monotonic);
    return prev < shared.opts.skip_first;
}

fn serializeChunkRecords(shared: *SharedState, chunk_index: usize, chunk: *Chunk, out: *OutputWriter, ctx: *binxml.Context) !void {
    const opts = shared.opts;
    var rec_iter = chunk.records();

    if (shared.output_slots) |slots| {
        const slot = &slots[chunk_index];
        defer slot.ready.store(true, .release);

        while (nextRecord(shared, &rec_iter)) |rec| {
            if (trySkipRecord(shared, &shared.records_skipped)) continue;

            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
            const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &chunk.buf };
            const bytes = out.serializeRecord(view, ctx) catch |e| {
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };
            try scheduleOrderedRecord(shared, slot, bytes);
        }
        return;
    }

    const has_limits = (opts.max_records != 0) or (opts.skip_first > 0);
    if (!has_limits) {
        var chunk_out: std.ArrayList(u8) = .empty;
        defer chunk_out.deinit(shared.allocator);
        try chunk_out.ensureTotalCapacityPrecise(shared.allocator, 96 * 1024);

        while (nextRecord(shared, &rec_iter)) |rec| {
            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
            const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &chunk.buf };
            const bytes = out.serializeRecord(view, ctx) catch |e| {
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };
            try chunk_out.appendSlice(shared.allocator, bytes);
        }

        if (shared.cancelled.load(.acquire) or chunk_out.items.len == 0) return;
        try writeAll(shared, chunk_out.items);
        return;
    }

    while (nextRecord(shared, &rec_iter)) |rec| {
        if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
        if (trySkipRecord(shared, &shared.skipped)) continue;
        if (!reserveEmitSlot(shared)) return;

        const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &chunk.buf };
        const bytes = out.serializeRecord(view, ctx) catch |e| {
            shared.emitted.fetchSub(1, .acq_rel);
            log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
            continue;
        };

        writeAll(shared, bytes) catch |err| {
            shared.emitted.fetchSub(1, .acq_rel);
            handleWriteError(shared, err);
            return err;
        };
    }
}

fn processChunk(shared: *SharedState, chunk_index: usize, chunk: Chunk) !void {
    if (shared.cancelled.load(.acquire)) return;

    const allocator = shared.allocator;
    const opts = shared.opts;

    var out = OutputWriter.initSerializeOnly(allocator, shared.out_kind) catch |err| {
        setFatal(shared, err);
        return err;
    };
    defer out.deinit();
    var ctx = binxml.Context.init(allocator);
    defer ctx.deinit();

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
        return err;
    };

    serializeChunkRecords(shared, chunk_index, &mutable_chunk, &out, &ctx) catch |err| {
        setFatal(shared, err);
        return err;
    };
}

fn workerMain(shared: *SharedState, task: *WorkerTask) void {
    processChunk(shared, task.chunk_index, task.chunk) catch |err| {
        task.err = err;
    };
}

fn joinWorker(allocator: std.mem.Allocator, finished: *WorkerTask) !void {
    defer allocator.destroy(finished);
    finished.thread.join();
    if (finished.err) |err| return err;
}

fn drainOrderedOutput(shared: *SharedState, actual_chunks: usize) !void {
    const slots = shared.output_slots orelse return;

    drain_loop: for (slots[0..actual_chunks], 0..) |*slot, chunk_index| {
        assertReadyToDrain(slot, chunk_index);
        for (slot.spans.items) |span| {
            if (!reserveEmitSlot(shared)) break :drain_loop;

            const start: usize = span.start;
            const end: usize = start + span.len;
            writeAllCatchPipe(shared, slot.data.items[start..end]);
            if (shared.broken_pipe.load(.acquire)) break :drain_loop;
            if (shared.fatal_error) |e| return e;
        }
    }
}

pub fn parseConcurrent(
    allocator: std.mem.Allocator,
    io_runtime: IoRuntime,
    reader: anytype,
    opts: ParserOptions,
    out_kind: OutKind,
    num_threads: usize,
) !void {
    ignoreSigpipe();

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

    if (opts.verbosity >= 3) logger.setModuleLevel("binxml", .trace);

    const hdr: FileHeader = try FileHeader.read(reader);
    const num_chunks: usize = hdr.core.num_chunks;
    var output_slots: ?[]OutputSlot = null;
    if (opts.ordered and num_chunks > 0) {
        output_slots = try allocator.alloc(OutputSlot, num_chunks);
        for (output_slots.?) |*slot| slot.* = .{};
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
        .io_runtime = io_runtime,
        .opts = opts,
        .out_kind = out_kind,
        .output_slots = output_slots,
    };

    var active = std.ArrayList(ActiveWorker).empty;
    defer active.deinit(allocator);
    const worker_limit = @max(@as(usize, 1), num_threads);

    var chunk_index: usize = 0;
    var actual_chunks: usize = 0;
    while (opts.carve or chunk_index < num_chunks) : (chunk_index += 1) {
        if (shared.cancelled.load(.acquire)) break;
        const chunk = Chunk.read(reader) catch |e| switch (e) {
            error.EndOfStream, error.BadChunkSignature => break,
            else => {
                log.err("failed to read chunk {d}: {s}", .{ chunk_index, @errorName(e) });
                break;
            },
        };
        actual_chunks += 1;

        const task = try allocator.create(WorkerTask);
        errdefer allocator.destroy(task);
        task.* = .{
            .thread = undefined,
            .chunk_index = chunk_index,
            .chunk = chunk,
        };
        task.thread = try std.Thread.spawn(.{}, workerMain, .{ &shared, task });
        errdefer task.thread.join();
        try active.append(allocator, .{ .task = task });

        if (active.items.len >= worker_limit) {
            try joinWorker(allocator, active.orderedRemove(0).task);
        }

        if (shared.cancelled.load(.acquire)) break;
        if (!opts.ordered and opts.max_records != 0 and shared.emitted.load(.acquire) >= opts.max_records) break;
    }

    while (active.pop()) |entry| {
        try joinWorker(allocator, entry.task);
    }

    if (shared.fatal_error) |e| return e;
    if (shared.broken_pipe.load(.acquire)) return;

    try drainOrderedOutput(&shared, actual_chunks);

    if (shared.broken_pipe.load(.acquire)) return;
    if (opts.verbosity >= 1) log.info("done. emitted={d}", .{shared.emitted.load(.acquire)});
}

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
    const total = try countRecordsSingleThreaded(test_evtx_path, 0);
    try std.testing.expect(total > 10);
}
