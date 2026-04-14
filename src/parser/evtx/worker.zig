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

pub const EmittedRecord = struct {
    identifier: u64,
    bytes: []u8,
};

const PendingRecord = struct {
    identifier: u64,
    bytes: []u8,
};

pub const CollectedOutput = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayList(EmittedRecord) = .empty,

    pub fn deinit(self: *CollectedOutput) void {
        for (self.records.items) |record| self.allocator.free(record.bytes);
        self.records.deinit(self.allocator);
    }
};

const CollectState = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayList(EmittedRecord) = .empty,
    fail_after_records: ?usize = null,
    fail_error: anyerror = error.Unexpected,

    fn deinit(self: *CollectState) void {
        for (self.records.items) |record| self.allocator.free(record.bytes);
        self.records.deinit(self.allocator);
    }

    fn writeRecord(self: *CollectState, record: PendingRecord) !void {
        const index = self.records.items.len;
        if (self.fail_after_records) |limit| {
            if (index >= limit) return self.fail_error;
        }

        try self.records.append(self.allocator, .{
            .identifier = record.identifier,
            .bytes = record.bytes,
        });
    }

    fn takeOutput(self: *CollectState) CollectedOutput {
        const records = self.records;
        self.records = .empty;
        return .{ .allocator = self.allocator, .records = records };
    }
};

const ConcurrentSink = union(enum) {
    stdout: IoRuntime,
    collect: *CollectState,
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
    identifier: u64,
    start: u32,
    len: u32,
};

const OutputSlot = struct {
    data: std.ArrayList(u8) = .empty,
    spans: std.ArrayList(RecordSpan) = .empty,
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

const JoinedTask = struct {
    chunk_index: usize,
    err: ?anyerror,
};

const SharedState = struct {
    allocator: std.mem.Allocator,
    sink: ConcurrentSink,
    opts: ParserOptions,
    out_kind: OutKind,
    fatal_mutex: std.Io.Mutex = .init,
    write_mutex: std.Io.Mutex = .init,
    fatal_error: ?anyerror = null,
    cancelled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    broken_pipe: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    emitted: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    failed: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    skipped: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    records_skipped: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    records_selected: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    output_slots: ?[]OutputSlot = null,
};

const WorkerTask = struct {
    thread: std.Thread,
    chunk_index: usize,
    chunk: Chunk,
    err: ?anyerror = null,
};

fn sharedIo(shared: *SharedState) std.Io {
    return switch (shared.sink) {
        .stdout => |runtime| runtime.io,
        .collect => std.Options.debug_threaded_io.?.io(),
    };
}

fn setFatal(shared: *SharedState, err: anyerror) void {
    const io = sharedIo(shared);
    shared.fatal_mutex.lockUncancelable(io);
    defer shared.fatal_mutex.unlock(io);
    if (shared.fatal_error == null) {
        shared.fatal_error = err;
        shared.cancelled.store(true, .release);
    }
}

fn writeAll(shared: *SharedState, record: PendingRecord) !void {
    const io = sharedIo(shared);
    shared.write_mutex.lockUncancelable(io);
    defer shared.write_mutex.unlock(io);

    switch (shared.sink) {
        .stdout => |runtime| {
            var write_buf: [4096]u8 = undefined;
            var writer = runtime.stdout_file.writer(runtime.io, &write_buf);
            try writer.interface.writeAll(record.bytes);
            try writer.interface.flush();
            shared.allocator.free(record.bytes);
        },
        .collect => |collector| {
            try collector.writeRecord(record);
        },
    }
}

fn writeAllCatchPipe(shared: *SharedState, record: PendingRecord) void {
    writeAll(shared, record) catch |err| {
        shared.allocator.free(record.bytes);
        handleWriteError(shared, err);
    };
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

fn appendToOutputSlot(shared: *SharedState, slot: *OutputSlot, identifier: u64, bytes: []const u8) bool {
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
    slot.spans.append(allocator, .{ .identifier = identifier, .start = start, .len = len }) catch |err| {
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

fn releaseEmitSlot(shared: *SharedState) void {
    const previous = shared.emitted.fetchSub(1, .acq_rel);
    std.debug.assert(previous > 0);
}

fn reserveSelectedRecord(shared: *SharedState) bool {
    const max_records = shared.opts.max_records;
    if (max_records == 0) return true;

    while (true) {
        const observed = shared.records_selected.load(.acquire);
        if (observed >= max_records) {
            shared.cancelled.store(true, .release);
            return false;
        }
        if (shared.records_selected.cmpxchgWeak(observed, observed + 1, .acq_rel, .acquire) == null) {
            return true;
        }
    }
}

fn assertReadyToDrain(slot: *const OutputSlot, chunk_index: usize) void {
    std.debug.assert(slot.ready.load(.acquire));
    var previous_end: usize = 0;
    for (slot.spans.items) |span| {
        const start: usize = span.start;
        const end: usize = start + span.len;
        if (start < previous_end) {
            std.debug.panic("ordered output slot {d} spans overlap", .{chunk_index});
        }
        if (end > slot.data.items.len) {
            std.debug.panic("ordered output slot {d} span out of bounds", .{chunk_index});
        }
        previous_end = end;
    }
}

fn scheduleOrderedRecord(shared: *SharedState, slot: *OutputSlot, identifier: u64, bytes: []const u8) !void {
    if (!appendToOutputSlot(shared, slot, identifier, bytes)) return error.OutOfMemory;
}

fn makePendingRecord(shared: *SharedState, identifier: u64, bytes: []const u8) !PendingRecord {
    const owned = try shared.allocator.dupe(u8, bytes);
    errdefer shared.allocator.free(owned);
    return .{
        .identifier = identifier,
        .bytes = owned,
    };
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
            if (!reserveSelectedRecord(shared)) return;

            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
            const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &chunk.buf };
            const bytes = out.serializeRecord(view, ctx) catch |e| {
                _ = shared.failed.fetchAdd(1, .acq_rel);
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };
            try scheduleOrderedRecord(shared, slot, rec.identifier, bytes);
        }
        return;
    }

    const has_limits = (opts.max_records != 0) or (opts.skip_first > 0);
    if (!has_limits) {
        while (nextRecord(shared, &rec_iter)) |rec| {
            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
            const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &chunk.buf };
            const bytes = out.serializeRecord(view, ctx) catch |e| {
                _ = shared.failed.fetchAdd(1, .acq_rel);
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };
            const pending = try makePendingRecord(shared, rec.identifier, bytes);
            writeAll(shared, pending) catch |err| {
                handleWriteError(shared, err);
                return err;
            };
        }
        return;
    }

    while (nextRecord(shared, &rec_iter)) |rec| {
        if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
        if (trySkipRecord(shared, &shared.skipped)) continue;
        if (!reserveSelectedRecord(shared)) return;
        if (!reserveEmitSlot(shared)) return;

        const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &chunk.buf };
        const bytes = out.serializeRecord(view, ctx) catch |e| {
            _ = shared.failed.fetchAdd(1, .acq_rel);
            releaseEmitSlot(shared);
            log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
            continue;
        };
        const pending = makePendingRecord(shared, rec.identifier, bytes) catch |err| {
            releaseEmitSlot(shared);
            return err;
        };

        writeAll(shared, pending) catch |err| {
            releaseEmitSlot(shared);
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

fn joinWorker(allocator: std.mem.Allocator, finished: *WorkerTask) JoinedTask {
    defer allocator.destroy(finished);
    finished.thread.join();
    return .{
        .chunk_index = finished.chunk_index,
        .err = finished.err,
    };
}

fn drainOrderedOutput(shared: *SharedState, actual_chunks: usize) !void {
    const slots = shared.output_slots orelse return;
    std.debug.assert(actual_chunks <= slots.len);

    var drained_chunks: usize = 0;
    drain_loop: for (slots[0..actual_chunks], 0..) |*slot, chunk_index| {
        if (!slot.ready.load(.acquire)) break :drain_loop;

        assertReadyToDrain(slot, chunk_index);
        for (slot.spans.items) |span| {
            if (!reserveEmitSlot(shared)) break :drain_loop;

            const start: usize = span.start;
            const end: usize = start + span.len;
            const pending = try makePendingRecord(shared, span.identifier, slot.data.items[start..end]);
            writeAllCatchPipe(shared, pending);
            if (shared.broken_pipe.load(.acquire)) break :drain_loop;
            if (shared.fatal_error) |e| return e;
        }
        drained_chunks += 1;
    }

    if (drained_chunks < actual_chunks) {
        const selected = shared.records_selected.load(.acquire);
        const emitted = shared.emitted.load(.acquire);
        const failed = shared.failed.load(.acquire);
        std.debug.assert(shared.cancelled.load(.acquire));
        std.debug.assert(selected >= emitted + failed);
    }
}

fn parseConcurrentWithSink(
    allocator: std.mem.Allocator,
    sink: ConcurrentSink,
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
        .sink = sink,
        .opts = opts,
        .out_kind = out_kind,
        .output_slots = output_slots,
    };

    var active = std.ArrayList(*WorkerTask).empty;
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
        try active.append(allocator, task);

        if (active.items.len >= worker_limit) {
            const joined = joinWorker(allocator, active.orderedRemove(0));
            if (joined.err) |err| {
                log.err("worker for chunk {d} failed: {s}", .{ joined.chunk_index, @errorName(err) });
                return err;
            }
        }

        if (shared.cancelled.load(.acquire)) break;
        if (!opts.ordered and opts.max_records != 0 and shared.emitted.load(.acquire) >= opts.max_records) break;
    }

    while (active.pop()) |task| {
        const joined = joinWorker(allocator, task);
        if (joined.err) |err| {
            log.err("worker for chunk {d} failed: {s}", .{ joined.chunk_index, @errorName(err) });
            return err;
        }
    }

    if (shared.fatal_error) |e| return e;
    if (shared.broken_pipe.load(.acquire)) return;

    try drainOrderedOutput(&shared, actual_chunks);

    if (shared.broken_pipe.load(.acquire)) return;
    if (opts.verbosity >= 1) log.info("done. emitted={d} failed={d}", .{ shared.emitted.load(.acquire), shared.failed.load(.acquire) });
}

pub fn parseConcurrent(
    allocator: std.mem.Allocator,
    io_runtime: IoRuntime,
    reader: anytype,
    opts: ParserOptions,
    out_kind: OutKind,
    num_threads: usize,
) !void {
    try parseConcurrentWithSink(allocator, .{ .stdout = io_runtime }, reader, opts, out_kind, num_threads);
}

fn countRecordsSingleThreaded(file_path: []const u8, skip_first: usize) !usize {
    var io_impl = std.Io.Threaded.init(std.testing.allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();

    var file = try std.Io.Dir.cwd().openFile(io, file_path, .{ .mode = .read_only });
    defer file.close(io);

    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(io, &read_buf);

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

pub fn collectConcurrentOutput(allocator: std.mem.Allocator, reader: anytype, opts: ParserOptions, out_kind: OutKind, num_threads: usize) !CollectedOutput {
    var collector = CollectState{ .allocator = allocator };
    errdefer collector.deinit();

    try parseConcurrentWithSink(allocator, .{ .collect = &collector }, reader, opts, out_kind, num_threads);
    return collector.takeOutput();
}

pub fn collectConcurrentOutputWithFailure(allocator: std.mem.Allocator, reader: anytype, opts: ParserOptions, out_kind: OutKind, num_threads: usize, fail_after_records: usize, fail_error: anyerror) !CollectedOutput {
    var collector = CollectState{ .allocator = allocator, .fail_after_records = fail_after_records, .fail_error = fail_error };
    errdefer collector.deinit();

    try parseConcurrentWithSink(allocator, .{ .collect = &collector }, reader, opts, out_kind, num_threads);
    return collector.takeOutput();
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
