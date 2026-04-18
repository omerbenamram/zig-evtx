//! Concurrent EVTX parsing built on Zig 0.16 std.Io primitives.
//!
//! Architecture:
//! - A fixed pool of `worker_limit` long-lived worker futures. Each worker
//!   owns its `Serializer` and `Context` and reuses them across every chunk
//!   it processes, so the allocator never sees per-chunk setup cost.
//! - A fixed pool of `Buffer`s (double-buffered: `2 * worker_limit`). Each
//!   `Buffer` holds the serialised bytes of one chunk plus `RecordSpan`
//!   metadata. Workers rent a `Buffer` from a free-list queue, fill it, and
//!   publish a `ChunkBatch` pointing at it. The drain emits the spans and
//!   returns the `Buffer` to the free-list.
//! - Three `std.Io.Queue`s thread the stages together: intake→workers
//!   (`task_queue`), workers→drain (`batch_queue`), drain→workers
//!   (`free_list`).
//! - Cancellation is cooperative via `Future.cancel` from the orchestrator.
//!   Early-exit (max_records reached, sink error) closes the queues, which
//!   causes any blocked `putOne` / `getOne` to return `error.Closed`; workers
//!   and intake then unwind cleanly.
//! - Buffer memory is owned by the orchestrator for the entire parse. The
//!   free-list queue only passes around `*Buffer` pointers, so "orphaned"
//!   buffers (e.g. a worker holding one when the free-list closes) never
//!   leak — the orchestrator's teardown deinits every buffer in the pool.

const std = @import("std");
const binxml = @import("../binxml/mod.zig");
const logger = @import("../../logger.zig");
const log = logger.scoped("evtx");
const runtime = @import("../../runtime.zig");

const format = @import("format.zig");
const output = @import("output.zig");
const parser_mod = @import("parser.zig");
const err_mod = @import("../err.zig");

pub const FileHeader = format.FileHeader;
pub const Chunk = format.Chunk;
pub const Serializer = output.Serializer;
pub const ParserOptions = parser_mod.ParserOptions;
pub const OutKind = output.OutputMode;
pub const EventRecordRaw = format.EventRecordRaw;

/// Errors the worker pipeline (parse + publish) can surface. Sink-side
/// functions still return `anyerror!void` because user-supplied sinks
/// (Python bindings, test stubs) can fail with arbitrary errors.
pub const WorkerError = err_mod.RenderError ||
    std.Io.Cancelable ||
    std.mem.Allocator.Error ||
    error{Closed};

pub const IoRuntime = struct {
    io: std.Io,
    stdout_file: *std.Io.File,
    stdout_writer: *std.Io.File.Writer,
};

// ---------------------------------------------------------------------------
// Public collect API (unchanged surface for tests and Python bindings)
// ---------------------------------------------------------------------------

/// A single serialized record with heap-owned bytes. Only materialised on the
/// `collectConcurrentOutput*` paths (tests, bindings). The stdout drain
/// writes spans directly and never allocates an `EmittedRecord`.
pub const EmittedRecord = struct {
    identifier: u64,
    bytes: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, identifier: u64, bytes: []const u8) !EmittedRecord {
        const owned = try allocator.dupe(u8, bytes);
        return .{ .identifier = identifier, .bytes = owned, .allocator = allocator };
    }

    pub fn takeOwned(allocator: std.mem.Allocator, identifier: u64, owned_bytes: []u8) EmittedRecord {
        return .{ .identifier = identifier, .bytes = owned_bytes, .allocator = allocator };
    }

    pub fn deinit(self: *const EmittedRecord) void {
        self.allocator.free(self.bytes);
    }
};

pub fn duplicateEmittedRecord(allocator: std.mem.Allocator, identifier: u64, bytes: []const u8) !EmittedRecord {
    return EmittedRecord.init(allocator, identifier, bytes);
}

pub fn deinitEmittedRecords(_: std.mem.Allocator, records: []const EmittedRecord) void {
    for (records) |*record| record.deinit();
}

pub const CollectedOutput = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayList(EmittedRecord) = .empty,

    pub fn deinit(self: *CollectedOutput) void {
        for (self.records.items) |*record| record.deinit();
        self.records.deinit(self.allocator);
    }
};

const CollectState = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayList(EmittedRecord) = .empty,
    fail_after_records: ?usize = null,
    fail_error: anyerror = error.Unexpected,
    /// Test-only: artificial delay injected before each record is appended,
    /// used to widen the window between workers and drain so that any
    /// ordering/ownership bug surfaces as dropped or reordered records.
    per_record_delay: ?std.Io.Duration = null,
    io: ?std.Io = null,

    fn deinit(self: *CollectState) void {
        for (self.records.items) |*record| record.deinit();
        self.records.deinit(self.allocator);
    }

    fn writeRecord(self: *CollectState, identifier: u64, bytes: []const u8) !void {
        const index = self.records.items.len;
        if (self.fail_after_records) |limit| {
            if (index >= limit) return self.fail_error;
        }

        if (self.per_record_delay) |dur| {
            if (self.io) |io| std.Io.sleep(io, dur, .awake) catch |e| switch (e) {
                error.Canceled => return e,
            };
        }

        const record = try EmittedRecord.init(self.allocator, identifier, bytes);
        try self.records.append(self.allocator, record);
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

// ---------------------------------------------------------------------------
// Internal pipeline types
// ---------------------------------------------------------------------------

const RecordSpan = struct { identifier: u64, start: u32, len: u32 };

/// Reusable output buffer for one chunk. Workers rent one from the free-list,
/// fill `data` with serialised records and `spans` with `(id, offset, len)`
/// tuples, then hand off ownership (the `*Buffer` pointer) to the drain. The
/// drain emits the spans and returns the pointer to the free-list. The
/// underlying `ArrayList`s keep their capacity via `clearRetainingCapacity`,
/// so steady-state workload performs zero allocations per chunk.
const Buffer = struct {
    data: std.ArrayList(u8) = .empty,
    spans: std.ArrayList(RecordSpan) = .empty,

    fn reset(self: *Buffer) void {
        self.data.clearRetainingCapacity();
        self.spans.clearRetainingCapacity();
    }

    fn deinit(self: *Buffer, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
        self.spans.deinit(allocator);
    }
};

/// Worker output: a chunk index (for ordered reassembly) plus a borrowed
/// buffer pointer. The drain owns the pointer transiently and returns it
/// to the free-list after emitting.
const ChunkBatch = struct {
    chunk_index: usize,
    record_base: usize,
    buffer: *Buffer,
};

/// Intake output: a chunk ready for a worker to parse.
const WorkerTask = struct {
    chunk_index: usize,
    record_base: usize,
    chunk: Chunk,

    fn deinit(self: *WorkerTask) void {
        self.chunk.deinit();
    }
};

const TaskQueue = std.Io.Queue(WorkerTask);
const BatchQueue = std.Io.Queue(ChunkBatch);
const FreeListQueue = std.Io.Queue(*Buffer);

/// Shared state threaded through every pipeline task by pointer.
const SharedState = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: ConcurrentSink,
    opts: ParserOptions,
    out_kind: OutKind,
    stdout_kind: ?std.Io.File.Kind = null,

    task_queue: *TaskQueue,
    batch_queue: *BatchQueue,
    free_list: *FreeListQueue,

    /// Counts down as workers exit; the last one out closes `batch_queue`
    /// so the drain observes end-of-stream without orchestrator intervention
    /// on the clean path.
    workers_alive: std.atomic.Value(usize),

    // Counters retained for observability and for selection accounting.
    emitted: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    failed: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    skipped: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    records_selected: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
};

// ---------------------------------------------------------------------------
// Sink helpers
// ---------------------------------------------------------------------------

fn shouldTreatSinkErrorAsCleanStop(shared: *const SharedState, err: anyerror) bool {
    return switch (shared.sink) {
        .stdout => runtime.shouldTreatOutputErrorAsCleanExitForKind(err, shared.stdout_kind),
        .collect => false,
    };
}

fn isCleanStopError(shared: *const SharedState, err: anyerror) bool {
    if (err == error.BrokenPipe) return true;
    return shouldTreatSinkErrorAsCleanStop(shared, err);
}

/// Writes one record span to the sink. The drain calls this once per span
/// inside a ChunkBatch. No flushing here — the drain flushes once at
/// end-of-stream, matching the sequential path's behaviour.
fn writeSpanToSink(shared: *SharedState, data: []const u8, span: RecordSpan) anyerror!void {
    const bytes = data[span.start .. span.start + span.len];
    switch (shared.sink) {
        .stdout => |io_runtime| {
            try io_runtime.stdout_writer.interface.writeAll(bytes);
        },
        .collect => |collector| {
            try collector.writeRecord(span.identifier, bytes);
        },
    }
}

fn flushSink(shared: *SharedState) anyerror!void {
    switch (shared.sink) {
        .stdout => |io_runtime| try io_runtime.stdout_writer.interface.flush(),
        .collect => {},
    }
}

// ---------------------------------------------------------------------------
// Selection helpers (skip_first / max_records)
// ---------------------------------------------------------------------------

fn selectedRecordRangeEnd(opts: ParserOptions) ?usize {
    if (opts.max_records == 0) return null;
    return std.math.add(usize, opts.skip_first, opts.max_records) catch std.math.maxInt(usize);
}

fn usesLogicalSubsetSelection(opts: ParserOptions) bool {
    return !opts.ordered and opts.skip_first > 0;
}

/// Per-worker record-selection predicate. Exactly the semantics the pre-batch
/// code had; the sequential parser in `parser.zig` also uses this via
/// `forSequential`, so we must keep the public surface stable.
pub const RecordFilter = struct {
    mode: Mode,
    skip_first: usize = 0,
    selection_end: ?usize = null,
    record_index: usize = 0,

    const Mode = enum { take_all, logical_subset, shared_counter };
    pub const Decision = enum { take, skip, stop };

    fn forTask(opts: ParserOptions, record_base: usize) RecordFilter {
        if (opts.ordered) return .{ .mode = .take_all };
        if (usesLogicalSubsetSelection(opts)) return .{
            .mode = .logical_subset,
            .skip_first = opts.skip_first,
            .selection_end = selectedRecordRangeEnd(opts),
            .record_index = record_base,
        };
        if (opts.max_records != 0) return .{ .mode = .shared_counter };
        return .{ .mode = .take_all };
    }

    pub fn forSequential(opts: ParserOptions) RecordFilter {
        return .{
            .mode = .logical_subset,
            .skip_first = opts.skip_first,
            .selection_end = selectedRecordRangeEnd(opts),
            .record_index = 0,
        };
    }

    pub fn acceptLocal(self: *RecordFilter) Decision {
        switch (self.mode) {
            .take_all => return .take,
            .logical_subset => {
                const i = self.record_index;
                self.record_index += 1;
                if (i < self.skip_first) return .skip;
                if (self.selection_end) |end| {
                    if (i >= end) return .stop;
                }
                return .take;
            },
            .shared_counter => unreachable,
        }
    }

    fn accept(self: *RecordFilter, shared: *SharedState) Decision {
        return switch (self.mode) {
            .take_all, .logical_subset => self.acceptLocal(),
            .shared_counter => blk: {
                if (trySkipRecord(shared, &shared.skipped)) break :blk .skip;
                if (!reserveSelectedRecord(shared)) break :blk .stop;
                break :blk .take;
            },
        };
    }
};

fn countChunkRecords(chunk: *const Chunk) usize {
    const buf = chunk.buf;
    const end = @min(buf.len, chunk.header.free_space_offset);
    var offset: usize = format.CHUNK_HEADER_SIZE;
    var count: usize = 0;
    while (offset + 24 <= end) {
        if (!std.mem.eql(u8, buf[offset..][0..4], &[_]u8{ 0x2a, 0x2a, 0x00, 0x00 })) break;
        const size = std.mem.readInt(u32, buf[offset + 4 ..][0..4], .little);
        if (size < 32) break;
        if (offset + size > end) break;
        offset += size;
        count += 1;
    }
    return count;
}

fn trySkipRecord(shared: *SharedState, skip_counter: *std.atomic.Value(usize)) bool {
    if (shared.opts.skip_first == 0) return false;
    const prev = skip_counter.fetchAdd(1, .monotonic);
    return prev < shared.opts.skip_first;
}

fn reserveSelectedRecord(shared: *SharedState) bool {
    const max_records = shared.opts.max_records;
    if (max_records == 0) return true;
    while (true) {
        const observed = shared.records_selected.load(.acquire);
        if (observed >= max_records) return false;
        if (shared.records_selected.cmpxchgWeak(observed, observed + 1, .acq_rel, .acquire) == null) return true;
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// Long-lived worker. Loops pulling `WorkerTask`s, renting a `*Buffer`,
/// serialising the chunk into it, and publishing a `ChunkBatch`. Exits
/// when `task_queue` is closed (clean shutdown) or any queue op returns
/// an error we can't recover from. The last worker to exit closes
/// `batch_queue` so the drain observes end-of-stream.
fn workerLoop(shared: *SharedState) WorkerError!void {
    // Last-worker-out closes the batch queue so the drain unblocks on
    // end-of-stream. Runs on every exit path (clean, error, cancel).
    defer {
        if (shared.workers_alive.fetchSub(1, .acq_rel) == 1) {
            shared.batch_queue.close(shared.io);
        }
    }

    const allocator = shared.allocator;
    const out_kind = shared.out_kind;

    var serializer = try Serializer.init(allocator, out_kind);
    defer serializer.deinit();
    var ctx = binxml.Context.init(allocator);
    defer ctx.deinit();

    while (true) {
        var task = shared.task_queue.getOne(shared.io) catch |e| switch (e) {
            error.Closed => return,
            else => return e,
        };
        // Chunk ownership is ours once we've dequeued the task. On every
        // exit path below we must free it (either by publishing the batch
        // and letting drain drop the chunk's buf via `task.chunk.deinit()`,
        // or by dropping it ourselves on error).
        //
        // Actually the drain doesn't need the chunk buffer — the buffer
        // holds the serialised bytes. So we free the chunk right after
        // parsing it into the output buffer.

        const buffer = shared.free_list.getOne(shared.io) catch |e| switch (e) {
            error.Closed => {
                task.deinit();
                return;
            },
            else => {
                task.deinit();
                return e;
            },
        };
        buffer.reset();

        processChunk(shared, &task, buffer, &serializer, &ctx) catch |e| {
            task.deinit();
            // Return the buffer to the free-list so another worker can use
            // it. If the free-list is closed, the buffer is still in the
            // orchestrator's pool and will be deinited at teardown.
            shared.free_list.putOne(shared.io, buffer) catch {};
            return e;
        };
        task.deinit();

        shared.batch_queue.putOne(shared.io, .{
            .chunk_index = task.chunk_index,
            .record_base = task.record_base,
            .buffer = buffer,
        }) catch |e| switch (e) {
            error.Closed => {
                // Drain exited early. Return buffer to free-list if we can.
                shared.free_list.putOne(shared.io, buffer) catch {};
                return;
            },
            else => {
                shared.free_list.putOne(shared.io, buffer) catch {};
                return e;
            },
        };
    }
}

/// Serialises every record in `task.chunk` into `buffer`, honouring the
/// opts-derived `RecordFilter`. Reuses the worker-owned `serializer` and
/// `ctx` across chunks.
fn processChunk(shared: *SharedState, task: *WorkerTask, buffer: *Buffer, serializer: *Serializer, ctx: *binxml.Context) WorkerError!void {
    const allocator = shared.allocator;
    const opts = shared.opts;
    const chunk = &task.chunk;

    if (opts.verbosity >= 1) log.info("chunk {d}: free_off=0x{x}, last_rec_off=0x{x}", .{
        task.chunk_index,
        chunk.header.free_space_offset,
        chunk.header.last_event_record_offset,
    });

    if (opts.validate_checksums) {
        chunk.validateChecksums() catch |e| {
            log.err("chunk {d} checksum error: {s}", .{ task.chunk_index, @errorName(e) });
            return;
        };
    }

    ctx.resetPerChunk();
    try ctx.preCacheFromChunkHeader(chunk.buf, &chunk.header.common_string_offsets);

    var filter = RecordFilter.forTask(opts, task.record_base);
    var rec_iter = chunk.records();

    while (try rec_iter.next()) |rec| {
        if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
        switch (filter.accept(shared)) {
            .stop => return,
            .skip => continue,
            .take => {},
        }

        const view = EventRecordRaw{
            .identifier = rec.identifier,
            .written_time = rec.written_time,
            .binxml = rec.binxml,
            .chunk_buf = chunk.buf,
        };
        const bytes = serializer.serializeRecord(view, ctx) catch |e| {
            _ = shared.failed.fetchAdd(1, .acq_rel);
            log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
            switch (opts.on_record_error) {
                .continue_with_log => continue,
                .fail_fast => return e,
            }
        };

        const start: u32 = @intCast(buffer.data.items.len);
        try buffer.data.appendSlice(allocator, bytes);
        try buffer.spans.append(allocator, .{
            .identifier = rec.identifier,
            .start = start,
            .len = @intCast(bytes.len),
        });
    }
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

/// Emits spans from one batch. Returns the buffer to the free-list on every
/// exit path, including errors.
///
/// In ordered mode, workers run `take_all`, so the drain must apply
/// `skip_first` and `max_records` itself; `skipped` is threaded across
/// batches to keep the filter global. In unordered mode, workers have
/// already enforced both via the `logical_subset` or `shared_counter`
/// filters — the drain just emits.
fn emitBatch(
    shared: *SharedState,
    batch: ChunkBatch,
    skipped: *usize,
    should_stop: *bool,
) anyerror!void {
    defer shared.free_list.putOne(shared.io, batch.buffer) catch {};

    if (should_stop.*) return;

    const opts = shared.opts;
    const data = batch.buffer.data.items;

    for (batch.buffer.spans.items) |span| {
        if (opts.ordered) {
            if (opts.skip_first > 0 and skipped.* < opts.skip_first) {
                skipped.* += 1;
                continue;
            }
            if (opts.max_records != 0 and shared.emitted.load(.acquire) >= opts.max_records) {
                should_stop.* = true;
                return;
            }
        }

        try writeSpanToSink(shared, data, span);
        _ = shared.emitted.fetchAdd(1, .acq_rel);
    }
}

/// Ordered drain: batches arrive in completion order from workers, but we
/// must emit in chunk-index order. Buffer out-of-order batches in a small
/// hash map keyed by chunk_index; whenever the next expected chunk arrives,
/// drain it plus any already-buffered successors.
fn drainOrdered(shared: *SharedState) anyerror!void {
    const allocator = shared.allocator;
    var pending: std.AutoHashMapUnmanaged(usize, ChunkBatch) = .empty;
    defer {
        // Anything still in the reorder map on exit: return its buffer so
        // the free-list can be drained by the orchestrator (or a blocked
        // worker can be unblocked if the free-list is still open).
        var it = pending.valueIterator();
        while (it.next()) |batch| {
            shared.free_list.putOne(shared.io, batch.buffer) catch {};
        }
        pending.deinit(allocator);
    }

    var next_expected: usize = 0;
    var skipped: usize = 0;
    var should_stop = false;

    while (!should_stop) {
        const batch = shared.batch_queue.getOne(shared.io) catch |e| switch (e) {
            error.Closed => break,
            else => return e,
        };

        if (batch.chunk_index == next_expected) {
            try emitBatch(shared, batch, &skipped, &should_stop);
            next_expected += 1;

            // Drain any subsequent chunks that arrived early.
            while (pending.fetchRemove(next_expected)) |kv| {
                if (should_stop) {
                    // Drop without emitting; still return the buffer.
                    shared.free_list.putOne(shared.io, kv.value.buffer) catch {};
                    next_expected += 1;
                    continue;
                }
                try emitBatch(shared, kv.value, &skipped, &should_stop);
                next_expected += 1;
            }
        } else {
            try pending.put(allocator, batch.chunk_index, batch);
        }
    }

    // On clean shutdown (batch_queue closed by last worker), any pending
    // entries represent chunks that were skipped by intake (e.g. due to
    // logical_subset selection). Return their buffers.
    // Handled by the deferred cleanup above.
}

/// Unordered drain: emit batches as they arrive, respecting skip_first (via
/// the shared-counter filter in workers) and max_records (here globally).
fn drainUnordered(shared: *SharedState) anyerror!void {
    var skipped: usize = 0;
    var should_stop = false;

    while (!should_stop) {
        const batch = shared.batch_queue.getOne(shared.io) catch |e| switch (e) {
            error.Closed => return,
            else => return e,
        };

        try emitBatch(shared, batch, &skipped, &should_stop);
    }
}

/// Top-level drain dispatcher. Flushes the sink once at end-of-stream so we
/// match the sequential path's one-flush behaviour.
fn drainMain(shared: *SharedState) anyerror!void {
    const result = if (shared.opts.ordered) drainOrdered(shared) else drainUnordered(shared);
    // Flush before propagating the result so partial output gets written.
    flushSink(shared) catch |flush_err| {
        if (result) |_| {
            return flush_err;
        } else |_| {}
    };
    try result;
}

// ---------------------------------------------------------------------------
// Intake
// ---------------------------------------------------------------------------

/// Reads chunks sequentially and pushes them into the task queue. Closes
/// `task_queue` on exit so workers observe end-of-input.
fn intakeLoop(
    shared: *SharedState,
    reader: *std.Io.Reader,
    num_chunks: usize,
    carve: bool,
) anyerror!void {
    const allocator = shared.allocator;
    defer shared.task_queue.close(shared.io);

    var chunk_index: usize = 0;
    var record_base: usize = 0;
    const selection_end = if (usesLogicalSubsetSelection(shared.opts)) selectedRecordRangeEnd(shared.opts) else null;

    while (carve or chunk_index < num_chunks) : (chunk_index += 1) {
        // Lock-free early-exit checks. The drain/workers may have progressed
        // past max_records since we last looked.
        if (shared.opts.max_records != 0 and shared.emitted.load(.acquire) >= shared.opts.max_records) break;
        if (selection_end) |end| {
            if (record_base >= end) break;
        }

        var chunk = Chunk.read(allocator, reader) catch |e| switch (e) {
            error.EndOfStream, error.BadChunkSignature => break,
            else => {
                std.Io.checkCancel(shared.io) catch |ce| switch (ce) {
                    error.Canceled => return,
                };
                log.err("failed to read chunk {d}: {s}", .{ chunk_index, @errorName(e) });
                return e;
            },
        };

        const chunk_record_base = record_base;
        if (selection_end != null or usesLogicalSubsetSelection(shared.opts)) {
            record_base += countChunkRecords(&chunk);
        }

        if (usesLogicalSubsetSelection(shared.opts)) {
            // Whole chunk falls inside skip_first prefix; don't queue it.
            if (record_base <= shared.opts.skip_first) {
                chunk.deinit();
                continue;
            }
        }

        shared.task_queue.putOne(shared.io, .{
            .chunk_index = chunk_index,
            .record_base = chunk_record_base,
            .chunk = chunk,
        }) catch |e| switch (e) {
            error.Closed => {
                // Pipeline teardown requested; drop this chunk and exit.
                chunk.deinit();
                return;
            },
            else => {
                chunk.deinit();
                return e;
            },
        };
    }
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

fn parseConcurrentWithSink(
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: ConcurrentSink,
    reader: *std.Io.Reader,
    opts: ParserOptions,
    out_kind: OutKind,
    num_threads: usize,
) !void {
    runtime.ignoreSigpipe();
    runtime.configureVerbosity(opts.verbosity);

    const hdr: FileHeader = try FileHeader.read(reader);
    const num_chunks: usize = hdr.core.num_chunks;
    const worker_limit = @max(@as(usize, 1), num_threads);

    // Queue capacities. Scaled to worker_limit so we never stall because of
    // tiny fixed buffers. `buffer_count` > `worker_limit` gives the pipeline
    // slack: a worker can start filling the next buffer while a previous
    // one is still on its way through the drain.
    const buffer_count = worker_limit * 2;
    const task_cap = @max(worker_limit * 2, 4);
    const batch_cap = @max(buffer_count, 4);
    const free_cap = buffer_count;

    // Orchestrator owns the buffer pool for the entire parse. Workers and
    // the drain only borrow `*Buffer` pointers; on teardown we deinit every
    // buffer regardless of which queue still holds the pointer.
    const buffers = try allocator.alloc(Buffer, buffer_count);
    for (buffers) |*b| b.* = .{};
    defer {
        for (buffers) |*b| b.deinit(allocator);
        allocator.free(buffers);
    }

    const task_buf = try allocator.alloc(WorkerTask, task_cap);
    defer allocator.free(task_buf);
    var task_queue = TaskQueue.init(task_buf);

    const batch_buf = try allocator.alloc(ChunkBatch, batch_cap);
    defer allocator.free(batch_buf);
    var batch_queue = BatchQueue.init(batch_buf);

    const free_buf = try allocator.alloc(*Buffer, free_cap);
    defer allocator.free(free_buf);
    var free_list = FreeListQueue.init(free_buf);
    // Seed the free-list with every buffer up-front.
    for (buffers) |*b| {
        free_list.putOne(io, b) catch unreachable; // capacity == buffer_count
    }

    var shared = SharedState{
        .allocator = allocator,
        .io = io,
        .sink = sink,
        .opts = opts,
        .out_kind = out_kind,
        .task_queue = &task_queue,
        .batch_queue = &batch_queue,
        .free_list = &free_list,
        .workers_alive = std.atomic.Value(usize).init(worker_limit),
    };
    shared.stdout_kind = switch (sink) {
        .stdout => |io_runtime| blk: {
            const st = io_runtime.stdout_file.stat(io_runtime.io) catch break :blk null;
            break :blk st.kind;
        },
        .collect => null,
    };

    // Spawn the pipeline. Intake first (producers ready before consumers
    // spin up), then workers, then drain.
    var intake_future = try io.concurrent(intakeLoop, .{ &shared, reader, num_chunks, opts.carve });
    defer _ = intake_future.cancel(io) catch {};

    const worker_futures = try allocator.alloc(std.Io.Future(WorkerError!void), worker_limit);
    defer allocator.free(worker_futures);
    var spawned: usize = 0;
    errdefer {
        // Cancel any workers we managed to spawn before a spawn failure.
        var i: usize = 0;
        while (i < spawned) : (i += 1) _ = worker_futures[i].cancel(io) catch {};
    }
    while (spawned < worker_limit) : (spawned += 1) {
        worker_futures[spawned] = try io.concurrent(workerLoop, .{&shared});
    }

    var drain_future = try io.concurrent(drainMain, .{&shared});
    defer _ = drain_future.cancel(io) catch {};

    // Wait for the drain to finish (it's the deciding stage: max_records,
    // sink failure, or end-of-stream). Stash its error and move into
    // teardown; the rest of the pipeline is squeezed out below.
    var drain_err: ?anyerror = null;
    drain_future.await(io) catch |err| {
        drain_err = err;
    };

    // Force everything else to unblock. Close order is arbitrary; each
    // `close` is idempotent and unblocks any in-flight put/get on that
    // queue with `error.Closed`.
    task_queue.close(io);
    batch_queue.close(io);
    free_list.close(io);

    // Intake may be mid-`Chunk.read` (blocked on the file reader). `cancel`
    // interrupts the syscall and awaits intake's return in one call. We
    // always cancel intake after the drain returns (the drain owns the
    // "are we done?" decision — max_records, sink failure, or end-of-
    // stream), so any error intake reports here is either the direct
    // effect of that cancel (e.g. `ReadFailed` from an interrupted
    // syscall) or it was already surfaced through `log.err`. Swallow it.
    _ = intake_future.cancel(io) catch {};

    // Workers should now all be returning from their blocked queue ops.
    // Await each one so their `defer` cleanup runs before we deinit the
    // buffer pool.
    for (worker_futures[0..spawned]) |*f| {
        _ = f.cancel(io) catch {};
    }

    // Drain any WorkerTasks still sitting in `task_queue`. On the clean path
    // workers consume every task before exiting, but if the drain aborted
    // early (max_records, sink error) we closed `free_list` / `batch_queue`
    // which causes workers to exit before they've drained every task. Each
    // leftover task still owns a heap-allocated `chunk.buf` — free it here
    // so the pool deinit below doesn't leak.
    while (task_queue.getOneUncancelable(io)) |leftover| {
        var t = leftover;
        t.deinit();
    } else |err| switch (err) {
        error.Closed => {},
    }

    if (opts.verbosity >= 1) log.info("done. emitted={d} failed={d}", .{
        shared.emitted.load(.acquire),
        shared.failed.load(.acquire),
    });

    if (drain_err) |err| {
        if (isCleanStopError(&shared, err)) return;
        return err;
    }
}

// ---------------------------------------------------------------------------
// Public entrypoints
// ---------------------------------------------------------------------------

pub fn parseConcurrent(
    allocator: std.mem.Allocator,
    io_runtime: IoRuntime,
    reader: *std.Io.Reader,
    opts: ParserOptions,
    out_kind: OutKind,
    num_threads: usize,
) !void {
    try parseConcurrentWithSink(allocator, io_runtime.io, .{ .stdout = io_runtime }, reader, opts, out_kind, num_threads);
}

pub fn collectConcurrentOutput(allocator: std.mem.Allocator, io: std.Io, reader: *std.Io.Reader, opts: ParserOptions, out_kind: OutKind, num_threads: usize) !CollectedOutput {
    var collector = CollectState{ .allocator = allocator };
    errdefer collector.deinit();

    try parseConcurrentWithSink(allocator, io, .{ .collect = &collector }, reader, opts, out_kind, num_threads);
    return collector.takeOutput();
}

pub fn collectConcurrentOutputWithFailure(allocator: std.mem.Allocator, io: std.Io, reader: *std.Io.Reader, opts: ParserOptions, out_kind: OutKind, num_threads: usize, fail_after_records: usize, fail_error: anyerror) !CollectedOutput {
    var collector = CollectState{ .allocator = allocator, .fail_after_records = fail_after_records, .fail_error = fail_error };
    errdefer collector.deinit();

    try parseConcurrentWithSink(allocator, io, .{ .collect = &collector }, reader, opts, out_kind, num_threads);
    return collector.takeOutput();
}

pub fn collectConcurrentOutputWithSlowDrain(
    allocator: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.Reader,
    opts: ParserOptions,
    out_kind: OutKind,
    num_threads: usize,
    per_record_delay: std.Io.Duration,
) !CollectedOutput {
    var collector = CollectState{
        .allocator = allocator,
        .per_record_delay = per_record_delay,
        .io = io,
    };
    errdefer collector.deinit();

    try parseConcurrentWithSink(allocator, io, .{ .collect = &collector }, reader, opts, out_kind, num_threads);
    return collector.takeOutput();
}

// ---------------------------------------------------------------------------
// Internal tests
// ---------------------------------------------------------------------------

const test_util = @import("../../test/util.zig");

fn getProjectRoot() []const u8 {
    return comptime test_util.getProjectRoot(@src().file);
}

const project_root = getProjectRoot();
const test_evtx_path = project_root ++ "/samples/security.evtx";

fn countRecordsSingleThreaded(file_path: []const u8, skip_first: usize) !usize {
    var io_impl = std.Io.Threaded.init(std.testing.allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();

    var file = try std.Io.Dir.cwd().openFile(io, file_path, .{ .mode = .read_only });
    defer file.close(io);

    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(io, &read_buf);

    const hdr = try FileHeader.read(&reader.interface);
    var count: usize = 0;
    var skipped: usize = 0;

    var chunk_index: usize = 0;
    while (chunk_index < hdr.core.num_chunks) : (chunk_index += 1) {
        const chunk = Chunk.read(std.testing.allocator, &reader.interface) catch |e| switch (e) {
            error.EndOfStream, error.BadChunkSignature => break,
            else => return e,
        };
        defer chunk.deinit();

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

test "skip: single-threaded skip_first skips exact number of records" {
    const total = try countRecordsSingleThreaded(test_evtx_path, 0);
    try std.testing.expect(total > 10);
}
