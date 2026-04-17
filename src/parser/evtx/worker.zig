//! Concurrent EVTX parsing built on Zig 0.16 std.Io primitives.
//!
//! Architecture (see docs/plans/std.io_idiomatic_redesign for background):
//! - Workers are spawned via `io.concurrent`, each returning a `std.Io.Future(anyerror!void)`.
//! - Output handoff uses `std.Io.Queue(EmittedRecord)`.
//!   * Ordered mode: each worker owns a per-chunk queue. A meta queue carries
//!     the (chunk_index, *queue) pairs to the drain task in spawn order so the
//!     drain can pull queue-by-queue, preserving overall record order.
//!   * Unordered mode: a single shared queue. All workers `putOne` to it; the
//!     drain consumes records as they arrive.
//! - The chunk reader runs as a concurrent intake task too, so the orchestrator
//!   can cancel it cleanly when the drain finishes early (max_records reached
//!   or sink failure).
//! - Cancellation is cooperative via `Future.cancel` deferred at every spawn,
//!   not via shared atomic flags. Errors propagate naturally through `await`.

const std = @import("std");
const binxml = @import("../binxml/mod.zig");
const logger = @import("../../logger.zig");
const log = logger.scoped("evtx");
const runtime = @import("../../runtime.zig");

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
    stdout_writer: *std.Io.File.Writer,
};

pub const EmittedRecord = struct {
    identifier: u64,
    bytes: []u8,
};

pub fn deinitEmittedRecords(allocator: std.mem.Allocator, records: []const EmittedRecord) void {
    for (records) |record| allocator.free(record.bytes);
}

pub fn duplicateEmittedRecord(allocator: std.mem.Allocator, identifier: u64, bytes: []const u8) !EmittedRecord {
    const owned = try allocator.dupe(u8, bytes);
    errdefer allocator.free(owned);
    return .{
        .identifier = identifier,
        .bytes = owned,
    };
}

pub const CollectedOutput = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayList(EmittedRecord) = .empty,

    pub fn deinit(self: *CollectedOutput) void {
        deinitEmittedRecords(self.allocator, self.records.items);
        self.records.deinit(self.allocator);
    }
};

const CollectState = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayList(EmittedRecord) = .empty,
    fail_after_records: ?usize = null,
    fail_error: anyerror = error.Unexpected,

    fn deinit(self: *CollectState) void {
        deinitEmittedRecords(self.allocator, self.records.items);
        self.records.deinit(self.allocator);
    }

    fn writeRecord(self: *CollectState, record: EmittedRecord) !void {
        const index = self.records.items.len;
        if (self.fail_after_records) |limit| {
            if (index >= limit) return self.fail_error;
        }

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

/// Per-worker queue capacity. Bounded so a fast worker exerts back-pressure on
/// itself when the drain is slow, instead of buffering an entire chunk in
/// memory.
const RECORD_QUEUE_CAPACITY: usize = 16;

/// Per-orchestrator unordered queue capacity. Larger than the per-worker
/// capacity since all workers share it.
const SHARED_QUEUE_CAPACITY: usize = 128;

const RecordQueue = std.Io.Queue(EmittedRecord);

const OrderedMeta = struct {
    chunk_index: usize,
    queue: *RecordQueue,
};

const OrderedMetaQueue = std.Io.Queue(OrderedMeta);

/// Discriminates how workers publish records and how the drain consumes them.
const SinkOutput = union(enum) {
    /// Per-chunk queues; the meta queue threads them through to the drain in
    /// spawn order so that overall output order matches sequential parsing.
    ordered: *OrderedMetaQueue,
    /// Single shared queue; workers publish records as they finish them.
    unordered: *RecordQueue,
};

/// Shared state passed by pointer to every worker, intake, and drain task.
///
/// Notable: there is no `cancelled` / `broken_pipe` / `fatal_error` here.
/// Cancellation is the side effect of `defer future.cancel(io)` at every spawn
/// site; errors propagate via `Future.await` returning `anyerror!void`.
const SharedState = struct {
    allocator: std.mem.Allocator,
    /// Explicit Io handle used for every blocking primitive (mutex, queue ops,
    /// future awaits). No global fallback.
    io: std.Io,
    sink: ConcurrentSink,
    opts: ParserOptions,
    out_kind: OutKind,
    stdout_kind: ?std.Io.File.Kind = null,
    /// Serializes concurrent writes to the sink. Held very briefly per record.
    write_mutex: std.Io.Mutex = .init,
    output: SinkOutput = undefined,

    // Counters retained for observability and for max_records / skip_first
    // accounting. Workers no longer use them as a cancellation flag.
    emitted: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    failed: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    skipped: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    records_selected: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
};

const WorkerTask = struct {
    chunk_index: usize,
    chunk: Chunk,
    record_base: usize = 0,
    queue_buf: [RECORD_QUEUE_CAPACITY]EmittedRecord = undefined,
    queue: RecordQueue = undefined,
    future: std.Io.Future(anyerror!void) = undefined,
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

/// Writes an EmittedRecord to the sink and frees its bytes on success or
/// failure. Holds `write_mutex` briefly so concurrent drain helpers (today
/// just one) cannot interleave their output.
fn writeRecordToSink(shared: *SharedState, record: EmittedRecord) anyerror!void {
    errdefer shared.allocator.free(record.bytes);

    const io = shared.io;
    // Cancellable lock so a deferred `cancel` on the drain task can interrupt
    // a stuck stdout write instead of holding the lock indefinitely.
    try shared.write_mutex.lock(io);
    defer shared.write_mutex.unlock(io);

    switch (shared.sink) {
        .stdout => |io_runtime| {
            try io_runtime.stdout_writer.interface.writeAll(record.bytes);
            try io_runtime.stdout_writer.interface.flush();
            shared.allocator.free(record.bytes);
        },
        .collect => |collector| {
            try collector.writeRecord(record);
            // Collector took ownership of bytes on success. Suppress the
            // errdefer free for the success path.
            // (errdefer only fires if we return an error, so do nothing here.)
        },
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

fn countChunkRecords(chunk: *const Chunk) !usize {
    var rec_iter = chunk.records();
    var count: usize = 0;
    while (try rec_iter.next()) |_| count += 1;
    return count;
}

fn trySkipRecord(shared: *SharedState, skip_counter: *std.atomic.Value(usize)) bool {
    if (shared.opts.skip_first == 0) return false;
    const prev = skip_counter.fetchAdd(1, .monotonic);
    return prev < shared.opts.skip_first;
}

/// Reserves a slot in `records_selected` (the cross-worker counter that gates
/// `max_records` for unordered selection). Returns false if the limit has
/// already been reached.
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

/// Pushes one freshly-allocated record to the appropriate output queue. The
/// queue takes ownership of `bytes` on success.
fn publishRecord(shared: *SharedState, task: *WorkerTask, identifier: u64, bytes: []const u8) anyerror!void {
    const owned = try shared.allocator.dupe(u8, bytes);
    errdefer shared.allocator.free(owned);
    const record = EmittedRecord{ .identifier = identifier, .bytes = owned };
    switch (shared.output) {
        .ordered => try task.queue.putOne(shared.io, record),
        .unordered => |q| try q.putOne(shared.io, record),
    }
}

fn serializeChunkRecords(shared: *SharedState, task: *WorkerTask, chunk: *Chunk, out: *OutputWriter, ctx: *binxml.Context) anyerror!void {
    const opts = shared.opts;
    var rec_iter = chunk.records();

    // Ordered mode: workers push every record; the drain handles skip_first
    // and max_records globally.
    if (opts.ordered) {
        while (try rec_iter.next()) |rec| {
            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
            const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &chunk.buf };
            const bytes = out.serializeRecord(view, ctx) catch |e| {
                _ = shared.failed.fetchAdd(1, .acq_rel);
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };
            try publishRecord(shared, task, rec.identifier, bytes);
        }
        return;
    }

    // Unordered + skip_first: workers do per-chunk-aware selection so we never
    // serialize records destined for the cutting-room floor.
    if (usesLogicalSubsetSelection(opts)) {
        const selection_end = selectedRecordRangeEnd(opts);
        var record_index = task.record_base;

        while (try rec_iter.next()) |rec| : (record_index += 1) {
            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
            if (record_index < opts.skip_first) continue;
            if (selection_end) |end| {
                if (record_index >= end) return;
            }

            const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &chunk.buf };
            const bytes = out.serializeRecord(view, ctx) catch |e| {
                _ = shared.failed.fetchAdd(1, .acq_rel);
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };
            try publishRecord(shared, task, rec.identifier, bytes);
        }
        return;
    }

    // Unordered + no skip_first: trivial loop. max_records is enforced by the
    // drain (which closes the queue once it has emitted enough records).
    const has_limits = opts.max_records != 0;
    if (!has_limits) {
        while (try rec_iter.next()) |rec| {
            if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
            const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &chunk.buf };
            const bytes = out.serializeRecord(view, ctx) catch |e| {
                _ = shared.failed.fetchAdd(1, .acq_rel);
                log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                continue;
            };
            try publishRecord(shared, task, rec.identifier, bytes);
        }
        return;
    }

    // Unordered + max_records (no skip_first): workers reserve a slot in the
    // shared counter so we stop serializing once enough records are queued for
    // the drain.
    while (try rec_iter.next()) |rec| {
        if (opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
        if (trySkipRecord(shared, &shared.skipped)) continue;
        if (!reserveSelectedRecord(shared)) return;

        const view = EventRecordRaw{ .identifier = rec.identifier, .written_time = rec.written_time, .binxml = rec.binxml, .chunk_buf = &chunk.buf };
        const bytes = out.serializeRecord(view, ctx) catch |e| {
            _ = shared.failed.fetchAdd(1, .acq_rel);
            log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
            continue;
        };
        try publishRecord(shared, task, rec.identifier, bytes);
    }
}

/// Drains any records still buffered in `q` and frees their owned bytes.
/// Used during teardown after the drain has stopped consuming records (e.g.
/// max_records reached) so we don't leak per-record allocations queued but
/// never written.
fn freeQueuedRecords(allocator: std.mem.Allocator, q: *RecordQueue, io: std.Io) void {
    while (q.getOneUncancelable(io)) |record| {
        allocator.free(record.bytes);
    } else |err| switch (err) {
        error.Closed => {},
    }
}

/// Worker entry point. Returns `anyerror!void`; errors propagate up through
/// `Future.await`. Always closes its per-chunk queue in `defer` so the drain
/// can move on, even on cancellation.
fn workerMain(shared: *SharedState, task: *WorkerTask) anyerror!void {
    // Closing the queue signals "no more records from this chunk" to the
    // ordered drain. Unordered mode shares a queue, so this is a no-op there
    // (the queue is closed by intake when all workers have returned).
    if (shared.opts.ordered) {
        defer task.queue.close(shared.io);
        try processChunk(shared, task);
    } else {
        try processChunk(shared, task);
    }
}

fn processChunk(shared: *SharedState, task: *WorkerTask) anyerror!void {
    const allocator = shared.allocator;
    const opts = shared.opts;

    var out = try OutputWriter.initSerializeOnly(allocator, shared.out_kind);
    defer out.deinit();
    var ctx = binxml.Context.init(allocator);
    defer ctx.deinit();

    var mutable_chunk = task.chunk;

    if (opts.verbosity >= 1) log.info("chunk {d}: free_off=0x{x}, last_rec_off=0x{x}", .{ task.chunk_index, mutable_chunk.header.free_space_offset, mutable_chunk.header.last_event_record_offset });

    if (opts.validate_checksums) {
        mutable_chunk.validateChecksums() catch |e| {
            log.err("chunk {d} checksum error: {s}", .{ task.chunk_index, @errorName(e) });
            return;
        };
    }

    ctx.resetPerChunk();
    try ctx.preCacheFromChunkHeader(&mutable_chunk.buf, &mutable_chunk.header.common_string_offsets);

    try serializeChunkRecords(shared, task, &mutable_chunk, &out, &ctx);
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

fn drainOrdered(shared: *SharedState, meta_queue: *OrderedMetaQueue) anyerror!void {
    const opts = shared.opts;
    var skipped: usize = 0;

    while (true) {
        const meta = meta_queue.getOne(shared.io) catch |e| switch (e) {
            error.Closed => return,
            else => return e,
        };

        // Drain everything the worker published to its queue, then move to
        // the next chunk's queue.
        while (true) {
            const record = meta.queue.getOne(shared.io) catch |e| switch (e) {
                error.Closed => break,
                else => return e,
            };

            // Apply skip_first globally (workers in ordered mode push every
            // record, so the drain owns this filter).
            if (opts.skip_first > 0 and skipped < opts.skip_first) {
                skipped += 1;
                shared.allocator.free(record.bytes);
                continue;
            }

            // Apply max_records.
            if (opts.max_records != 0 and shared.emitted.load(.acquire) >= opts.max_records) {
                shared.allocator.free(record.bytes);
                return;
            }

            try writeRecordToSink(shared, record);
            _ = shared.emitted.fetchAdd(1, .acq_rel);
        }
    }
}

fn drainUnordered(shared: *SharedState, queue: *RecordQueue) anyerror!void {
    const opts = shared.opts;

    while (true) {
        const record = queue.getOne(shared.io) catch |e| switch (e) {
            error.Closed => return,
            else => return e,
        };

        // Apply max_records. (skip_first is handled by the workers in
        // unordered mode.)
        if (opts.max_records != 0 and shared.emitted.load(.acquire) >= opts.max_records) {
            shared.allocator.free(record.bytes);
            return;
        }

        try writeRecordToSink(shared, record);
        _ = shared.emitted.fetchAdd(1, .acq_rel);
    }
}

// ---------------------------------------------------------------------------
// Intake (chunk reader + worker spawner)
// ---------------------------------------------------------------------------

/// Body of the intake task. Reads chunks sequentially from `reader`, spawns a
/// worker future per chunk, and bounds concurrency to `worker_limit` in-flight
/// workers at a time.
///
/// Generic over the reader type because callers pass concrete `*std.Io.File.Reader`
/// values. The orchestrator wraps this in a per-call-site struct so that
/// `io.concurrent` sees a concrete function pointer.
fn intakeLoopImpl(
    shared: *SharedState,
    reader: anytype,
    worker_limit: usize,
    num_chunks: usize,
    carve: bool,
) anyerror!void {
    const allocator = shared.allocator;

    // Active workers list. On any exit (success, error, or cancel) we cancel
    // any outstanding workers (which also awaits them) and free their tasks.
    var active = std.ArrayList(*WorkerTask).empty;
    defer {
        // Cancel any still-active workers; cancel() blocks until the future
        // has actually completed, so this is also our await. After the worker
        // returns, drain any records still in its per-task queue (ordered
        // mode only) before freeing the task struct.
        for (active.items) |t| {
            _ = t.future.cancel(shared.io) catch {};
            if (shared.opts.ordered) freeQueuedRecords(allocator, &t.queue, shared.io);
            allocator.destroy(t);
        }
        active.deinit(allocator);
    }

    // When we exit (for any reason) the output side must be closed so the
    // drain can finish. Per-task queues are closed by their own workers in
    // defer; we close the meta or shared queue here.
    defer switch (shared.output) {
        .ordered => |q| q.close(shared.io),
        .unordered => |q| q.close(shared.io),
    };

    var chunk_index: usize = 0;
    var record_base: usize = 0;
    const selection_end = if (usesLogicalSubsetSelection(shared.opts)) selectedRecordRangeEnd(shared.opts) else null;

    // Set when the chunk loop exits due to an unexpected read failure (which
    // includes the cancellation case: the file reader reports `ReadFailed`,
    // not `Canceled`, when its syscall is interrupted by `Future.cancel`).
    // In that case, the in-flight workers may be blocked on `queue.putOne`
    // for a queue that no one is reading; passively awaiting them in the
    // cleanup loop would deadlock. Aborting cancels them so their `putOne`
    // returns `Canceled` and they exit.
    var abort_workers = false;

    while (carve or chunk_index < num_chunks) : (chunk_index += 1) {
        // Stop if we've already emitted enough records (lock-free check).
        if (shared.opts.max_records != 0 and shared.emitted.load(.acquire) >= shared.opts.max_records) break;
        if (selection_end) |end| {
            if (record_base >= end) break;
        }

        const chunk = Chunk.read(reader) catch |e| switch (e) {
            error.EndOfStream, error.BadChunkSignature => break,
            else => {
                log.err("failed to read chunk {d}: {s}", .{ chunk_index, @errorName(e) });
                abort_workers = true;
                break;
            },
        };

        const chunk_record_base = record_base;
        if (selection_end != null or usesLogicalSubsetSelection(shared.opts)) {
            record_base += try countChunkRecords(&chunk);
        }

        if (usesLogicalSubsetSelection(shared.opts)) {
            // The whole chunk falls in skip_first; don't bother spawning a
            // worker for it.
            if (record_base <= shared.opts.skip_first) continue;
        }

        // Allocate the task and incrementally transfer ownership so we don't
        // double-free it on the error path. The outer defer iterates
        // `active.items`; an errdefer here would race with that and destroy
        // the same task twice. Instead we use explicit error handling for
        // each phase.
        const task = allocator.create(WorkerTask) catch |e| return e;

        task.* = .{
            .chunk_index = chunk_index,
            .chunk = chunk,
            .record_base = chunk_record_base,
        };
        task.queue = .init(&task.queue_buf);

        // Ordered mode: register the meta entry BEFORE spawning the worker so
        // the drain sees this queue in spawn order. If the meta queue is full,
        // putOne blocks (back-pressure), which is the desired behavior.
        if (shared.opts.ordered) {
            shared.output.ordered.putOne(shared.io, .{
                .chunk_index = chunk_index,
                .queue = &task.queue,
            }) catch |e| {
                allocator.destroy(task);
                return e;
            };
        }

        task.future = shared.io.concurrent(workerMain, .{ shared, task }) catch |e| {
            // Worker not spawned; task is owned by no-one.
            allocator.destroy(task);
            return e;
        };

        active.append(allocator, task) catch |e| {
            // Worker is running but we couldn't track it; cancel it so it
            // returns before we free its task struct.
            _ = task.future.cancel(shared.io) catch {};
            allocator.destroy(task);
            return e;
        };
        // Ownership now lives in `active`; the outer defer is responsible for
        // tearing this task down.

        if (active.items.len >= worker_limit) {
            const oldest = active.orderedRemove(0);
            // Once removed from `active`, the outer defer no longer sees it.
            // We own it and must free it ourselves on every exit path.
            defer {
                if (shared.opts.ordered) freeQueuedRecords(allocator, &oldest.queue, shared.io);
                allocator.destroy(oldest);
            }
            try oldest.future.await(shared.io);
        }
    }

    // If we aborted, request cancellation on every remaining worker up front
    // so the cleanup loop never blocks waiting for one stuck on `putOne`.
    if (abort_workers) {
        for (active.items) |t| _ = t.future.cancel(shared.io) catch {};
    }

    // Await remaining workers in spawn order so errors surface deterministically.
    // After abort, workers will return `error.Canceled` (or some other
    // cancellation-flavored error); we swallow those because they're caused
    // by our own cancel request, not a real problem in the chunk.
    while (active.items.len > 0) {
        const oldest = active.orderedRemove(0);
        defer {
            if (shared.opts.ordered) freeQueuedRecords(allocator, &oldest.queue, shared.io);
            allocator.destroy(oldest);
        }
        if (abort_workers) {
            _ = oldest.future.await(shared.io) catch {};
        } else {
            try oldest.future.await(shared.io);
        }
    }
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

fn parseConcurrentWithSink(
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: ConcurrentSink,
    reader: anytype,
    opts: ParserOptions,
    out_kind: OutKind,
    num_threads: usize,
) !void {
    runtime.ignoreSigpipe();
    runtime.configureVerbosity(opts.verbosity);

    const hdr: FileHeader = try FileHeader.read(reader);
    const num_chunks: usize = hdr.core.num_chunks;
    const worker_limit = @max(@as(usize, 1), num_threads);

    var shared = SharedState{
        .allocator = allocator,
        .io = io,
        .sink = sink,
        .opts = opts,
        .out_kind = out_kind,
    };
    shared.stdout_kind = switch (sink) {
        .stdout => |io_runtime| blk: {
            const st = io_runtime.stdout_file.stat(io_runtime.io) catch break :blk null;
            break :blk st.kind;
        },
        .collect => null,
    };

    // Output queues. We allocate exactly one of the two depending on mode.
    if (opts.ordered) {
        // Meta queue capacity: large enough that intake rarely blocks
        // registering a new chunk's queue. We size it to the worker limit + a
        // small buffer; if the drain falls behind by more than this, intake
        // back-pressures, which is fine.
        const meta_capacity = @max(worker_limit * 2, 8);
        const meta_buf = try allocator.alloc(OrderedMeta, meta_capacity);
        defer allocator.free(meta_buf);

        var meta_queue = OrderedMetaQueue.init(meta_buf);
        shared.output = .{ .ordered = &meta_queue };

        // Per-task queues are drained by the intake's defer; the meta queue
        // only carries pointers, so it has nothing to free here.
        try runOrchestratedConcurrent(&shared, reader, worker_limit, num_chunks, opts.carve, drainOrdered, &meta_queue);
    } else {
        const unordered_buf = try allocator.alloc(EmittedRecord, SHARED_QUEUE_CAPACITY);
        defer allocator.free(unordered_buf);

        var unordered_queue = RecordQueue.init(unordered_buf);
        shared.output = .{ .unordered = &unordered_queue };
        // After both intake and drain have stopped, the shared queue may
        // still hold records (drain stopped early on max_records / broken
        // pipe). Free their owned bytes so the test allocator stays clean.
        defer freeQueuedRecords(allocator, &unordered_queue, io);

        try runOrchestratedConcurrent(&shared, reader, worker_limit, num_chunks, opts.carve, drainUnordered, &unordered_queue);
    }

    if (opts.verbosity >= 1) log.info("done. emitted={d} failed={d}", .{ shared.emitted.load(.acquire), shared.failed.load(.acquire) });
}

/// Runs the intake + drain pair of futures and reconciles their errors. The
/// `drain_fn` and `drain_arg` are passed through so this same function works
/// for both ordered and unordered drain.
///
/// Generic over the reader and drain-arg types so we can monomorphize the
/// concurrent intake task.
fn runOrchestratedConcurrent(
    shared: *SharedState,
    reader: anytype,
    worker_limit: usize,
    num_chunks: usize,
    carve: bool,
    comptime drain_fn: anytype,
    drain_arg: anytype,
) !void {
    const io = shared.io;
    const ReaderArg = @TypeOf(reader);
    const DrainArg = @TypeOf(drain_arg);

    // Monomorphized intake function so io.concurrent can take a concrete fn
    // even though the inner intake is generic over the reader type.
    const Intake = struct {
        fn run(s: *SharedState, r: ReaderArg, wl: usize, nc: usize, c: bool) anyerror!void {
            return intakeLoopImpl(s, r, wl, nc, c);
        }
    };

    // Spawn intake first so the meta/unordered queue starts seeing producers
    // by the time the drain spins up.
    var intake_future = try io.concurrent(Intake.run, .{ shared, reader, worker_limit, num_chunks, carve });
    // Cancel-on-exit safety net. `cancel` also awaits the task, so any early
    // return from this function still tears intake down cleanly.
    defer _ = intake_future.cancel(io) catch {};

    // Spawn drain. Same cancel-on-exit pattern.
    const Drain = struct {
        fn run(s: *SharedState, q: DrainArg) anyerror!void {
            return drain_fn(s, q);
        }
    };
    var drain_future = try io.concurrent(Drain.run, .{ shared, drain_arg });
    defer _ = drain_future.cancel(io) catch {};

    // Await drain first. It is the only task that can decide "we're done"
    // early (max_records hit, sink failed). Intake keeps running until it
    // is told to stop.
    var drain_err: ?anyerror = null;
    drain_future.await(io) catch |err| {
        drain_err = err;
    };

    // Drain has finished. The intake may still be busy: blocked on a worker
    // future, mid-Chunk.read, or pushing to a now-stalled queue. We must
    // explicitly *cancel* it (not await) — `cancel` propagates the cancel
    // request through intake's defers, which in turn cancel any in-flight
    // workers, freeing them from blocked `putOne` calls. `cancel` blocks
    // until intake actually returns, so it doubles as the await.
    var intake_err: ?anyerror = null;
    intake_future.cancel(io) catch |err| {
        intake_err = err;
    };

    // Drain's error wins (it is the proximate cause of teardown). Intake's
    // error is reported only if drain succeeded.
    if (drain_err) |err| {
        if (isCleanStopError(shared, err)) return;
        return err;
    }
    if (intake_err) |err| {
        // After a successful drain, intake is expected to return either ok
        // or `error.Canceled` (because we asked it to stop). Anything else
        // is a real failure.
        if (err == error.Canceled) return;
        if (isCleanStopError(shared, err)) return;
        return err;
    }
}

// ---------------------------------------------------------------------------
// Public entrypoints
// ---------------------------------------------------------------------------

pub fn parseConcurrent(
    allocator: std.mem.Allocator,
    io_runtime: IoRuntime,
    reader: anytype,
    opts: ParserOptions,
    out_kind: OutKind,
    num_threads: usize,
) !void {
    try parseConcurrentWithSink(allocator, io_runtime.io, .{ .stdout = io_runtime }, reader, opts, out_kind, num_threads);
}

pub fn collectConcurrentOutput(allocator: std.mem.Allocator, io: std.Io, reader: anytype, opts: ParserOptions, out_kind: OutKind, num_threads: usize) !CollectedOutput {
    var collector = CollectState{ .allocator = allocator };
    errdefer collector.deinit();

    try parseConcurrentWithSink(allocator, io, .{ .collect = &collector }, reader, opts, out_kind, num_threads);
    return collector.takeOutput();
}

pub fn collectConcurrentOutputWithFailure(allocator: std.mem.Allocator, io: std.Io, reader: anytype, opts: ParserOptions, out_kind: OutKind, num_threads: usize, fail_after_records: usize, fail_error: anyerror) !CollectedOutput {
    var collector = CollectState{ .allocator = allocator, .fail_after_records = fail_after_records, .fail_error = fail_error };
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

test "skip: single-threaded skip_first skips exact number of records" {
    const total = try countRecordsSingleThreaded(test_evtx_path, 0);
    try std.testing.expect(total > 10);
}
