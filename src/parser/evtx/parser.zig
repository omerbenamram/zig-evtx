//! Core EVTX parser with sequential and concurrent parsing.

const std = @import("std");
const binxml = @import("../binxml/mod.zig");
const logger = @import("../../logger.zig");
const log = logger.scoped("evtx");
const runtime = @import("../../runtime.zig");

const format = @import("format.zig");
const worker = @import("worker.zig");
const output = @import("output.zig");

pub const FileHeader = format.FileHeader;
pub const Chunk = format.Chunk;
pub const OutKind = output.OutputMode;

/// Policy controlling what happens when serializing a single record fails.
///
/// Both the sequential and concurrent paths consult this policy; keeping
/// the decision explicit (rather than implicit `catch continue`) makes the
/// intent visible at the call site and lets tests dial fail-fast on or off.
pub const ErrorPolicy = enum {
    /// Skip the failing record, log it, and keep parsing. This matches
    /// the historical behavior — useful for forensics where a partial
    /// dump beats no dump at all.
    continue_with_log,

    /// Surface the first failure to the caller. The parse function
    /// returns the error from `serializeRecord` immediately.
    fail_fast,
};

/// Configuration for `EvtxParser`. The fields are grouped by concern so
/// each axis can be reasoned about independently:
///
/// - **Parse behavior** (`validate_checksums`, `carve`) governs how the
///   parser reads chunks and whether it trusts header integrity.
/// - **Error handling** (`on_record_error`) decides whether per-record
///   serialization failures are skipped or propagated.
/// - **Selection** (`skip_first`, `max_records`) controls which subset of
///   records is emitted.
/// - **Concurrency** (`ordered`) controls the concurrent worker mode; it
///   has no effect on the single-threaded path.
/// - **Logging** (`verbosity`) is a convenience shortcut for the logger
///   level; callers can configure the `logger` module directly instead
///   (see `runtime.configureVerbosity` and the `EVTX_LOG_*` env vars).
pub const ParserOptions = struct {
    // -- Parse behavior --

    /// When true (default), verify chunk header and events CRC32 sums.
    validate_checksums: bool = true,

    /// When true, enable dirty-file tolerance:
    ///   1. scan every chunk-sized window until EOF instead of capping at
    ///      the file header's `num_chunks`,
    ///   2. skip past chunks whose `ElfChnk\x00` magic is missing or
    ///      corrupted instead of stopping on the first one,
    ///   3. trust record headers' `size` field even if the trailing
    ///      size-repeat (last 4 bytes of the record, used for
    ///      self-synchronisation by the spec) disagrees.
    ///
    /// Default is `false` — strict, spec-conformant parsing. `--carve`
    /// matches the Rust `evtx` crate's default tolerance and is what you
    /// want for forensic / recovery work on dirty or partially corrupted
    /// files.
    carve: bool = false,

    // -- Error handling --

    /// What to do when a single record fails to serialize. Defaults to
    /// `continue_with_log`, preserving the historical behavior.
    on_record_error: ErrorPolicy = .continue_with_log,

    // -- Selection --

    /// Stop after emitting this many records. 0 means "no limit".
    max_records: usize = 0,

    /// Number of records to skip before emitting any output.
    skip_first: usize = 0,

    // -- Concurrency (concurrent path only) --

    /// When true (default), concurrent workers publish records in file
    /// order (deterministic). When false, records stream in completion
    /// order — faster but non-deterministic.
    ordered: bool = true,

    // -- Logging --

    /// 0 = warnings+errors only (default), 1 = info, 2 = debug, 3+ = trace.
    verbosity: u8 = 0,
};

pub const EvtxParser = struct {
    allocator: std.mem.Allocator,
    opts: ParserOptions,

    pub fn init(allocator: std.mem.Allocator, opts: ParserOptions) EvtxParser {
        return .{ .allocator = allocator, .opts = opts };
    }

    /// Sequential parse: reads records and hands each `(identifier, bytes)`
    /// pair to `sink.emit`. `serializer` owns the scratch buffer; its slice
    /// is only valid until the next `serializeRecord` call, so sinks that
    /// need to retain the bytes must copy them.
    ///
    /// Selection (`skip_first` / `max_records`) is driven by the same
    /// `worker.RecordFilter` the concurrent workers use, so the semantics
    /// of both paths stay in lock-step.
    pub fn parse(self: *EvtxParser, reader: *std.Io.Reader, serializer: *output.Serializer, sink: anytype) !void {
        runtime.configureVerbosity(self.opts.verbosity);
        const hdr: FileHeader = try FileHeader.read(reader);

        var ctx = binxml.Context.init(self.allocator);
        defer ctx.deinit();

        var filter = worker.RecordFilter.forSequential(self.opts);
        var chunk_index: usize = 0;
        var emitted: usize = 0;
        var failed: usize = 0;

        while (self.opts.carve or chunk_index < hdr.core.num_chunks) : (chunk_index += 1) {
            const chunk = Chunk.read(self.allocator, reader) catch |e| switch (e) {
                error.EndOfStream => break,
                error.BadChunkSignature => if (self.opts.carve) continue else break,
                else => return e,
            };
            defer chunk.deinit();
            if (self.opts.verbosity >= 1) log.info("chunk {d}: free_off=0x{x}, last_rec_off=0x{x}", .{ chunk_index, chunk.header.free_space_offset, chunk.header.last_event_record_offset });
            if (self.opts.validate_checksums) try chunk.validateChecksums();
            ctx.resetPerChunk();
            try ctx.preCacheFromChunkHeader(chunk.buf, &chunk.header.common_string_offsets);

            var rec_iter = if (self.opts.carve) chunk.recordsCarve() else chunk.records();
            while (try rec_iter.next()) |rec| {
                if (self.opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
                switch (filter.acceptLocal()) {
                    .stop => return,
                    .skip => continue,
                    .take => {},
                }
                const bytes = serializer.serializeRecord(rec, &ctx) catch |e| {
                    failed += 1;
                    log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                    switch (self.opts.on_record_error) {
                        .continue_with_log => continue,
                        .fail_fast => return e,
                    }
                };
                try sink.emit(rec.identifier, bytes);
                emitted += 1;
            }
        }
        if (self.opts.verbosity >= 1) log.info("done. emitted={d} failed={d}", .{ emitted, failed });
    }

    /// Concurrent parsing entry point: read chunks sequentially, parse in a thread pool, and stream outputs to the provided sink.
    pub fn parseConcurrent(self: *EvtxParser, io_runtime: worker.IoRuntime, reader: *std.Io.Reader, out_kind: OutKind, num_threads: usize) !void {
        try worker.parseConcurrent(self.allocator, io_runtime, reader, self.opts, out_kind, num_threads);
    }

    pub fn collectConcurrent(self: *EvtxParser, io: std.Io, reader: *std.Io.Reader, out_kind: OutKind, num_threads: usize) !worker.CollectedOutput {
        return try worker.collectConcurrentOutput(self.allocator, io, reader, self.opts, out_kind, num_threads);
    }

    pub fn collectConcurrentWithFailure(self: *EvtxParser, io: std.Io, reader: *std.Io.Reader, out_kind: OutKind, num_threads: usize, fail_after_records: usize, fail_error: anyerror) !worker.CollectedOutput {
        return try worker.collectConcurrentOutputWithFailure(self.allocator, io, reader, self.opts, out_kind, num_threads, fail_after_records, fail_error);
    }

    /// Test-only: collect with an artificial per-record delay in the drain,
    /// used to exercise races between intake and drain over per-task queue
    /// ownership in ordered mode.
    pub fn collectConcurrentWithSlowDrain(
        self: *EvtxParser,
        io: std.Io,
        reader: *std.Io.Reader,
        out_kind: OutKind,
        num_threads: usize,
        per_record_delay: std.Io.Duration,
    ) !worker.CollectedOutput {
        return try worker.collectConcurrentOutputWithSlowDrain(
            self.allocator,
            io,
            reader,
            self.opts,
            out_kind,
            num_threads,
            per_record_delay,
        );
    }
};
