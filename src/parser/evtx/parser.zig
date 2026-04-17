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

pub const ParserOptions = struct {
    validate_checksums: bool = true,
    // Verbosity levels:
    // 0 = warnings+errors only (default)
    // 1 = info
    // 2 = debug
    // 3+ = trace
    verbosity: u8 = 0,
    // 0 means no limit
    max_records: usize = 0,
    // number of records to skip before emitting any output
    skip_first: usize = 0,
    // When true, scan all valid chunks until EOF instead of trusting header's num_chunks.
    // Useful for files with corrupted headers or for carving chunks from disk images.
    carve: bool = false,
    // When true (default), output chunks in original order. Slightly slower but deterministic.
    // When false, chunks output in whatever order they complete (faster but non-deterministic).
    ordered: bool = true,
};

pub const EvtxParser = struct {
    allocator: std.mem.Allocator,
    opts: ParserOptions,

    pub const OutKind = output.OutputMode;

    pub fn init(allocator: std.mem.Allocator, opts: ParserOptions) EvtxParser {
        return .{ .allocator = allocator, .opts = opts };
    }

    pub fn parse(self: *EvtxParser, reader: anytype, out: anytype) !void {
        runtime.configureVerbosity(self.opts.verbosity);
        const hdr: FileHeader = try FileHeader.read(reader);

        var chunk_index: usize = 0;
        var emitted: usize = 0;
        var skipped: usize = 0;
        var selected_including_skips: usize = 0;
        var failed: usize = 0;
        var ctx = binxml.Context.init(self.allocator);
        defer ctx.deinit();
        // We need a mutable output to retain and reuse scratch capacity across records
        var out_mut = out;
        // In carve mode, scan all valid chunks until EOF or invalid signature.
        // Otherwise, trust the header's num_chunks field.
        while (self.opts.carve or chunk_index < hdr.core.num_chunks) : (chunk_index += 1) {
            const chunk = Chunk.read(reader) catch |e| switch (e) {
                error.EndOfStream, error.BadChunkSignature => break,
                else => return e,
            };
            if (self.opts.verbosity >= 1) log.info("chunk {d}: free_off=0x{x}, last_rec_off=0x{x}", .{ chunk_index, chunk.header.free_space_offset, chunk.header.last_event_record_offset });
            if (self.opts.validate_checksums) try chunk.validateChecksums();
            ctx.resetPerChunk();
            // Pre-cache common strings from chunk header for faster lookups
            try ctx.preCacheFromChunkHeader(&chunk.buf, &chunk.header.common_string_offsets);
            var rec_iter = chunk.records();
            while (try rec_iter.next()) |rec| {
                if (self.opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
                // Skip initial records if requested
                if (self.opts.skip_first > 0 and skipped < self.opts.skip_first) {
                    skipped += 1;
                    continue;
                }
                selected_including_skips += 1;
                const bytes = out_mut.serializeRecord(rec, &ctx) catch |e| {
                    failed += 1;
                    log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                    // If isolating with skip_first, respect -n even when the selected record fails
                    if (self.opts.max_records != 0 and self.opts.skip_first > 0 and selected_including_skips >= self.opts.max_records) {
                        return;
                    }
                    continue; // keep going to inspect later records and compare outputs
                };
                try out_mut.writeSerialized(bytes);
                emitted += 1;
                if (self.opts.max_records != 0) {
                    if (self.opts.skip_first > 0) {
                        if (selected_including_skips >= self.opts.max_records) return;
                    } else {
                        if (emitted >= self.opts.max_records) return;
                    }
                }
            }
        }
        if (self.opts.verbosity >= 1) log.info("done. emitted={d} failed={d}", .{ emitted, failed });
    }

    /// Concurrent parsing entry point: read chunks sequentially, parse in a thread pool, and stream outputs to the provided sink.
    pub fn parseConcurrent(self: *EvtxParser, io_runtime: worker.IoRuntime, reader: anytype, out_kind: OutKind, num_threads: usize) !void {
        try worker.parseConcurrent(self.allocator, io_runtime, reader, self.opts, out_kind, num_threads);
    }

    pub fn collectConcurrent(self: *EvtxParser, reader: anytype, out_kind: OutKind, num_threads: usize) !worker.CollectedOutput {
        return try worker.collectConcurrentOutput(self.allocator, reader, self.opts, out_kind, num_threads);
    }

    pub fn collectConcurrentWithFailure(self: *EvtxParser, reader: anytype, out_kind: OutKind, num_threads: usize, fail_after_records: usize, fail_error: anyerror) !worker.CollectedOutput {
        return try worker.collectConcurrentOutputWithFailure(self.allocator, reader, self.opts, out_kind, num_threads, fail_after_records, fail_error);
    }
};
