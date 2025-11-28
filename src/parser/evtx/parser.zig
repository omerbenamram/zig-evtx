//! Core EVTX parser with sequential and concurrent parsing.

const std = @import("std");
const binxml = @import("../binxml/mod.zig");
const logger = @import("../../logger.zig");
const log = logger.scoped("evtx");

const format = @import("format.zig");
const worker = @import("worker.zig");

pub const FileHeader = format.FileHeader;
pub const Chunk = format.Chunk;
pub const EventRecordView = format.EventRecordView;

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
};

pub const EvtxParser = struct {
    allocator: std.mem.Allocator,
    opts: ParserOptions,

    pub const OutKind = worker.OutKind;

    pub fn init(allocator: std.mem.Allocator, opts: ParserOptions) !EvtxParser {
        return .{ .allocator = allocator, .opts = opts };
    }

    pub fn deinit(self: *EvtxParser) void {
        _ = self;
    }

    pub fn parse(self: *EvtxParser, reader: anytype, out: anytype) !void {
        // Configure logging levels per verbosity
        switch (self.opts.verbosity) {
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
        if (self.opts.validate_checksums) try hdr.validateChecksum();

        var chunk_index: usize = 0;
        var emitted: usize = 0;
        var skipped: usize = 0;
        var failed: usize = 0;
        var ctx = try binxml.Context.init(self.allocator);
        defer ctx.deinit();
        // We need a mutable output to retain and reuse scratch capacity across records
        var out_mut = out;
        while (chunk_index < hdr.num_chunks) : (chunk_index += 1) {
            var chunk = try Chunk.read(reader);
            if (self.opts.verbosity >= 1) log.info("chunk {d}: free_off=0x{x}, last_rec_off=0x{x}", .{ chunk_index, chunk.header.free_space_offset, chunk.header.last_event_record_offset });
            if (self.opts.validate_checksums) try chunk.validateChecksums();
            ctx.resetPerChunk();
            // Pre-cache common strings from chunk header for faster lookups
            ctx.preCacheFromChunkHeader(&chunk.buf, &chunk.header.common_string_offsets);
            // Only enable deepest renderer-specific traces at -vvv
            ctx.verbose = (self.opts.verbosity >= 3);
            // Provide output with reusable context for this chunk
            if (@hasDecl(@TypeOf(out_mut.*), "setContext")) {
                out_mut.setContext(&ctx);
            }
            var rec_iter = chunk.records();
            var selected_including_skips: usize = 0;
            while (try rec_iter.next()) |rec| {
                if (self.opts.verbosity >= 2) log.debug("record id={d} time={d}", .{ rec.identifier, rec.written_time });
                // Skip initial records if requested
                if (self.opts.skip_first > 0 and skipped < self.opts.skip_first) {
                    skipped += 1;
                    continue;
                }
                selected_including_skips += 1;
                const view = EventRecordView{ .id = rec.identifier, .timestamp_filetime = rec.written_time, .raw_xml = rec.binxml, .chunk_buf = rec.chunk_buf };
                out_mut.writeRecord(view) catch |e| {
                    failed += 1;
                    log.err("record id={d} parse error: {s}", .{ rec.identifier, @errorName(e) });
                    // If isolating with skip_first, respect -n even when the selected record fails
                    if (self.opts.max_records != 0 and self.opts.skip_first > 0 and selected_including_skips >= self.opts.max_records) {
                        return;
                    }
                    continue; // keep going to inspect later records and compare outputs
                };
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

    /// Concurrent parsing entry point: read chunks sequentially, parse in a thread pool, and stream outputs to stdout.
    pub fn parseConcurrent(self: *EvtxParser, reader: anytype, out_kind: OutKind, num_threads: usize) !void {
        try worker.parseConcurrent(
            self.allocator,
            reader,
            .{
                .validate_checksums = self.opts.validate_checksums,
                .verbosity = self.opts.verbosity,
                .max_records = self.opts.max_records,
                .skip_first = self.opts.skip_first,
            },
            out_kind,
            num_threads,
        );
    }
};
