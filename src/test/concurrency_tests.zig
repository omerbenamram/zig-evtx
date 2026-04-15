const std = @import("std");
const evtx = @import("../parser/evtx/mod.zig");
const test_util = @import("util.zig");

const project_root = test_util.getProjectRoot("src/test/concurrency_tests.zig");
const sample_path = project_root ++ "/samples/security.evtx";

const ParsedRecord = evtx.worker.EmittedRecord;

const LogicalRecordCollector = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayList(ParsedRecord) = .empty,

    fn deinit(self: *LogicalRecordCollector) void {
        evtx.worker.deinitEmittedRecords(self.allocator, self.records.items);
        self.records.deinit(self.allocator);
    }

    fn append(self: *LogicalRecordCollector, identifier: u64, bytes: []const u8) !void {
        try self.records.append(self.allocator, try evtx.worker.duplicateEmittedRecord(self.allocator, identifier, bytes));
    }

    fn takeOutput(self: *LogicalRecordCollector) ParsedOutput {
        const records = self.records;
        self.records = .empty;
        return .{ .allocator = self.allocator, .records = records };
    }
};

const ParsedOutput = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayList(ParsedRecord) = .empty,

    fn deinit(self: *ParsedOutput) void {
        evtx.worker.deinitEmittedRecords(self.allocator, self.records.items);
        self.records.deinit(self.allocator);
    }
};

const SequentialParserCollector = struct {
    allocator: std.mem.Allocator,
    collector: LogicalRecordCollector,
    out: evtx.OutputWriter,
    pending_identifier: ?u64 = null,

    fn init(allocator: std.mem.Allocator, mode: evtx.OutputMode) !SequentialParserCollector {
        return .{
            .allocator = allocator,
            .collector = .{ .allocator = allocator },
            .out = try evtx.OutputWriter.initSerializeOnly(allocator, mode),
        };
    }

    fn deinit(self: *SequentialParserCollector) void {
        self.out.deinit();
        self.collector.deinit();
    }

    pub fn serializeRecord(self: *SequentialParserCollector, record: evtx.EventRecordRaw, ctx: *evtx.Context) ![]const u8 {
        self.pending_identifier = record.identifier;
        return self.out.serializeRecord(record, ctx);
    }

    pub fn writeSerialized(self: *SequentialParserCollector, bytes: []const u8) !void {
        const identifier = self.pending_identifier orelse unreachable;
        try self.collector.append(identifier, bytes);
    }

    fn takeOutput(self: *SequentialParserCollector) ParsedOutput {
        self.out.deinit();
        self.out = undefined;
        return self.collector.takeOutput();
    }
};

fn openSample(io: std.Io) !std.Io.File {
    return std.Io.Dir.cwd().openFile(io, sample_path, .{ .mode = .read_only });
}

fn withSampleReader(allocator: std.mem.Allocator, comptime ReturnType: type, reader_fn: anytype, context: anytype) anyerror!ReturnType {
    var io_impl = std.Io.Threaded.init(allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();

    var file = try openSample(io);
    defer file.close(io);

    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    return try @call(.auto, reader_fn, .{ context, &reader });
}

fn parseSequentialOutput(allocator: std.mem.Allocator, opts: evtx.ParserOptions, mode: evtx.OutputMode) !ParsedOutput {
    const Context = struct {
        allocator: std.mem.Allocator,
        opts: evtx.ParserOptions,
        mode: evtx.OutputMode,
    };

    const Runner = struct {
        fn run(ctx_data: Context, reader: anytype) !ParsedOutput {
            const hdr = try evtx.worker.FileHeader.read(reader);
            var collector = LogicalRecordCollector{ .allocator = ctx_data.allocator };
            errdefer collector.deinit();
            var skipped: usize = 0;

            var chunk_index: usize = 0;
            while (chunk_index < hdr.core.num_chunks) : (chunk_index += 1) {
                const chunk = evtx.worker.Chunk.read(reader) catch |err| switch (err) {
                    error.EndOfStream, error.BadChunkSignature => break,
                    else => return err,
                };

                var out = try evtx.OutputWriter.initSerializeOnly(ctx_data.allocator, ctx_data.mode);
                defer out.deinit();
                var ctx = evtx.Context.init(ctx_data.allocator);
                defer ctx.deinit();

                var mutable_chunk = chunk;
                ctx.resetPerChunk();
                try ctx.preCacheFromChunkHeader(&mutable_chunk.buf, &mutable_chunk.header.common_string_offsets);

                var rec_iter = mutable_chunk.records();
                while (try rec_iter.next()) |rec| {
                    if (ctx_data.opts.skip_first > 0 and skipped < ctx_data.opts.skip_first) {
                        skipped += 1;
                        continue;
                    }
                    const emitted_count = collector.records.items.len;
                    if (ctx_data.opts.max_records != 0 and emitted_count >= ctx_data.opts.max_records) return collector.takeOutput();

                    const view = evtx.worker.EventRecordRaw{
                        .identifier = rec.identifier,
                        .written_time = rec.written_time,
                        .binxml = rec.binxml,
                        .chunk_buf = &mutable_chunk.buf,
                    };
                    const bytes = out.serializeRecord(view, &ctx) catch continue;
                    try collector.append(rec.identifier, bytes);
                }
            }

            return collector.takeOutput();
        }
    };

    return withSampleReader(allocator, ParsedOutput, Runner.run, Context{ .allocator = allocator, .opts = opts, .mode = mode });
}

fn parseSequentialParserOutput(allocator: std.mem.Allocator, opts: evtx.ParserOptions, mode: evtx.OutputMode) !ParsedOutput {
    const Context = struct {
        allocator: std.mem.Allocator,
        opts: evtx.ParserOptions,
        mode: evtx.OutputMode,
    };

    const Runner = struct {
        fn run(ctx_data: Context, reader: anytype) !ParsedOutput {
            var parser = evtx.EvtxParser.init(ctx_data.allocator, ctx_data.opts);
            var collector = try SequentialParserCollector.init(ctx_data.allocator, ctx_data.mode);
            errdefer collector.deinit();
            try parser.parse(reader, &collector);
            return collector.takeOutput();
        }
    };

    return withSampleReader(allocator, ParsedOutput, Runner.run, Context{ .allocator = allocator, .opts = opts, .mode = mode });
}

fn collectConcurrentOutput(allocator: std.mem.Allocator, opts: evtx.ParserOptions, num_threads: usize) !evtx.worker.CollectedOutput {
    const Context = struct {
        allocator: std.mem.Allocator,
        opts: evtx.ParserOptions,
        num_threads: usize,
    };

    const Runner = struct {
        fn run(ctx_data: Context, reader: anytype) !evtx.worker.CollectedOutput {
            var parser = evtx.EvtxParser.init(ctx_data.allocator, ctx_data.opts);
            return try parser.collectConcurrent(reader, .xml, ctx_data.num_threads);
        }
    };

    return withSampleReader(allocator, evtx.worker.CollectedOutput, Runner.run, Context{ .allocator = allocator, .opts = opts, .num_threads = num_threads });
}

fn collectConcurrentOutputWithFailure(allocator: std.mem.Allocator, opts: evtx.ParserOptions, num_threads: usize, fail_after_records: usize, fail_error: anyerror) !evtx.worker.CollectedOutput {
    const Context = struct {
        allocator: std.mem.Allocator,
        opts: evtx.ParserOptions,
        num_threads: usize,
        fail_after_records: usize,
        fail_error: anyerror,
    };

    const Runner = struct {
        fn run(ctx_data: Context, reader: anytype) !evtx.worker.CollectedOutput {
            var parser = evtx.EvtxParser.init(ctx_data.allocator, ctx_data.opts);
            return try parser.collectConcurrentWithFailure(reader, .xml, ctx_data.num_threads, ctx_data.fail_after_records, ctx_data.fail_error);
        }
    };

    return withSampleReader(allocator, evtx.worker.CollectedOutput, Runner.run, Context{ .allocator = allocator, .opts = opts, .num_threads = num_threads, .fail_after_records = fail_after_records, .fail_error = fail_error });
}

fn sortCollectedById(records: []evtx.worker.EmittedRecord) void {
    std.mem.sort(evtx.worker.EmittedRecord, records, {}, struct {
        fn lessThan(_: void, lhs: evtx.worker.EmittedRecord, rhs: evtx.worker.EmittedRecord) bool {
            return lhs.identifier < rhs.identifier;
        }
    }.lessThan);
}

fn sortParsedById(records: []ParsedRecord) void {
    std.mem.sort(ParsedRecord, records, {}, struct {
        fn lessThan(_: void, lhs: ParsedRecord, rhs: ParsedRecord) bool {
            return lhs.identifier < rhs.identifier;
        }
    }.lessThan);
}

fn expectMatchingRecordSet(sequential: []ParsedRecord, concurrent: []evtx.worker.EmittedRecord) !void {
    try std.testing.expectEqual(sequential.len, concurrent.len);
    for (sequential, concurrent) |seq, conc| {
        try std.testing.expectEqual(seq.identifier, conc.identifier);
        try std.testing.expectEqualStrings(seq.bytes, conc.bytes);
    }
}

test "concurrency: ordered mode preserves sequential output equivalence" {
    const allocator = std.testing.allocator;

    var sequential = try parseSequentialOutput(allocator, .{}, .xml);
    defer sequential.deinit();

    var concurrent = try collectConcurrentOutput(allocator, .{ .ordered = true }, 4);
    defer concurrent.deinit();

    try std.testing.expectEqual(sequential.records.items.len, concurrent.records.items.len);
    for (sequential.records.items, concurrent.records.items) |seq, conc| {
        try std.testing.expectEqual(seq.identifier, conc.identifier);
        try std.testing.expectEqualStrings(seq.bytes, conc.bytes);
    }
}

test "concurrency: unordered mode emits same record set as sequential mode" {
    const allocator = std.testing.allocator;

    var sequential = try parseSequentialOutput(allocator, .{}, .xml);
    defer sequential.deinit();
    var concurrent = try collectConcurrentOutput(allocator, .{ .ordered = false }, 4);
    defer concurrent.deinit();

    sortParsedById(sequential.records.items);
    sortCollectedById(concurrent.records.items);

    try expectMatchingRecordSet(sequential.records.items, concurrent.records.items);
}

test "concurrency: skip_first and max_records match sequential selection" {
    const allocator = std.testing.allocator;
    const opts: evtx.ParserOptions = .{
        .skip_first = 3,
        .max_records = 7,
        .ordered = true,
    };

    var sequential = try parseSequentialOutput(allocator, opts, .xml);
    defer sequential.deinit();
    var concurrent = try collectConcurrentOutput(allocator, opts, 4);
    defer concurrent.deinit();

    try std.testing.expectEqual(sequential.records.items.len, concurrent.records.items.len);
    for (sequential.records.items, concurrent.records.items) |seq, conc| {
        try std.testing.expectEqual(seq.identifier, conc.identifier);
        try std.testing.expectEqualStrings(seq.bytes, conc.bytes);
    }
}

test "concurrency: unordered skip_first and max_records match sequential record subset" {
    const allocator = std.testing.allocator;
    const opts: evtx.ParserOptions = .{
        .skip_first = 3,
        .max_records = 7,
        .ordered = false,
    };

    var sequential = try parseSequentialOutput(allocator, opts, .xml);
    defer sequential.deinit();
    var concurrent = try collectConcurrentOutput(allocator, opts, 4);
    defer concurrent.deinit();

    sortParsedById(sequential.records.items);
    sortCollectedById(concurrent.records.items);

    try expectMatchingRecordSet(sequential.records.items, concurrent.records.items);
}

test "concurrency: unordered skip_first and max_records stay exact across chunk boundaries" {
    const allocator = std.testing.allocator;
    const opts: evtx.ParserOptions = .{
        .skip_first = 85,
        .max_records = 12,
        .ordered = false,
    };

    var sequential = try parseSequentialOutput(allocator, opts, .xml);
    defer sequential.deinit();
    var concurrent = try collectConcurrentOutput(allocator, opts, 4);
    defer concurrent.deinit();

    sortParsedById(sequential.records.items);
    sortCollectedById(concurrent.records.items);

    try expectMatchingRecordSet(sequential.records.items, concurrent.records.items);
}

test "concurrency: sequential skip_first and max_records stay exact across chunk boundaries" {
    const allocator = std.testing.allocator;
    const opts: evtx.ParserOptions = .{
        .skip_first = 85,
        .max_records = 12,
        .ordered = true,
    };

    var expected = try parseSequentialOutput(allocator, opts, .xml);
    defer expected.deinit();
    var actual = try parseSequentialParserOutput(allocator, opts, .xml);
    defer actual.deinit();

    try std.testing.expectEqual(expected.records.items.len, actual.records.items.len);
    for (expected.records.items, actual.records.items) |want, got| {
        try std.testing.expectEqual(want.identifier, got.identifier);
        try std.testing.expectEqualStrings(want.bytes, got.bytes);
    }
}

test "concurrency: sequential ordered and unordered agree on cross-chunk subset" {
    const allocator = std.testing.allocator;
    const opts: evtx.ParserOptions = .{
        .skip_first = 85,
        .max_records = 12,
        .ordered = true,
    };

    var sequential = try parseSequentialParserOutput(allocator, opts, .xml);
    defer sequential.deinit();
    var ordered = try collectConcurrentOutput(allocator, opts, 4);
    defer ordered.deinit();

    try std.testing.expectEqual(sequential.records.items.len, ordered.records.items.len);
    for (sequential.records.items, ordered.records.items) |seq, conc| {
        try std.testing.expectEqual(seq.identifier, conc.identifier);
        try std.testing.expectEqualStrings(seq.bytes, conc.bytes);
    }

    var unordered = try collectConcurrentOutput(allocator, .{
        .skip_first = opts.skip_first,
        .max_records = opts.max_records,
        .ordered = false,
    }, 4);
    defer unordered.deinit();

    sortParsedById(sequential.records.items);
    sortCollectedById(unordered.records.items);
    try expectMatchingRecordSet(sequential.records.items, unordered.records.items);
}

test "concurrency: cancellation after max_records stops further emission" {
    const allocator = std.testing.allocator;
    const limit: usize = 5;

    var concurrent = try collectConcurrentOutput(allocator, .{ .ordered = true, .max_records = limit }, 4);
    defer concurrent.deinit();

    try std.testing.expectEqual(limit, concurrent.records.items.len);
}

test "concurrency: broken pipe and write failures stop cleanly" {
    const allocator = std.testing.allocator;

    var broken_pipe_output = try collectConcurrentOutputWithFailure(allocator, .{ .ordered = true }, 4, 2, error.BrokenPipe);
    defer broken_pipe_output.deinit();
    try std.testing.expectEqual(@as(usize, 2), broken_pipe_output.records.items.len);

    try std.testing.expectError(error.TestSinkWriteFailed, collectConcurrentOutputWithFailure(allocator, .{ .ordered = true }, 4, 2, error.TestSinkWriteFailed));

    var unordered_broken_pipe_output = try collectConcurrentOutputWithFailure(allocator, .{ .ordered = false }, 4, 2, error.BrokenPipe);
    defer unordered_broken_pipe_output.deinit();
    try std.testing.expectEqual(@as(usize, 2), unordered_broken_pipe_output.records.items.len);

    try std.testing.expectError(error.TestSinkWriteFailed, collectConcurrentOutputWithFailure(allocator, .{ .ordered = false }, 4, 2, error.TestSinkWriteFailed));
}
