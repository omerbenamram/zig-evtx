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

fn openSample(io: std.Io) !std.Io.File {
    return std.Io.Dir.cwd().openFile(io, sample_path, .{ .mode = .read_only });
}

fn withSampleReader(allocator: std.mem.Allocator, func: anytype) @typeInfo(@TypeOf(func)).@"fn".return_type.? {
    var io_impl = std.Io.Threaded.init(allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();

    var file = try openSample(io);
    defer file.close(io);

    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    return func(&reader);
}

fn parseSequentialOutput(allocator: std.mem.Allocator, opts: evtx.ParserOptions, mode: evtx.OutputMode) !ParsedOutput {
    const Runner = struct {
        fn run(reader: anytype) !ParsedOutput {
            const hdr = try evtx.worker.FileHeader.read(reader);
            var collector = LogicalRecordCollector{ .allocator = allocator };
            errdefer collector.deinit();
            var skipped: usize = 0;

            var chunk_index: usize = 0;
            while (chunk_index < hdr.core.num_chunks) : (chunk_index += 1) {
                const chunk = evtx.worker.Chunk.read(reader) catch |err| switch (err) {
                    error.EndOfStream, error.BadChunkSignature => break,
                    else => return err,
                };

                var out = try evtx.OutputWriter.initSerializeOnly(allocator, mode);
                defer out.deinit();
                var ctx = evtx.Context.init(allocator);
                defer ctx.deinit();

                var mutable_chunk = chunk;
                ctx.resetPerChunk();
                try ctx.preCacheFromChunkHeader(&mutable_chunk.buf, &mutable_chunk.header.common_string_offsets);

                var rec_iter = mutable_chunk.records();
                while (try rec_iter.next()) |rec| {
                    if (opts.skip_first > 0 and skipped < opts.skip_first) {
                        skipped += 1;
                        continue;
                    }
                    const emitted_count = collector.records.items.len;
                    if (opts.max_records != 0 and emitted_count >= opts.max_records) return collector.takeOutput();

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

    return withSampleReader(allocator, Runner.run);
}

fn collectConcurrentOutput(allocator: std.mem.Allocator, opts: evtx.ParserOptions, num_threads: usize) !evtx.worker.CollectedOutput {
    const Runner = struct {
        fn run(reader: anytype) !evtx.worker.CollectedOutput {
            var parser = evtx.EvtxParser.init(allocator, opts);
            return try parser.collectConcurrent(reader, .xml, num_threads);
        }
    };

    return withSampleReader(allocator, Runner.run);
}

fn collectConcurrentOutputWithFailure(allocator: std.mem.Allocator, opts: evtx.ParserOptions, num_threads: usize, fail_after_records: usize, fail_error: anyerror) !evtx.worker.CollectedOutput {
    const Runner = struct {
        fn run(reader: anytype) !evtx.worker.CollectedOutput {
            var parser = evtx.EvtxParser.init(allocator, opts);
            return try parser.collectConcurrentWithFailure(reader, .xml, num_threads, fail_after_records, fail_error);
        }
    };

    return withSampleReader(allocator, Runner.run);
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

    try std.testing.expectEqual(sequential.records.items.len, concurrent.records.items.len);
    for (sequential.records.items, concurrent.records.items) |seq, conc| {
        try std.testing.expectEqual(seq.identifier, conc.identifier);
        try std.testing.expectEqualStrings(seq.bytes, conc.bytes);
    }
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
    var concurrent = try collectConcurrentOutput(allocator, opts, 1);
    defer concurrent.deinit();

    try std.testing.expectEqual(sequential.records.items.len, concurrent.records.items.len);
    for (sequential.records.items, concurrent.records.items) |seq, conc| {
        try std.testing.expectEqual(seq.identifier, conc.identifier);
        try std.testing.expectEqualStrings(seq.bytes, conc.bytes);
    }
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
}
