const std = @import("std");
const evtx = @import("../parser/evtx/mod.zig");
const test_util = @import("util.zig");

const project_root = test_util.getProjectRoot("src/test/concurrency_tests.zig");
const sample_path = project_root ++ "/samples/security.evtx";

const ParsedRecord = struct {
    identifier: u64,
    bytes: []u8,
};

const ParsedOutput = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayList(ParsedRecord) = .empty,

    fn deinit(self: *ParsedOutput) void {
        for (self.records.items) |*record| self.allocator.free(record.bytes);
        self.records.deinit(self.allocator);
    }
};

fn openSample(io: std.Io) !std.Io.File {
    return std.Io.Dir.cwd().openFile(io, sample_path, .{ .mode = .read_only });
}

fn parseRecordId(line: []const u8) !u64 {
    const needle = "<EventRecordID>";
    const start = std.mem.indexOf(u8, line, needle) orelse return error.MissingEventRecordID;
    const id_start = start + needle.len;
    const end_rel = std.mem.indexOfScalar(u8, line[id_start..], '<') orelse return error.MissingEventRecordID;
    return std.fmt.parseUnsigned(u64, line[id_start .. id_start + end_rel], 10);
}

fn parseSequentialOutput(allocator: std.mem.Allocator, opts: evtx.ParserOptions, mode: evtx.OutputMode) !ParsedOutput {
    var io_impl = std.Io.Threaded.init(allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();

    var file = try openSample(io);
    defer file.close(io);

    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(io, &read_buf);

    var parser = evtx.EvtxParser.init(allocator, opts);
    var out = try evtx.OutputWriter.initSerializeOnly(allocator, mode);
    defer out.deinit();
    try parser.parse(&reader, &out);

    var parsed = ParsedOutput{ .allocator = allocator };
    errdefer parsed.deinit();

    var lines = std.mem.tokenizeScalar(u8, out.scratch.written(), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const duped = try allocator.dupe(u8, line);
        errdefer allocator.free(duped);
        try parsed.records.append(allocator, .{
            .identifier = try parseRecordId(line),
            .bytes = duped,
        });
    }

    return parsed;
}

fn collectConcurrentOutput(allocator: std.mem.Allocator, opts: evtx.ParserOptions, num_threads: usize) !evtx.worker.CollectedOutput {
    var file = try openSample();
    defer file.close();

    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(&read_buf);

    var parser = evtx.EvtxParser.init(allocator, opts);
    return try parser.collectConcurrent(&reader, .xml, num_threads);
}

fn collectConcurrentOutputWithFailure(allocator: std.mem.Allocator, opts: evtx.ParserOptions, num_threads: usize, fail_after_records: usize, fail_error: anyerror) !evtx.worker.CollectedOutput {
    var file = try openSample();
    defer file.close();

    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(&read_buf);

    var parser = evtx.EvtxParser.init(allocator, opts);
    return try parser.collectConcurrentWithFailure(&reader, .xml, num_threads, fail_after_records, fail_error);
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
    var concurrent = try collectConcurrentOutput(allocator, opts, 4);
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
