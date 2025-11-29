//! Implementation module for Python bindings.
//! This module is separated from evtx_pydust.zig to isolate the complex evtx types
//! from pydust's comptime type introspection.

const std = @import("std");
const alloc_mod = @import("alloc");

const RecordStream = @import("parser/evtx/stream.zig").RecordStream;
const EvtxParser = @import("parser/evtx/parser.zig").EvtxParser;
const OutputWriter = @import("parser/evtx/output.zig").OutputWriter;

pub const Options = struct {
    skip_first: usize = 0,
    max_records: usize = 0,
    validate_checksums: bool = true,
    verbosity: u8 = 0,
};

// Iterator state stored on heap (pointer stored in fixed buffer)
const IterState = struct {
    stream: ?*RecordStream = null,
    buf: std.ArrayList(u8) = .empty,
    infile: ?std.fs.File = null,
    read_buf: [8192]u8 = undefined,
    bytes_data: []const u8 = &[_]u8{},
    bytes_pos: usize = 0,
};

// We store a pointer to heap-allocated IterState
pub const IterStateSize = @sizeOf(*IterState);

fn getStatePtr(storage: *[IterStateSize]u8) *?*IterState {
    return @ptrCast(@alignCast(storage));
}

fn getState(storage: *[IterStateSize]u8) ?*IterState {
    return getStatePtr(storage).*;
}

fn file_read_cb(ctx_ptr: *anyopaque, buf: []u8) !void {
    const storage: *[IterStateSize]u8 = @ptrCast(@alignCast(ctx_ptr));
    const state = getState(storage) orelse return error.EndOfStream;
    const f = state.infile orelse return error.EndOfStream;
    const n = try f.readAll(buf);
    if (n < buf.len) return error.EndOfStream;
}

fn bytes_read_cb(ctx_ptr: *anyopaque, out_buf: []u8) !void {
    const storage: *[IterStateSize]u8 = @ptrCast(@alignCast(ctx_ptr));
    const state = getState(storage) orelse return error.EndOfStream;
    if (state.bytes_pos + out_buf.len > state.bytes_data.len) return error.EndOfStream;
    const src = state.bytes_data[state.bytes_pos .. state.bytes_pos + out_buf.len];
    @memcpy(out_buf, src);
    state.bytes_pos += out_buf.len;
}

pub fn initIterFromPath(
    storage: *[IterStateSize]u8,
    path: []const u8,
    format: []const u8,
    opts: Options,
) !void {
    const allocator = alloc_mod.get();

    if (!(std.mem.eql(u8, format, "xml") or std.mem.eql(u8, format, "jsonl") or std.mem.eql(u8, format, "jsonlines"))) {
        return error.InvalidFormat;
    }

    const infile = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    errdefer infile.close();

    // Allocate state on heap
    const state = try allocator.create(IterState);
    errdefer allocator.destroy(state);

    // Initialize state FIRST so the file handle is available when RecordStream reads
    state.* = .{
        .stream = null,
        .buf = .empty,
        .infile = infile,
        .read_buf = undefined,
        .bytes_data = &[_]u8{},
        .bytes_pos = 0,
    };

    // Store pointer in the storage array
    getStatePtr(storage).* = state;

    const stream = try allocator.create(RecordStream);
    errdefer allocator.destroy(stream);

    stream.* = try RecordStream.init(
        allocator,
        @ptrCast(storage),
        @ptrCast(&file_read_cb),
        .{
            .validate_checksums = opts.validate_checksums,
            .verbosity = opts.verbosity,
            .max_records = opts.max_records,
            .skip_first = opts.skip_first,
        },
        format,
    );

    state.stream = stream;
}

pub fn initIterFromBytes(
    storage: *[IterStateSize]u8,
    data: []const u8,
    format: []const u8,
    opts: Options,
) !void {
    const allocator = alloc_mod.get();

    if (!(std.mem.eql(u8, format, "xml") or std.mem.eql(u8, format, "jsonl") or std.mem.eql(u8, format, "jsonlines"))) {
        return error.InvalidFormat;
    }

    // Copy data first
    const bytes_copy = try allocator.dupe(u8, data);
    errdefer allocator.free(bytes_copy);

    // Allocate state on heap
    const state = try allocator.create(IterState);
    errdefer allocator.destroy(state);

    state.* = .{
        .stream = null,
        .buf = .empty,
        .infile = null,
        .read_buf = undefined,
        .bytes_data = bytes_copy,
        .bytes_pos = 0,
    };

    // Store pointer in the storage array
    getStatePtr(storage).* = state;

    const stream = try allocator.create(RecordStream);
    errdefer allocator.destroy(stream);

    stream.* = try RecordStream.init(
        allocator,
        @ptrCast(storage),
        @ptrCast(&bytes_read_cb),
        .{
            .validate_checksums = opts.validate_checksums,
            .verbosity = opts.verbosity,
            .max_records = opts.max_records,
            .skip_first = opts.skip_first,
        },
        format,
    );

    state.stream = stream;
}

pub fn deinitIter(storage: *[IterStateSize]u8) void {
    const allocator = alloc_mod.get();
    const state = getState(storage) orelse return;

    if (state.stream) |s| {
        s.deinit();
        allocator.destroy(s);
    }
    if (state.infile) |*f| f.close();
    state.buf.deinit(allocator);
    if (state.bytes_data.len > 0) allocator.free(state.bytes_data);

    // Free the state itself
    allocator.destroy(state);
    getStatePtr(storage).* = null;
}

pub fn nextRecord(storage: *[IterStateSize]u8) !?[]const u8 {
    const allocator = alloc_mod.get();
    const state = getState(storage) orelse return null;
    const stream = state.stream orelse return null;

    if (try stream.nextSerialized()) |bytes| {
        state.buf.clearRetainingCapacity();
        try state.buf.appendSlice(allocator, bytes);
        return state.buf.items;
    }
    return null;
}

pub fn dumpFileBytes(
    path: []const u8,
    format: []const u8,
    opts: Options,
) ![]const u8 {
    const allocator = alloc_mod.get();

    var infile = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer infile.close();
    var read_buf: [8192]u8 = undefined;
    var reader = infile.reader(&read_buf);

    var scratch = std.Io.Writer.Allocating.initCapacity(allocator, 64 * 1024) catch std.Io.Writer.Allocating.init(allocator);
    errdefer scratch.deinit();

    var parser = try EvtxParser.init(allocator, .{
        .validate_checksums = opts.validate_checksums,
        .verbosity = opts.verbosity,
        .max_records = opts.max_records,
        .skip_first = opts.skip_first,
    });

    var output = blk: {
        if (std.mem.eql(u8, format, "xml")) {
            break :blk OutputWriter.initXml(&scratch.writer);
        } else if (std.mem.eql(u8, format, "json")) {
            break :blk OutputWriter.initJson(&scratch.writer, .single);
        } else if (std.mem.eql(u8, format, "jsonl") or std.mem.eql(u8, format, "jsonlines")) {
            break :blk OutputWriter.initJson(&scratch.writer, .lines);
        } else {
            return error.InvalidFormat;
        }
    };
    defer output.deinit();

    try parser.parse(&reader, &output);
    output.flush();

    return try allocator.dupe(u8, scratch.written());
}

pub fn dumpFileToFile(
    path: []const u8,
    out_path: []const u8,
    format: []const u8,
    opts: Options,
) !void {
    const allocator = alloc_mod.get();

    var infile = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer infile.close();
    var read_buf: [8192]u8 = undefined;
    var reader = infile.reader(&read_buf);

    var outfile = try std.fs.cwd().createFile(out_path, .{ .truncate = true });
    defer outfile.close();
    var write_buf: [8192]u8 = undefined;
    var out_writer = outfile.writer(&write_buf);

    var parser = try EvtxParser.init(allocator, .{
        .validate_checksums = opts.validate_checksums,
        .verbosity = opts.verbosity,
        .max_records = opts.max_records,
        .skip_first = opts.skip_first,
    });

    var output = blk: {
        if (std.mem.eql(u8, format, "xml")) {
            break :blk OutputWriter.initXml(&out_writer.interface);
        } else if (std.mem.eql(u8, format, "json")) {
            break :blk OutputWriter.initJson(&out_writer.interface, .single);
        } else if (std.mem.eql(u8, format, "jsonl") or std.mem.eql(u8, format, "jsonlines")) {
            break :blk OutputWriter.initJson(&out_writer.interface, .lines);
        } else {
            return error.InvalidFormat;
        }
    };
    defer output.deinit();

    try parser.parse(&reader, &output);
    output.flush();
}
