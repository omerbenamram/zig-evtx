//! Implementation module for Python bindings.
//! This module is separated from evtx_pydust.zig to isolate the complex evtx types
//! from pydust's comptime type introspection.

const std = @import("std");
const alloc_mod = @import("alloc");

const binxml = @import("parser/binxml/mod.zig");
const format = @import("parser/evtx/format.zig");
const logger = @import("logger.zig");
const output = @import("parser/evtx/output.zig");

const EvtxParser = @import("parser/evtx/parser.zig").EvtxParser;
const OutputWriter = output.OutputWriter;

pub const Options = struct {
    skip_first: usize = 0,
    max_records: usize = 0,
    validate_checksums: bool = true,
    verbosity: u8 = 0,
    carve: bool = false,
};

/// Streaming iterator state - combines source handling and parsing.
const IterState = struct {
    allocator: std.mem.Allocator,

    // Source (mutually exclusive)
    infile: ?std.fs.File = null,
    bytes_data: []const u8 = &.{},
    bytes_pos: usize = 0,

    // Options
    opts: Options,
    is_xml: bool,

    // Parse state
    out: OutputWriter,
    hdr: format.FileHeader,
    chunk_index: usize = 0,
    ctx: binxml.Context,
    have_iter: bool = false,
    exhausted: bool = false,
    current_chunk: format.Chunk = undefined,
    rec_iter: format.RecordIterator = undefined,
    selected_including_skips: usize = 0,
    emitted: usize = 0,

    // Output buffer for Python
    buf: std.ArrayList(u8) = .empty,

    /// Read from whichever source is active.
    pub fn readNoEof(self: *IterState, dest: []u8) !void {
        if (self.infile) |f| {
            const n = try f.readAll(dest);
            if (n < dest.len) return error.EndOfStream;
        } else {
            if (self.bytes_pos + dest.len > self.bytes_data.len) return error.EndOfStream;
            @memcpy(dest, self.bytes_data[self.bytes_pos..][0..dest.len]);
            self.bytes_pos += dest.len;
        }
    }

    fn init(allocator: std.mem.Allocator, opts: Options, fmt: []const u8) !*IterState {
        const self = try allocator.create(IterState);
        errdefer allocator.destroy(self);

        const is_xml = std.mem.eql(u8, fmt, "xml");

        // Initialize context first (can fail)
        const ctx = try binxml.Context.init(allocator);
        errdefer ctx.deinit();

        // Now initialize everything (OutputWriter.initSerializeOnly cannot fail)
        self.* = .{
            .allocator = allocator,
            .opts = opts,
            .is_xml = is_xml,
            .out = OutputWriter.initSerializeOnly(if (is_xml) .xml else .json_lines),
            .hdr = undefined,
            .ctx = ctx,
        };
        return self;
    }

    fn readHeader(self: *IterState) !void {
        self.hdr = try format.FileHeader.read(self);
    }

    pub fn deinit(self: *IterState) void {
        self.out.deinit();
        self.ctx.deinit();
        self.buf.deinit(self.allocator);
        if (self.infile) |*f| f.close();
        if (self.bytes_data.len > 0) self.allocator.free(self.bytes_data);
        self.allocator.destroy(self);
    }

    fn ensureIterator(self: *IterState) !bool {
        if (self.exhausted) return false;
        if (self.have_iter) return true;
        // In carve mode, scan until EOF/invalid signature. Otherwise, trust header's num_chunks.
        if (!self.opts.carve and self.chunk_index >= self.hdr.core.num_chunks) return false;

        self.current_chunk = format.Chunk.read(self) catch |e| switch (e) {
            error.EndOfStream, error.BadChunkSignature => return false,
            else => return e,
        };
        if (self.opts.validate_checksums) try self.current_chunk.validateChecksums();
        self.ctx.resetPerChunk();
        self.ctx.preCacheFromChunkHeader(&self.current_chunk.buf, &self.current_chunk.header.common_string_offsets);
        if (self.opts.verbosity >= 3) logger.setModuleLevel("binxml", .trace);
        self.rec_iter = self.current_chunk.records();
        self.have_iter = true;
        return true;
    }

    /// Returns a slice valid until the next call.
    pub fn nextSerialized(self: *IterState) !?[]const u8 {
        while (true) {
            if (!try self.ensureIterator()) return null;
            if (try self.rec_iter.next()) |rec| {
                if (self.opts.skip_first > 0 and self.selected_including_skips < self.opts.skip_first) {
                    self.selected_including_skips += 1;
                    continue;
                }
                self.selected_including_skips += 1;
                const bytes = try self.out.serializeRecord(rec, &self.ctx);
                self.emitted += 1;
                if (self.opts.max_records != 0 and self.emitted >= self.opts.max_records) {
                    self.exhausted = true;
                }
                return bytes;
            } else {
                self.have_iter = false;
                self.chunk_index += 1;
            }
        }
    }
};

// We store a pointer to heap-allocated IterState
pub const IterStateSize = @sizeOf(*IterState);

fn getStatePtr(storage: *[IterStateSize]u8) *?*IterState {
    return @ptrCast(@alignCast(storage));
}

fn getState(storage: *[IterStateSize]u8) ?*IterState {
    return getStatePtr(storage).*;
}

fn validateFormat(fmt: []const u8) !void {
    if (!(std.mem.eql(u8, fmt, "xml") or std.mem.eql(u8, fmt, "jsonl") or std.mem.eql(u8, fmt, "jsonlines"))) {
        return error.InvalidFormat;
    }
}

pub fn initIterFromPath(
    storage: *[IterStateSize]u8,
    path: []const u8,
    fmt: []const u8,
    opts: Options,
) !void {
    try validateFormat(fmt);
    const allocator = alloc_mod.get();

    var infile: ?std.fs.File = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    errdefer if (infile) |*f| f.close();

    const state = try IterState.init(allocator, opts, fmt);
    errdefer state.deinit();

    // Transfer ownership to state, mark local as null to prevent double-close
    state.infile = infile;
    infile = null;

    try state.readHeader();

    getStatePtr(storage).* = state;
}

pub fn initIterFromBytes(
    storage: *[IterStateSize]u8,
    data: []const u8,
    fmt: []const u8,
    opts: Options,
) !void {
    try validateFormat(fmt);
    const allocator = alloc_mod.get();

    var bytes_copy: ?[]const u8 = try allocator.dupe(u8, data);
    errdefer if (bytes_copy) |b| allocator.free(b);

    const state = try IterState.init(allocator, opts, fmt);
    errdefer state.deinit();

    // Transfer ownership to state, mark local as null to prevent double-free
    state.bytes_data = bytes_copy.?;
    bytes_copy = null;

    try state.readHeader();

    getStatePtr(storage).* = state;
}

pub fn deinitIter(storage: *[IterStateSize]u8) void {
    if (getState(storage)) |state| {
        state.deinit();
        getStatePtr(storage).* = null;
    }
}

pub fn nextRecord(storage: *[IterStateSize]u8) !?[]const u8 {
    const state = getState(storage) orelse return null;
    if (try state.nextSerialized()) |bytes| {
        state.buf.clearRetainingCapacity();
        try state.buf.appendSlice(state.allocator, bytes);
        return state.buf.items;
    }
    return null;
}

pub fn dumpFileBytes(path: []const u8, fmt: []const u8, opts: Options) ![]const u8 {
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
        .carve = opts.carve,
    });

    var out = blk: {
        if (std.mem.eql(u8, fmt, "xml")) {
            break :blk OutputWriter.initXml(&scratch.writer);
        } else if (std.mem.eql(u8, fmt, "json")) {
            break :blk OutputWriter.initJson(&scratch.writer, .single);
        } else if (std.mem.eql(u8, fmt, "jsonl") or std.mem.eql(u8, fmt, "jsonlines")) {
            break :blk OutputWriter.initJson(&scratch.writer, .lines);
        } else {
            return error.InvalidFormat;
        }
    };
    defer out.deinit();

    try parser.parse(&reader, &out);
    out.flush();

    return try allocator.dupe(u8, scratch.written());
}

pub fn dumpFileToFile(path: []const u8, out_path: []const u8, fmt: []const u8, opts: Options) !void {
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
        .carve = opts.carve,
    });

    var out = blk: {
        if (std.mem.eql(u8, fmt, "xml")) {
            break :blk OutputWriter.initXml(&out_writer.interface);
        } else if (std.mem.eql(u8, fmt, "json")) {
            break :blk OutputWriter.initJson(&out_writer.interface, .single);
        } else if (std.mem.eql(u8, fmt, "jsonl") or std.mem.eql(u8, fmt, "jsonlines")) {
            break :blk OutputWriter.initJson(&out_writer.interface, .lines);
        } else {
            return error.InvalidFormat;
        }
    };
    defer out.deinit();

    try parser.parse(&reader, &out);
    out.flush();
}
