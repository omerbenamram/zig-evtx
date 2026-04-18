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
const Serializer = output.Serializer;
const WriterSink = output.WriterSink;

pub const Options = struct {
    skip_first: usize = 0,
    max_records: usize = 0,
    validate_checksums: bool = true,
    verbosity: u8 = 0,
    carve: bool = false,
};

/// Backing source for the iterator's reader. The reader tag is mutually
/// exclusive with the bytes/file fields and is set once during init.
const Source = union(enum) {
    /// File-backed: owns the open `Io.File` plus the buffered file
    /// reader and its scratch buffer. The `*std.Io.Reader` we hand to the
    /// parser is `&file.reader.interface`, which stays valid as long as
    /// the IterState is heap-pinned.
    file: struct {
        handle: std.Io.File,
        reader: std.Io.File.Reader,
        buf: [READ_BUF_SIZE]u8 = undefined,
    },
    /// Bytes-backed: owns a heap copy of the input and an `Io.Reader`
    /// view over it via `Reader.fixed`.
    bytes: struct {
        data: []const u8,
        reader: std.Io.Reader,
    },
};

const READ_BUF_SIZE: usize = 8192;

/// Streaming iterator state - combines source handling and parsing.
const IterState = struct {
    allocator: std.mem.Allocator,
    io_impl: std.Io.Threaded,
    source: Source,

    // Options
    opts: Options,
    is_xml: bool,

    // Parse state
    out: Serializer,
    hdr: format.FileHeader,
    chunk_index: usize = 0,
    ctx: binxml.Context,
    have_iter: bool = false,
    exhausted: bool = false,
    current_chunk: format.Chunk = undefined,
    chunk_owned: bool = false,
    rec_iter: format.RecordIterator = undefined,
    selected_including_skips: usize = 0,
    emitted: usize = 0,

    // Output buffer for Python
    buf: std.ArrayList(u8) = .empty,

    fn io(self: *IterState) std.Io {
        return self.io_impl.io();
    }

    /// Returns a stable `*std.Io.Reader` over the active source. The
    /// pointer is owned by the IterState and stays valid for the
    /// lifetime of the iterator.
    fn reader(self: *IterState) *std.Io.Reader {
        return switch (self.source) {
            .file => |*f| &f.reader.interface,
            .bytes => |*b| &b.reader,
        };
    }

    fn initFromFile(
        allocator: std.mem.Allocator,
        opts: Options,
        fmt: []const u8,
        path: []const u8,
    ) !*IterState {
        var io_impl = std.Io.Threaded.init(allocator, .{});
        errdefer io_impl.deinit();

        var handle = try std.Io.Dir.cwd().openFile(io_impl.io(), path, .{ .mode = .read_only });
        errdefer handle.close(io_impl.io());

        const self = try allocator.create(IterState);
        errdefer allocator.destroy(self);

        try self.initCommon(allocator, io_impl, opts, fmt);
        // We need a stable address for `buf` — the file reader stores a
        // slice pointing into `self.source.file.buf` — so initialize the
        // file reader after the state is in place.
        self.source = .{ .file = .{
            .handle = handle,
            .reader = undefined,
        } };
        self.source.file.reader = handle.reader(io_impl.io(), &self.source.file.buf);
        return self;
    }

    fn initFromBytes(
        allocator: std.mem.Allocator,
        opts: Options,
        fmt: []const u8,
        data: []const u8,
    ) !*IterState {
        var io_impl = std.Io.Threaded.init(allocator, .{});
        errdefer io_impl.deinit();

        const owned = try allocator.dupe(u8, data);
        errdefer allocator.free(owned);

        const self = try allocator.create(IterState);
        errdefer allocator.destroy(self);

        try self.initCommon(allocator, io_impl, opts, fmt);
        self.source = .{ .bytes = .{
            .data = owned,
            .reader = std.Io.Reader.fixed(owned),
        } };
        return self;
    }

    /// Shared init for both source flavors. Caller must populate `source`
    /// after this returns (reader fields need stable self addresses).
    fn initCommon(
        self: *IterState,
        allocator: std.mem.Allocator,
        io_impl: std.Io.Threaded,
        opts: Options,
        fmt: []const u8,
    ) !void {
        const is_xml = std.mem.eql(u8, fmt, "xml");

        var ctx = binxml.Context.init(allocator);
        errdefer ctx.deinit();

        var out = try Serializer.init(allocator, if (is_xml) .xml else .json_lines);
        errdefer out.deinit();

        self.* = .{
            .allocator = allocator,
            .io_impl = io_impl,
            .source = undefined,
            .opts = opts,
            .is_xml = is_xml,
            .out = out,
            .hdr = undefined,
            .ctx = ctx,
        };
    }

    fn readHeader(self: *IterState) !void {
        self.hdr = try format.FileHeader.read(self.reader());
    }

    pub fn deinit(self: *IterState) void {
        self.releaseCurrentChunk();
        self.out.deinit();
        self.ctx.deinit();
        self.buf.deinit(self.allocator);
        switch (self.source) {
            .file => |*f| f.handle.close(self.io()),
            .bytes => |b| self.allocator.free(b.data),
        }
        self.io_impl.deinit();
        self.allocator.destroy(self);
    }

    fn ensureIterator(self: *IterState) !bool {
        if (self.exhausted) return false;
        if (self.have_iter) {
            return true;
        }
        // In carve mode, scan until EOF/invalid signature. Otherwise, trust header's num_chunks.
        if (!self.opts.carve and self.chunk_index >= self.hdr.core.num_chunks) return false;

        // Free the previous chunk, if any, before replacing it.
        self.releaseCurrentChunk();

        self.current_chunk = format.Chunk.read(self.allocator, self.reader()) catch |e| switch (e) {
            error.EndOfStream, error.BadChunkSignature => return false,
            else => return e,
        };
        self.chunk_owned = true;
        if (self.opts.validate_checksums) try self.current_chunk.validateChecksums();
        self.ctx.resetPerChunk();
        try self.ctx.preCacheFromChunkHeader(self.current_chunk.buf, &self.current_chunk.header.common_string_offsets);
        if (self.opts.verbosity >= 3) logger.setModuleLevel("binxml", .trace);
        self.rec_iter = self.current_chunk.records();
        self.have_iter = true;
        return true;
    }

    fn releaseCurrentChunk(self: *IterState) void {
        if (self.chunk_owned) {
            self.current_chunk.deinit();
            self.chunk_owned = false;
        }
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

    const state = try IterState.initFromFile(allocator, opts, fmt, path);
    errdefer state.deinit();

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

    const state = try IterState.initFromBytes(allocator, opts, fmt, data);
    errdefer state.deinit();

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

    var io_impl = std.Io.Threaded.init(allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();

    var infile = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer infile.close(io);
    var read_buf: [8192]u8 = undefined;
    var reader = infile.reader(io, &read_buf);

    var scratch = std.Io.Writer.Allocating.initCapacity(allocator, 64 * 1024) catch std.Io.Writer.Allocating.init(allocator);
    errdefer scratch.deinit();

    var parser = EvtxParser.init(allocator, .{
        .validate_checksums = opts.validate_checksums,
        .verbosity = opts.verbosity,
        .max_records = opts.max_records,
        .skip_first = opts.skip_first,
        .carve = opts.carve,
    });

    const mode: output.OutputMode = blk: {
        if (std.mem.eql(u8, fmt, "xml")) break :blk .xml;
        if (std.mem.eql(u8, fmt, "json")) break :blk .json_single;
        if (std.mem.eql(u8, fmt, "jsonl") or std.mem.eql(u8, fmt, "jsonlines")) break :blk .json_lines;
        return error.InvalidFormat;
    };

    var serializer = try Serializer.init(allocator, mode);
    defer serializer.deinit();
    var sink = WriterSink.init(&scratch.writer);

    try parser.parse(&reader.interface, &serializer, &sink);
    try sink.flush();

    return try allocator.dupe(u8, scratch.written());
}

pub fn dumpFileToFile(path: []const u8, out_path: []const u8, fmt: []const u8, opts: Options) !void {
    const allocator = alloc_mod.get();

    var io_impl = std.Io.Threaded.init(allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();

    var infile = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer infile.close(io);
    var read_buf: [8192]u8 = undefined;
    var reader = infile.reader(io, &read_buf);

    var outfile = try std.Io.Dir.cwd().createFile(io, out_path, .{ .truncate = true });
    defer outfile.close(io);
    var write_buf: [8192]u8 = undefined;
    var out_writer = outfile.writer(io, &write_buf);

    var parser = EvtxParser.init(allocator, .{
        .validate_checksums = opts.validate_checksums,
        .verbosity = opts.verbosity,
        .max_records = opts.max_records,
        .skip_first = opts.skip_first,
        .carve = opts.carve,
    });

    const mode: output.OutputMode = blk: {
        if (std.mem.eql(u8, fmt, "xml")) break :blk .xml;
        if (std.mem.eql(u8, fmt, "json")) break :blk .json_single;
        if (std.mem.eql(u8, fmt, "jsonl") or std.mem.eql(u8, fmt, "jsonlines")) break :blk .json_lines;
        return error.InvalidFormat;
    };

    var serializer = try Serializer.init(allocator, mode);
    defer serializer.deinit();
    var sink = WriterSink.init(&out_writer.interface);

    try parser.parse(&reader.interface, &serializer, &sink);
    try sink.flush();
}
