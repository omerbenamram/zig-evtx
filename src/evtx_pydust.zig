const std = @import("std");
const py = @import("pydust");
const evtx = @import("parser/evtx.zig");
const Root = @This();

pub const __doc__ = "EVTX Python bindings";

const IterDef = struct {
    // Lightweight IO context
    stream: ?evtx.RecordStream = null,
    buf: std.ArrayList(u8) = undefined,
    infile: ?std.fs.File = null,

    // For from_bytes
    bytes_data: []const u8 = &[_]u8{},
    bytes_pos: usize = 0,

    // For from_io (disabled for now)
    pyio_ptr: usize = 0,
    has_readinto: bool = false,
    has_read: bool = false,

    fn file_read_cb(ctx_ptr: *anyopaque, buf: []u8) !void {
        const self: *IterDef = @ptrCast(@alignCast(ctx_ptr));
        var f = self.infile orelse return error.EndOfStream;
        try f.reader().readNoEof(buf);
    }

    fn bytes_read_cb(ctx_ptr: *anyopaque, out_buf: []u8) !void {
        const self: *IterDef = @ptrCast(@alignCast(ctx_ptr));
        if (self.bytes_pos + out_buf.len > self.bytes_data.len) return error.EndOfStream;
        const src = self.bytes_data[self.bytes_pos .. self.bytes_pos + out_buf.len];
        @memcpy(out_buf, src);
        self.bytes_pos += out_buf.len;
    }

    pub fn __init__(self: *IterDef, args: struct {
        path: []const u8,
        format: []const u8,
        skip_first: usize = 0,
        max_records: usize = 0,
        validate_checksums: bool = true,
        verbosity: u8 = 0,
    }) !void {
        const allocator = std.heap.c_allocator;
        if (!(std.mem.eql(u8, args.format, "xml") or std.mem.eql(u8, args.format, "jsonl") or std.mem.eql(u8, args.format, "jsonlines"))) {
            return error.InvalidFormat;
        }
        const infile = try std.fs.cwd().openFile(args.path, .{ .mode = .read_only });
        self.infile = infile;
        const stream = try evtx.RecordStream.init(
            allocator,
            @ptrCast(self),
            @ptrCast(&file_read_cb),
            .{
                .validate_checksums = args.validate_checksums,
                .verbosity = args.verbosity,
                .max_records = args.max_records,
                .skip_first = args.skip_first,
            },
            args.format,
        );
        self.stream = stream;
        self.buf = std.ArrayList(u8).init(allocator);
    }

    pub fn __del__(self: *IterDef) void {
        if (self.stream) |*s| s.deinit();
        if (self.infile) |*f| {
            f.close();
            self.infile = null;
        }
        if (self.buf.capacity != 0) self.buf.deinit();
    }

    pub fn __iter__(self: *IterDef) !*IterDef {
        return self;
    }

    pub fn __next__(self: *IterDef) !?py.PyObject(@This()) {
        if (self.stream == null) return null;
        const s = &self.stream.?;
        if (try s.nextSerialized()) |bytes| {
            self.buf.clearRetainingCapacity();
            try self.buf.appendSlice(bytes);
            return (try py.PyString(@This()).create(self.buf.items)).obj;
        }
        return null;
    }

    /// Create an iterator that streams from a contiguous Python buffer (bytes/bytearray/memoryview).
    pub fn from_bytes(args: struct {
        data: []const u8,
        format: []const u8,
        skip_first: usize = 0,
        max_records: usize = 0,
        validate_checksums: bool = true,
        verbosity: u8 = 0,
    }) !*IterDef {
        if (!(std.mem.eql(u8, args.format, "xml") or std.mem.eql(u8, args.format, "jsonl") or std.mem.eql(u8, args.format, "jsonlines"))) {
            return error.InvalidFormat;
        }
        const allocator = std.heap.c_allocator;
        var self = try py.alloc(Root, IterDef);
        self.* = .{
            .stream = null,
            .buf = std.ArrayList(u8).init(allocator),
            .infile = null,
            .bytes_data = &[_]u8{},
            .bytes_pos = 0,
            .pyio_ptr = 0,
            .has_readinto = false,
            .has_read = false,
        };
        self.bytes_data = try allocator.dupe(u8, args.data);
        self.bytes_pos = 0;
        const stream = try evtx.RecordStream.init(
            allocator,
            @ptrCast(self),
            @ptrCast(&bytes_read_cb),
            .{
                .validate_checksums = args.validate_checksums,
                .verbosity = args.verbosity,
                .max_records = args.max_records,
                .skip_first = args.skip_first,
            },
            args.format,
        );
        self.stream = stream;
        return self;
    }
};

pub const Iter = py.class(IterDef);

pub fn dump_file_bytes(args: struct {
    path: []const u8,
    format: []const u8,
    skip_first: usize = 0,
    max_records: usize = 0,
    validate_checksums: bool = true,
    verbosity: u8 = 0,
}) !py.PyObject(@This()) {
    const allocator = std.heap.c_allocator;
    var infile = try std.fs.cwd().openFile(args.path, .{ .mode = .read_only });
    defer infile.close();
    var reader = infile.reader();

    var buf = std.ArrayList(u8).init(allocator);
    const out_writer = buf.writer();

    var parser = try evtx.EvtxParser.init(allocator, .{
        .validate_checksums = args.validate_checksums,
        .verbosity = args.verbosity,
        .max_records = args.max_records,
        .skip_first = args.skip_first,
    });
    defer parser.deinit();

    var output = blk: {
        if (std.mem.eql(u8, args.format, "xml")) {
            break :blk evtx.Output.xml(out_writer);
        } else if (std.mem.eql(u8, args.format, "json")) {
            break :blk evtx.Output.json(out_writer, .single);
        } else if (std.mem.eql(u8, args.format, "jsonl") or std.mem.eql(u8, args.format, "jsonlines")) {
            break :blk evtx.Output.json(out_writer, .lines);
        } else {
            return error.InvalidFormat;
        }
    };

    try parser.parse(&reader, &output);
    output.flush();
    const py_str = try py.PyString(@This()).create(buf.items);
    buf.deinit();
    return py_str.obj;
}

pub fn dump_file_to_file(args: struct {
    path: []const u8,
    out_path: []const u8,
    format: []const u8,
    skip_first: usize = 0,
    max_records: usize = 0,
    validate_checksums: bool = true,
    verbosity: u8 = 0,
}) !void {
    const allocator = std.heap.c_allocator;

    var infile = try std.fs.cwd().openFile(args.path, .{ .mode = .read_only });
    defer infile.close();
    var reader = infile.reader();

    var outfile = try std.fs.cwd().createFile(args.out_path, .{ .truncate = true });
    defer outfile.close();
    const out_writer = outfile.writer();

    var parser = try evtx.EvtxParser.init(allocator, .{
        .validate_checksums = args.validate_checksums,
        .verbosity = args.verbosity,
        .max_records = args.max_records,
        .skip_first = args.skip_first,
    });
    defer parser.deinit();

    var output = blk: {
        if (std.mem.eql(u8, args.format, "xml")) {
            break :blk evtx.Output.xml(out_writer);
        } else if (std.mem.eql(u8, args.format, "json")) {
            break :blk evtx.Output.json(out_writer, .single);
        } else if (std.mem.eql(u8, args.format, "jsonl") or std.mem.eql(u8, args.format, "jsonlines")) {
            break :blk evtx.Output.json(out_writer, .lines);
        } else {
            return error.InvalidFormat;
        }
    };

    try parser.parse(&reader, &output);
    output.flush();
}

comptime {
    py.rootmodule(@This());
}
