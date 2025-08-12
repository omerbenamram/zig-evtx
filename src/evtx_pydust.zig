const std = @import("std");
const py = @import("pydust");
const evtx = @import("parser/evtx.zig");
const alloc_mod = @import("alloc");
const Root = @This();

pub const __doc__ = "EVTX Python bindings";

// --- File-scope callbacks for RecordStream ---
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

fn io_read_cb(ctx_ptr: *anyopaque, out_buf: []u8) !void {
    const self: *IterDef = @ptrCast(@alignCast(ctx_ptr));
    const io_obj = self.pyio orelse return error.EndOfStream;
    // GIL is already held while executing __next__ from Python

    var filled: usize = 0;
    while (filled < out_buf.len) {
        const remaining = out_buf[filled..];
        var nread: usize = 0;
        if (self.has_read) {
            const to_read: usize = remaining.len;
            const result_obj = try io_obj.call(py.PyObject(Root), "read", .{to_read}, .{});
            defer result_obj.decref();
            const pybytes = try py.PyBytes(Root).checked(result_obj);
            const slice = try pybytes.asSlice();
            if (slice.len > remaining.len) return error.Unexpected;
            @memcpy(remaining[0..slice.len], slice[0..slice.len]);
            nread = slice.len;
        } else return error.Unexpected;

        if (nread == 0) {
            if (filled == 0) return error.EndOfStream;
            return error.EndOfStream;
        }
        filled += nread;
    }
}

const IterDef = struct {
    // Lightweight IO context
    stream: ?evtx.RecordStream = null,
    buf: std.ArrayList(u8) = undefined,
    infile: ?std.fs.File = null,

    // For from_bytes
    bytes_data: []const u8 = &[_]u8{},
    bytes_pos: usize = 0,

    // For from_io
    pyio: ?py.PyObject(Root) = null,
    has_readinto1: bool = false,
    has_readinto: bool = false,
    has_read: bool = false,

    // Note: callbacks moved to file scope to avoid being exposed as Python-callable methods

    pub fn __init__(self: *IterDef, args: struct {
        path: []const u8,
        format: []const u8,
        skip_first: usize = 0,
        max_records: usize = 0,
        validate_checksums: bool = true,
        verbosity: u8 = 0,
    }) !void {
        const allocator = alloc_mod.get();
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
        if (self.pyio) |obj| {
            obj.decref();
            self.pyio = null;
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
        const allocator = alloc_mod.get();
        var self = try py.alloc(Root, IterDef);
        self.* = .{
            .stream = null,
            .buf = std.ArrayList(u8).init(allocator),
            .infile = null,
            .bytes_data = &[_]u8{},
            .bytes_pos = 0,
            .pyio = null,
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

    /// Create an iterator that streams from a Python IO object (file-like).
    /// Call as: Iter.from_io(io, format="jsonl", ...)
    pub fn from_io(args: struct {
        args: py.Args(Root),
        kwargs: py.Kwargs(Root),
    }) !*IterDef {
        const allocator = alloc_mod.get();
        if (args.args.len == 0) {
            return py.TypeError(Root).raise("missing required positional arg: io");
        }
        const io_obj = args.args[0];

        // Extract kwargs with defaults
        var fmt: []const u8 = "";
        var skip_first: usize = 0;
        var max_records: usize = 0;
        var validate_checksums: bool = true;
        var verbosity: u8 = 0;

        var kwargs = args.kwargs; // make mutable copy
        if (kwargs.fetchRemove("format")) |e| fmt = try py.as(Root, []const u8, e.value);
        if (kwargs.fetchRemove("skip_first")) |e| skip_first = try py.as(Root, usize, e.value);
        if (kwargs.fetchRemove("max_records")) |e| max_records = try py.as(Root, usize, e.value);
        if (kwargs.fetchRemove("validate_checksums")) |e| validate_checksums = try py.as(Root, bool, e.value);
        if (kwargs.fetchRemove("verbosity")) |e| verbosity = try py.as(Root, u8, e.value);

        if (!(std.mem.eql(u8, fmt, "xml") or std.mem.eql(u8, fmt, "jsonl") or std.mem.eql(u8, fmt, "jsonlines"))) {
            return py.TypeError(Root).raise("missing/invalid 'format' (xml|jsonl|jsonlines)");
        }

        var self = try py.alloc(Root, IterDef);
        self.* = .{
            .stream = null,
            .buf = std.ArrayList(u8).init(allocator),
            .infile = null,
            .bytes_data = &[_]u8{},
            .bytes_pos = 0,
            .pyio = null,
            .has_read = false,
        };

        // Hold a strong reference to IO object to keep underlying resource alive
        io_obj.incref();
        self.pyio = io_obj;

        // Prefer fileno path to avoid Python roundtrips during read
        var use_fd: bool = false;
        if (io_obj.has("fileno") catch false) {
            const fd_val = try io_obj.call(c_int, "fileno", .{}, .{});
            const dup_fd: c_int = try std.posix.dup(fd_val);
            self.infile = std.fs.File{ .handle = @intCast(dup_fd) };
            use_fd = true;
        }

        const stream = try evtx.RecordStream.init(
            allocator,
            @ptrCast(self),
            if (use_fd) @ptrCast(&file_read_cb) else blk: {
                self.has_readinto1 = io_obj.has("readinto1") catch false;
                self.has_readinto = io_obj.has("readinto") catch false;
                self.has_read = io_obj.has("read") catch false;
                if (!(self.has_readinto1 or self.has_readinto or self.has_read)) return py.TypeError(Root).raise("io object must define fileno() or readinto1/readinto/read");
                break :blk @ptrCast(&io_read_cb);
            },
            .{
                .validate_checksums = validate_checksums,
                .verbosity = verbosity,
                .max_records = max_records,
                .skip_first = skip_first,
            },
            fmt,
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
    const allocator = alloc_mod.get();
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
    const allocator = alloc_mod.get();

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
