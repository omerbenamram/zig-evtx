const std = @import("std");
const py = @import("pydust");
const alloc_mod = @import("alloc");

const Root = @This();

pub const __doc__ = "EVTX Python bindings";

// All evtx logic is accessed through this separate module to avoid pydust's
// comptime type introspection walking through the complex evtx type hierarchy.
const impl = @import("evtx_pydust_impl.zig");

/// Native EVTX iterator exposed to Python via pydust.
///
/// WARNING: This type has a known GC timing issue. When Python uses patterns like
/// `list(Iter(...))` without keeping a reference to the iterator, the object can
/// be garbage collected while Python is still processing returned strings. This
/// causes heap corruption and segfaults.
///
/// The workaround is in `evtxzig/__init__.py` which wraps this in `_RecordIterator`
/// to ensure the native iterator stays alive during iteration.
///
/// If debugging segfaults related to iteration:
/// 1. Check if pattern is `list(Iter(...))` vs `it = Iter(...); list(it)`
/// 2. Look at pydust's tp_finalize in pytypes.zig
/// 3. Try gc.collect() between operations - if it helps, it's a lifetime issue
/// 4. See detailed docs in evtxzig/__init__.py on _RecordIterator
const IterDef = struct {
    // Use a simple byte array to store opaque state - pydust won't walk through it
    state_storage: [impl.IterStateSize]u8 align(8) = undefined,
    initialized: bool = false,

    pub fn __init__(self: *IterDef, args: struct {
        path: []const u8,
        format: []const u8,
        skip_first: usize = 0,
        max_records: usize = 0,
        validate_checksums: bool = true,
        verbosity: u8 = 0,
        carve: bool = false,
    }) !void {
        try impl.initIterFromPath(&self.state_storage, args.path, args.format, .{
            .skip_first = args.skip_first,
            .max_records = args.max_records,
            .validate_checksums = args.validate_checksums,
            .verbosity = args.verbosity,
            .carve = args.carve,
        });
        self.initialized = true;
    }

    pub fn __del__(self: *IterDef) void {
        if (self.initialized) {
            impl.deinitIter(&self.state_storage);
            self.initialized = false;
        }
    }

    pub fn __iter__(self: *IterDef) !*IterDef {
        return self;
    }

    pub fn __next__(self: *IterDef) !?py.PyObject {
        if (!self.initialized) return null;
        if (try impl.nextRecord(&self.state_storage)) |bytes| {
            return (try py.PyString.create(bytes)).obj;
        }
        return null;
    }

    pub fn from_bytes(args: struct {
        data: []const u8,
        format: []const u8,
        skip_first: usize = 0,
        max_records: usize = 0,
        validate_checksums: bool = true,
        verbosity: u8 = 0,
        carve: bool = false,
    }) !*IterDef {
        var self = try py.alloc(Root, IterDef);
        self.* = .{};
        try impl.initIterFromBytes(&self.state_storage, args.data, args.format, .{
            .skip_first = args.skip_first,
            .max_records = args.max_records,
            .validate_checksums = args.validate_checksums,
            .verbosity = args.verbosity,
            .carve = args.carve,
        });
        self.initialized = true;
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
    carve: bool = false,
}) !py.PyObject {
    const result = try impl.dumpFileBytes(args.path, args.format, .{
        .skip_first = args.skip_first,
        .max_records = args.max_records,
        .validate_checksums = args.validate_checksums,
        .verbosity = args.verbosity,
        .carve = args.carve,
    });
    const py_str = try py.PyString.create(result);
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
    carve: bool = false,
}) !void {
    try impl.dumpFileToFile(args.path, args.out_path, args.format, .{
        .skip_first = args.skip_first,
        .max_records = args.max_records,
        .validate_checksums = args.validate_checksums,
        .verbosity = args.verbosity,
        .carve = args.carve,
    });
}

comptime {
    py.rootmodule(@This());
}
