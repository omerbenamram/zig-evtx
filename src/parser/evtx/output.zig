//! Output serialization for EVTX records (XML/JSON).
//!
//! Keeps std.Io construction at the call boundary and scratch buffering local
//! to the serializer so parser and test code can share one explicit I/O model.

const std = @import("std");
const binxml = @import("../binxml/mod.zig");
const render_xml = @import("../render_xml.zig");
const render_json = @import("../render_json.zig");
const format = @import("format.zig");
const err = @import("../err.zig");

pub const EventRecordRaw = format.EventRecordRaw;
pub const WriterError = err.WriterError;

pub const JsonMode = enum { single, lines };

pub const OutputMode = enum { xml, json_single, json_lines };

/// Non-generic output serializer using concrete std.Io.Writer.
pub fn IoWriter(comptime Writer: type) type {
    return struct {
        value: Writer,

        const Self = @This();

        pub fn init(value: Writer) Self {
            return .{ .value = value };
        }

        pub fn writeAll(self: *Self, bytes: []const u8) WriterError!void {
            try self.writer().writeAll(bytes);
        }

        pub fn writeByte(self: *Self, byte: u8) WriterError!void {
            try self.writer().writeByte(byte);
        }

        pub fn flush(self: *Self) WriterError!void {
            if (@hasField(Writer, "writer")) return;
            try self.value.flush();
        }

        pub fn writer(self: *Self) *std.Io.Writer {
            if (@hasField(Writer, "writer")) {
                return &self.value.writer;
            }
            if (@hasField(Writer, "interface")) {
                return &self.value.interface;
            }
            @compileError("Writer must provide writer or interface field");
        }
    };
}

pub const SerializeWriter = IoWriter(std.Io.Writer.Allocating);

pub const OutputWriter = struct {
    /// Destination writer for final output. Null in serialize-only mode.
    dest_ctx: ?*anyopaque,
    dest_write_all_fn: ?*const fn (*anyopaque, []const u8) WriterError!void,
    dest_flush_fn: ?*const fn (*anyopaque) WriterError!void,
    /// Output format mode
    mode: OutputMode,
    /// Scratch writer for serialized output.
    scratch: SerializeWriter,

    pub fn initXml(allocator: std.mem.Allocator, dest: anytype) !OutputWriter {
        return init(allocator, dest, .xml);
    }

    pub fn initJson(allocator: std.mem.Allocator, dest: anytype, json_mode: JsonMode) !OutputWriter {
        return init(allocator, dest, if (json_mode == .single) .json_single else .json_lines);
    }

    /// Initialize for serialize-only mode (no destination writer needed).
    pub fn initSerializeOnly(allocator: std.mem.Allocator, mode_: OutputMode) !OutputWriter {
        return .{
            .dest_ctx = null,
            .dest_write_all_fn = null,
            .dest_flush_fn = null,
            .mode = mode_,
            .scratch = .init(try std.Io.Writer.Allocating.initCapacity(allocator, 4096)),
        };
    }

    fn init(allocator: std.mem.Allocator, dest: anytype, mode: OutputMode) !OutputWriter {
        const Dest = @TypeOf(dest);
        const dest_info = comptime switch (@typeInfo(Dest)) {
            .pointer => |ptr| blk: {
                if (ptr.size != .one) @compileError("destination writer must be a single-item pointer");
                break :blk ptr.child;
            },
            else => @compileError("destination writer must be passed by pointer"),
        };

        const Adapter = struct {
            fn writeAll(ctx: *anyopaque, bytes: []const u8) WriterError!void {
                const typed: *dest_info = @ptrCast(@alignCast(ctx));
                if (comptime @hasField(dest_info, "interface")) {
                    try typed.interface.writeAll(bytes);
                } else {
                    try typed.writeAll(bytes);
                }
            }

            fn flush(ctx: *anyopaque) WriterError!void {
                const typed: *dest_info = @ptrCast(@alignCast(ctx));
                typed.flush() catch return error.WriteFailed;
            }
        };

        return .{
            .dest_ctx = @ptrCast(dest),
            .dest_write_all_fn = Adapter.writeAll,
            .dest_flush_fn = Adapter.flush,
            .mode = mode,
            .scratch = .init(try std.Io.Writer.Allocating.initCapacity(allocator, 4096)),
        };
    }

    pub fn deinit(self: *OutputWriter) void {
        self.scratch.value.deinit();
    }

    pub fn serializeRecord(self: *OutputWriter, record: EventRecordRaw, ctx: *binxml.Context) ![]const u8 {
        self.scratch.value.clearRetainingCapacity();
        switch (self.mode) {
            .xml => {
                try render_xml.renderXmlWithContext(ctx, record.chunk_buf, record.binxml, self.scratch.writer());
                try self.scratch.writeByte('\n');
            },
            .json_single, .json_lines => {
                // Rust-compatible format: {"Event": ...}
                const tree = try binxml.parseRecord(ctx, record.chunk_buf, record.binxml);
                try self.scratch.writeAll("{\"Event\":");
                try render_json.renderElementJson(tree.element, ctx.arena.allocator(), self.scratch.writer());
                try self.scratch.writeAll("}\n");
            },
        }
        return self.scratch.value.written();
    }

    pub fn writeSerialized(self: *OutputWriter, bytes: []const u8) WriterError!void {
        const write_all = self.dest_write_all_fn orelse return;
        const dest_ctx = self.dest_ctx orelse return;
        try write_all(dest_ctx, bytes);
    }

    pub fn flush(self: *OutputWriter) WriterError!void {
        const flush_fn = self.dest_flush_fn orelse return;
        const dest_ctx = self.dest_ctx orelse return;
        try flush_fn(dest_ctx);
    }
};
