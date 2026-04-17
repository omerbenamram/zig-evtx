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

/// Wraps `std.Io.Writer.Allocating` so it can be the scratch buffer for
/// serialization. The wrapper exists only to expose a `*std.Io.Writer`
/// uniformly; callers should otherwise treat it as a thin shim.
pub const SerializeWriter = struct {
    value: std.Io.Writer.Allocating,

    pub fn init(value: std.Io.Writer.Allocating) SerializeWriter {
        return .{ .value = value };
    }

    pub fn writeAll(self: *SerializeWriter, bytes: []const u8) WriterError!void {
        try self.value.writer.writeAll(bytes);
    }

    pub fn writeByte(self: *SerializeWriter, byte: u8) WriterError!void {
        try self.value.writer.writeByte(byte);
    }

    pub fn writer(self: *SerializeWriter) *std.Io.Writer {
        return &self.value.writer;
    }
};

pub const OutputWriter = struct {
    /// Destination writer for final output. Null in serialize-only mode.
    /// Stored as the abstract `*std.Io.Writer`; callers that have a concrete
    /// `std.Io.File.Writer` should pass `&file_writer.interface`.
    dest: ?*std.Io.Writer,
    /// Output format mode
    mode: OutputMode,
    /// Scratch writer for serialized output.
    scratch: SerializeWriter,

    pub fn initXml(allocator: std.mem.Allocator, dest: *std.Io.Writer) !OutputWriter {
        return initWriter(allocator, dest, .xml);
    }

    pub fn initJson(allocator: std.mem.Allocator, dest: *std.Io.Writer, json_mode: JsonMode) !OutputWriter {
        return initWriter(allocator, dest, if (json_mode == .single) .json_single else .json_lines);
    }

    /// Initialize for serialize-only mode (no destination writer needed).
    pub fn initSerializeOnly(allocator: std.mem.Allocator, mode_: OutputMode) !OutputWriter {
        return initWriter(allocator, null, mode_);
    }

    fn initWriter(allocator: std.mem.Allocator, dest: ?*std.Io.Writer, mode: OutputMode) !OutputWriter {
        return .{
            .dest = dest,
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
        const dest = self.dest orelse return;
        try dest.writeAll(bytes);
    }

    pub fn flush(self: *OutputWriter) WriterError!void {
        const dest = self.dest orelse return;
        try dest.flush();
    }
};
