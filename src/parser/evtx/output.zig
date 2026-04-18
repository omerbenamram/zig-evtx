//! Record serialization and output sinks for the EVTX parser.
//!
//! This module separates two previously conflated roles:
//!
//! - `Serializer` owns a scratch buffer and turns an `EventRecordRaw` into
//!   bytes in its format of choice (XML or one of the two JSON flavors).
//!   Each call to `serializeRecord` reuses the same buffer; the returned
//!   slice is valid only until the next call.
//!
//! - `Sink` values (any struct with `emit(identifier, bytes) !void`) consume
//!   those bytes. `WriterSink` is a sink that forwards to a concrete
//!   `*std.Io.Writer`; tests and the worker path supply their own sinks.

const std = @import("std");
const binxml = @import("../binxml/mod.zig");
const render_xml = @import("../render_xml.zig");
const render_json = @import("../render_json.zig");
const format = @import("format.zig");
const err = @import("../err.zig");

pub const EventRecordRaw = format.EventRecordRaw;
pub const WriterError = err.WriterError;

pub const OutputMode = enum { xml, json_single, json_lines };

/// Serialize one record at a time into an owned scratch buffer.
///
/// The buffer is cleared between calls, so the slice returned by
/// `serializeRecord` is only valid until the next `serializeRecord` call.
/// Callers that need to retain the bytes must copy them out.
pub const Serializer = struct {
    mode: OutputMode,
    scratch: std.Io.Writer.Allocating,

    pub fn init(allocator: std.mem.Allocator, mode: OutputMode) !Serializer {
        return .{
            .mode = mode,
            .scratch = try std.Io.Writer.Allocating.initCapacity(allocator, 4096),
        };
    }

    pub fn deinit(self: *Serializer) void {
        self.scratch.deinit();
    }

    pub fn serializeRecord(self: *Serializer, record: EventRecordRaw, ctx: *binxml.Context) ![]const u8 {
        self.scratch.clearRetainingCapacity();
        const w = &self.scratch.writer;
        switch (self.mode) {
            .xml => {
                try render_xml.renderXmlWithContext(ctx, record.chunk_buf, record.binxml, w);
                try w.writeByte('\n');
            },
            .json_single, .json_lines => {
                const tree = try binxml.parseRecord(ctx, record.chunk_buf, record.binxml);
                try w.writeAll("{\"Event\":");
                try render_json.renderElementJson(tree.element, ctx.arena.allocator(), w);
                try w.writeAll("}\n");
            },
        }
        return self.scratch.written();
    }
};

/// Thin sink that forwards every record's bytes to a `*std.Io.Writer`.
/// Intended for the single-threaded path where each record is written
/// directly to its destination.
pub const WriterSink = struct {
    dest: *std.Io.Writer,

    pub fn init(dest: *std.Io.Writer) WriterSink {
        return .{ .dest = dest };
    }

    pub fn emit(self: *WriterSink, _: u64, bytes: []const u8) WriterError!void {
        try self.dest.writeAll(bytes);
    }

    pub fn flush(self: *WriterSink) WriterError!void {
        try self.dest.flush();
    }
};
