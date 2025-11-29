//! Output serialization for EVTX records (XML/JSON).
//!
//! Uses Zig 0.15's concrete std.Io.Writer interface for non-generic code
//! and std.Io.Writer.Allocating for efficient buffered serialization.

const std = @import("std");
const binxml = @import("../binxml/mod.zig");
const render_xml = @import("../render_xml.zig");
const render_json = @import("../render_json.zig");
const alloc_mod = @import("alloc");
const format = @import("format.zig");

pub const EventRecordRaw = format.EventRecordRaw;

pub const JsonMode = enum { single, lines };

pub const OutputMode = enum { xml, json_single, json_lines };

/// Non-generic output serializer using concrete std.Io.Writer.
pub const OutputWriter = struct {
    /// Destination writer for final output (null for serialize-only mode)
    dest: ?*std.Io.Writer,
    /// Output format mode
    mode: OutputMode,
    /// Allocating writer for building serialized output (auto-grows, retains capacity)
    scratch: std.Io.Writer.Allocating,

    pub fn initXml(dest: *std.Io.Writer) OutputWriter {
        return .{
            .dest = dest,
            .mode = .xml,
            .scratch = std.Io.Writer.Allocating.initCapacity(alloc_mod.get(), 4096) catch .init(alloc_mod.get()),
        };
    }

    pub fn initJson(dest: *std.Io.Writer, json_mode: JsonMode) OutputWriter {
        return .{
            .dest = dest,
            .mode = if (json_mode == .single) .json_single else .json_lines,
            .scratch = std.Io.Writer.Allocating.initCapacity(alloc_mod.get(), 4096) catch .init(alloc_mod.get()),
        };
    }

    /// Initialize for serialize-only mode (no destination writer needed).
    pub fn initSerializeOnly(mode_: OutputMode) OutputWriter {
        return .{
            .dest = null,
            .mode = mode_,
            .scratch = std.Io.Writer.Allocating.initCapacity(alloc_mod.get(), 4096) catch .init(alloc_mod.get()),
        };
    }

    pub fn deinit(self: *OutputWriter) void {
        self.scratch.deinit();
    }

    pub fn serializeRecord(self: *OutputWriter, record: EventRecordRaw, ctx: *binxml.Context) ![]const u8 {
        self.scratch.clearRetainingCapacity();
        const w: *std.Io.Writer = &self.scratch.writer;
        switch (self.mode) {
            .xml => {
                try render_xml.renderXmlWithContext(ctx, record.chunk_buf, record.binxml, w);
                try w.writeByte('\n');
            },
            .json_single, .json_lines => {
                // Rust-compatible format: {"Event": ...}
                const tree = try binxml.parseRecord(ctx, record.chunk_buf, record.binxml);
                try w.writeAll("{\"Event\":");
                try render_json.renderElementJson(tree.element, ctx.arena.allocator(), w);
                try w.writeAll("}\n");
            },
        }
        return self.scratch.written();
    }

    pub fn flush(self: *OutputWriter) void {
        if (self.dest) |dest| dest.flush() catch {};
    }
};
