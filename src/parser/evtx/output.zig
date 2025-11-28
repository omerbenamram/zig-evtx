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

pub const EventRecordView = format.EventRecordView;

pub const JsonMode = enum { single, lines };

pub const OutputMode = enum { xml, json_single, json_lines };

/// Non-generic output serializer using concrete std.Io.Writer.
pub const OutputWriter = struct {
    /// Destination writer for final output (null for serialize-only mode)
    dest: ?*std.Io.Writer,
    /// Output format mode
    mode: OutputMode,
    /// Allocating writer for building serialized output
    scratch: std.Io.Writer.Allocating,
    /// Size hint for pre-allocation
    last_size_hint: usize,
    /// Optional reusable rendering context provided by parser (per-chunk)
    ctx: ?*binxml.Context = null,
    /// Exponential moving average of previous serialized sizes for pre-sizing
    ema_size: f64 = 0.0,
    ema_alpha: f64 = 0.25,

    pub fn initXml(dest: *std.Io.Writer) OutputWriter {
        return .{
            .dest = dest,
            .mode = .xml,
            .scratch = std.Io.Writer.Allocating.initCapacity(alloc_mod.get(), 4096) catch std.Io.Writer.Allocating.init(alloc_mod.get()),
            .last_size_hint = 4096,
        };
    }

    pub fn initJson(dest: *std.Io.Writer, json_mode: JsonMode) OutputWriter {
        return .{
            .dest = dest,
            .mode = if (json_mode == .single) .json_single else .json_lines,
            .scratch = std.Io.Writer.Allocating.initCapacity(alloc_mod.get(), 4096) catch std.Io.Writer.Allocating.init(alloc_mod.get()),
            .last_size_hint = 4096,
        };
    }

    /// Initialize for serialize-only mode (no destination writer needed).
    /// Use serializeRecord() to get bytes; writeRecord() will fail.
    pub fn initSerializeOnly(mode_: OutputMode) OutputWriter {
        return .{
            .dest = null,
            .mode = mode_,
            .scratch = std.Io.Writer.Allocating.initCapacity(alloc_mod.get(), 4096) catch std.Io.Writer.Allocating.init(alloc_mod.get()),
            .last_size_hint = 4096,
        };
    }

    pub fn deinit(self: *OutputWriter) void {
        self.scratch.deinit();
    }

    pub fn setContext(self: *OutputWriter, c: *binxml.Context) void {
        self.ctx = c;
    }

    fn reserveScratch(self: *OutputWriter) void {
        // Reserve based on last serialized size (+25%) and EMA of recent sizes.
        const slack: usize = 512;
        const growth: usize = self.last_size_hint / 4; // +25%
        var target: usize = self.last_size_hint + growth + slack;
        if (self.ema_size > 0.0) {
            const ema_scaled: f64 = self.ema_size * 1.10 + 512.0;
            const ema_usize: usize = @intFromFloat(ema_scaled);
            if (ema_usize > target) target = ema_usize;
        }
        const max_cap: usize = 4 * 1024 * 1024; // clamp to 4 MiB retained capacity
        if (target > max_cap) target = max_cap;

        // Clear scratch buffer (keep capacity)
        self.scratch.clearRetainingCapacity();
        self.scratch.ensureTotalCapacity(target) catch {};
    }

    pub fn writeRecord(self: *OutputWriter, record: EventRecordView) !void {
        self.reserveScratch();
        const w: *std.Io.Writer = &self.scratch.writer;
        switch (self.mode) {
            .xml => {
                if (self.ctx) |ctx| {
                    try render_xml.renderXmlWithContext(ctx, record.chunk_buf, record.raw_xml, w);
                } else {
                    var local_ctx = try binxml.Context.init(alloc_mod.get());
                    defer local_ctx.deinit();
                    try render_xml.renderXmlWithContext(&local_ctx, record.chunk_buf, record.raw_xml, w);
                }
                try w.writeByte('\n');
            },
            .json_single, .json_lines => {
                try w.writeAll("{");
                try w.print("\"event_record_id\":{d},\"timestamp_filetime\":{d},\"Event\":", .{ record.id, record.timestamp_filetime });
                if (self.ctx) |ctx| {
                    var builder = binxml.Builder.init(ctx);
                    const root = try builder.build(record.chunk_buf, record.raw_xml);
                    try render_json.renderElementJson(root, ctx.arena.allocator(), w);
                } else {
                    var local_ctx = try binxml.Context.init(alloc_mod.get());
                    defer local_ctx.deinit();
                    var builder = binxml.Builder.init(&local_ctx);
                    const root = try builder.build(record.chunk_buf, record.raw_xml);
                    try render_json.renderElementJson(root, local_ctx.arena.allocator(), w);
                }
                try w.writeAll("}\n");
            },
        }
        // Emit once to the underlying writer and update size hint
        const written = self.scratch.written();
        if (self.dest) |dest| try dest.writeAll(written);
        self.last_size_hint = written.len;
        // Update EMA for future reservations
        const cur_len_f: f64 = @floatFromInt(written.len);
        if (self.ema_size == 0.0) {
            self.ema_size = cur_len_f;
        } else {
            self.ema_size = self.ema_size + self.ema_alpha * (cur_len_f - self.ema_size);
        }
    }

    pub fn serializeRecord(self: *OutputWriter, record: EventRecordView) ![]const u8 {
        self.reserveScratch();
        const w: *std.Io.Writer = &self.scratch.writer;
        switch (self.mode) {
            .xml => {
                if (self.ctx) |ctx| {
                    try render_xml.renderXmlWithContext(ctx, record.chunk_buf, record.raw_xml, w);
                } else {
                    var local_ctx = try binxml.Context.init(alloc_mod.get());
                    defer local_ctx.deinit();
                    try render_xml.renderXmlWithContext(&local_ctx, record.chunk_buf, record.raw_xml, w);
                }
                try w.writeByte('\n');
            },
            .json_single, .json_lines => {
                try w.writeAll("{");
                try w.print("\"event_record_id\":{d},\"timestamp_filetime\":{d},\"Event\":", .{ record.id, record.timestamp_filetime });
                if (self.ctx) |ctx| {
                    var builder = binxml.Builder.init(ctx);
                    const root = try builder.build(record.chunk_buf, record.raw_xml);
                    try render_json.renderElementJson(root, ctx.arena.allocator(), w);
                } else {
                    var local_ctx = try binxml.Context.init(alloc_mod.get());
                    defer local_ctx.deinit();
                    var builder = binxml.Builder.init(&local_ctx);
                    const root = try builder.build(record.chunk_buf, record.raw_xml);
                    try render_json.renderElementJson(root, local_ctx.arena.allocator(), w);
                }
                try w.writeAll("}\n");
            },
        }
        const written = self.scratch.written();
        self.last_size_hint = written.len;
        const cur_len_f: f64 = @floatFromInt(written.len);
        if (self.ema_size == 0.0) self.ema_size = cur_len_f else self.ema_size = self.ema_size + self.ema_alpha * (cur_len_f - self.ema_size);
        return written;
    }

    pub fn flush(self: *OutputWriter) void {
        if (self.dest) |dest| dest.flush() catch {};
    }
};
