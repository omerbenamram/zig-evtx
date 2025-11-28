//! Output serialization for EVTX records (XML/JSON).

const std = @import("std");
const binxml = @import("../binxml/mod.zig");
const render_xml = @import("../render_xml.zig");
const render_json = @import("../render_json.zig");
const alloc_mod = @import("alloc");
const format = @import("format.zig");

pub const EventRecordView = format.EventRecordView;

pub const Output = struct {
    pub const JsonMode = enum { single, lines };

    pub fn xml(writer: anytype) OutputImpl(@TypeOf(writer)) {
        return OutputImpl(@TypeOf(writer)).initXml(writer);
    }

    pub fn json(writer: anytype, mode: JsonMode) OutputImpl(@TypeOf(writer)) {
        return OutputImpl(@TypeOf(writer)).initJson(writer, mode);
    }
};

pub fn OutputImpl(comptime W: type) type {
    return struct {
        w: W,
        mode: enum { xml, json_single, json_lines },
        scratch: std.ArrayList(u8),
        last_size_hint: usize,
        // Optional reusable rendering context provided by parser (per-chunk)
        ctx: ?*binxml.Context = null,
        // Exponential moving average of previous serialized sizes for pre-sizing
        ema_size: f64 = 0.0,
        ema_alpha: f64 = 0.25,

        pub fn initXml(w: W) @This() {
            return .{ .w = w, .mode = .xml, .scratch = .empty, .last_size_hint = 4096 };
        }

        pub fn initJson(w: W, json_mode: Output.JsonMode) @This() {
            return .{ .w = w, .mode = if (json_mode == .single) .json_single else .json_lines, .scratch = .empty, .last_size_hint = 4096 };
        }

        pub fn setContext(self: *@This(), c: *binxml.Context) void {
            self.ctx = c;
        }

        fn reserveScratch(self: *@This()) !void {
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
            self.scratch.clearRetainingCapacity();
            try self.scratch.ensureTotalCapacityPrecise(alloc_mod.get(), target);
        }

        pub fn writeRecord(self: *@This(), record: EventRecordView) !void {
            try self.reserveScratch();
            var bw = self.scratch.writer(alloc_mod.get());
            switch (self.mode) {
                .xml => {
                    if (self.ctx) |ctx| {
                        try render_xml.renderXmlWithContext(ctx, record.chunk_buf, record.raw_xml, bw);
                    } else {
                        var local_ctx = try binxml.Context.init(alloc_mod.get());
                        defer local_ctx.deinit();
                        try render_xml.renderXmlWithContext(&local_ctx, record.chunk_buf, record.raw_xml, bw);
                    }
                    try bw.writeByte('\n');
                },
                .json_single, .json_lines => {
                    try bw.writeAll("{");
                    try bw.print("\"event_record_id\":{d},\"timestamp_filetime\":{d},\"Event\":", .{ record.id, record.timestamp_filetime });
                    if (self.ctx) |ctx| {
                        var builder = binxml.Builder.init(ctx);
                        const root = try builder.build(record.chunk_buf, record.raw_xml);
                        try render_json.renderElementJson(record.chunk_buf, root, ctx.arena.allocator(), bw);
                    } else {
                        var local_ctx = try binxml.Context.init(alloc_mod.get());
                        defer local_ctx.deinit();
                        var builder = binxml.Builder.init(&local_ctx);
                        const root = try builder.build(record.chunk_buf, record.raw_xml);
                        try render_json.renderElementJson(record.chunk_buf, root, local_ctx.arena.allocator(), bw);
                    }
                    try bw.writeAll("}\n");
                },
            }
            // Emit once to the underlying writer and update size hint
            var outw: *W = @constCast(&self.w);
            try outw.interface.writeAll(self.scratch.items);
            self.last_size_hint = self.scratch.items.len;
            // Update EMA for future reservations
            const cur_len_f: f64 = @floatFromInt(self.scratch.items.len);
            if (self.ema_size == 0.0) {
                self.ema_size = cur_len_f;
            } else {
                self.ema_size = self.ema_size + self.ema_alpha * (cur_len_f - self.ema_size);
            }
        }

        pub fn serializeRecord(self: *@This(), record: EventRecordView) ![]const u8 {
            try self.reserveScratch();
            var bw = self.scratch.writer(alloc_mod.get());
            switch (self.mode) {
                .xml => {
                    if (self.ctx) |ctx| {
                        try render_xml.renderXmlWithContext(ctx, record.chunk_buf, record.raw_xml, bw);
                    } else {
                        var local_ctx = try binxml.Context.init(alloc_mod.get());
                        defer local_ctx.deinit();
                        try render_xml.renderXmlWithContext(&local_ctx, record.chunk_buf, record.raw_xml, bw);
                    }
                    try bw.writeByte('\n');
                },
                .json_single, .json_lines => {
                    try bw.writeAll("{");
                    try bw.print("\"event_record_id\":{d},\"timestamp_filetime\":{d},\"Event\":", .{ record.id, record.timestamp_filetime });
                    if (self.ctx) |ctx| {
                        var builder = binxml.Builder.init(ctx);
                        const root = try builder.build(record.chunk_buf, record.raw_xml);
                        try render_json.renderElementJson(record.chunk_buf, root, ctx.arena.allocator(), bw);
                    } else {
                        var local_ctx = try binxml.Context.init(alloc_mod.get());
                        defer local_ctx.deinit();
                        var builder = binxml.Builder.init(&local_ctx);
                        const root = try builder.build(record.chunk_buf, record.raw_xml);
                        try render_json.renderElementJson(record.chunk_buf, root, local_ctx.arena.allocator(), bw);
                    }
                    try bw.writeAll("}\n");
                },
            }
            self.last_size_hint = self.scratch.items.len;
            const cur_len_f: f64 = @floatFromInt(self.scratch.items.len);
            if (self.ema_size == 0.0) self.ema_size = cur_len_f else self.ema_size = self.ema_size + self.ema_alpha * (cur_len_f - self.ema_size);
            return self.scratch.items;
        }

        pub fn flush(self: *@This()) void {
            // Flush the underlying writer
            var w_ptr: *W = @constCast(&self.w);
            w_ptr.interface.flush() catch {};
        }
    };
}
