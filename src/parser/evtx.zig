const std = @import("std");
const crc32 = std.hash.crc;
const binxml = @import("binxml.zig");

pub const ParserOptions = struct {
    validate_checksums: bool = true,
    verbose: bool = false,
    // 0 means no limit
    max_records: usize = 0,
};

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

        pub fn initXml(w: W) @This() {
            return .{ .w = w, .mode = .xml };
        }

        pub fn initJson(w: W, json_mode: Output.JsonMode) @This() {
            return .{ .w = w, .mode = if (json_mode == .single) .json_single else .json_lines };
        }

        pub fn writeRecord(self: *const @This(), record: EventRecordView) !void {
            switch (self.mode) {
                .xml => try record.writeXml(self.w),
                .json_single => try record.writeJson(self.w, .single),
                .json_lines => try record.writeJson(self.w, .lines),
            }
        }
    };
}

pub const EvtxParser = struct {
    allocator: std.mem.Allocator,
    opts: ParserOptions,

    pub fn init(allocator: std.mem.Allocator, opts: ParserOptions) !EvtxParser {
        return .{ .allocator = allocator, .opts = opts };
    }

    pub fn deinit(self: *EvtxParser) void {
        _ = self;
    }

    pub fn parse(self: *EvtxParser, reader: anytype, out: anytype) !void {
        if (self.opts.verbose) {
            try std.io.getStdErr().writer().print("[evtx] reading file header...\n", .{});
        }
        var hdr: FileHeader = try FileHeader.read(reader);
        if (self.opts.validate_checksums) try hdr.validateChecksum();

        var chunk_index: usize = 0;
        var emitted: usize = 0;
        var failed: usize = 0;
        var ctx = try binxml.Context.init(self.allocator);
        defer ctx.deinit();
        while (chunk_index < hdr.num_chunks) : (chunk_index += 1) {
            var chunk = try Chunk.read(reader);
            if (self.opts.verbose) {
                try std.io.getStdErr().writer().print("[evtx] chunk {d}: free_off=0x{x}, last_rec_off=0x{x}\n", .{ chunk_index, chunk.header.free_space_offset, chunk.header.last_event_record_offset });
            }
            if (self.opts.validate_checksums) try chunk.validateChecksums();
            ctx.resetPerChunk();
            var rec_iter = chunk.records();
            while (try rec_iter.next()) |rec| {
                if (self.opts.verbose) {
                    try std.io.getStdErr().writer().print("[evtx] record id={d} time={d}\n", .{ rec.identifier, rec.written_time });
                }
                const view = EventRecordView{ .id = rec.identifier, .timestamp_filetime = rec.written_time, .raw_xml = rec.binxml, .chunk_buf = rec.chunk_buf };
                out.writeRecord(view) catch |e| {
                    failed += 1;
                    if (self.opts.verbose) {
                        try std.io.getStdErr().writer().print("[evtx] record id={d} parse error: {s}\n", .{ rec.identifier, @errorName(e) });
                    }
                    continue;
                };
                emitted += 1;
                if (self.opts.max_records != 0 and emitted >= self.opts.max_records) {
                    return;
                }
            }
        }
        if (self.opts.verbose) {
            try std.io.getStdErr().writer().print("[evtx] done. emitted={d} failed={d}\n", .{ emitted, failed });
        }
    }
};

const FileHeader = struct {
    first_chunk: u64,
    last_chunk: u64,
    next_record_id: u64,
    header_size: u32,
    minor: u16,
    major: u16,
    header_block_size: u16,
    num_chunks: u16,
    flags: u32,
    checksum: u32,

    fn read(reader: anytype) !FileHeader {
        var buf: [4096]u8 = undefined;
        try reader.readNoEof(&buf);
        if (!std.mem.eql(u8, buf[0..8], "ElfFile\x00")) return error.BadSignature;
        const first_chunk = std.mem.readInt(u64, buf[8..16], .little);
        const last_chunk = std.mem.readInt(u64, buf[16..24], .little);
        const next_record_id = std.mem.readInt(u64, buf[24..32], .little);
        const header_size = std.mem.readInt(u32, buf[32..36], .little);
        const minor = std.mem.readInt(u16, buf[36..38], .little);
        const major = std.mem.readInt(u16, buf[38..40], .little);
        const header_block_size = std.mem.readInt(u16, buf[40..42], .little);
        const num_chunks = std.mem.readInt(u16, buf[42..44], .little);
        const flags = std.mem.readInt(u32, buf[120..124], .little);
        const checksum = std.mem.readInt(u32, buf[124..128], .little);

        // Verify header CRC32 over first 120 bytes
        var hasher = crc32.Crc32.init();
        hasher.update(buf[0..120]);
        const computed = hasher.final();
        if (computed != checksum) return error.BadHeaderChecksum;
        return .{
            .first_chunk = first_chunk,
            .last_chunk = last_chunk,
            .next_record_id = next_record_id,
            .header_size = header_size,
            .minor = minor,
            .major = major,
            .header_block_size = header_block_size,
            .num_chunks = num_chunks,
            .flags = flags,
            .checksum = checksum,
        };
    }

    fn validateChecksum(self: *const FileHeader) !void {
        _ = self;
    }
};

const Chunk = struct {
    header: ChunkHeader,
    buf: [65536]u8,

    fn read(reader: anytype) !Chunk {
        var buf: [65536]u8 = undefined;
        try reader.readNoEof(&buf);
        const h = try ChunkHeader.parse(&buf);
        return .{ .header = h, .buf = buf };
    }

    fn validateChecksums(self: *const Chunk) !void {
        // Header checksum: CRC32 over bytes 0..120 and 128..512
        const stored_hdr_crc = std.mem.readInt(u32, self.buf[124..128], .little);
        var h = crc32.Crc32.init();
        h.update(self.buf[0..120]);
        h.update(self.buf[128..512]);
        if (h.final() != stored_hdr_crc) return error.BadChunkHeaderChecksum;

        // Events checksum: CRC32 over event records data
        const stored_events_crc = std.mem.readInt(u32, self.buf[52..56], .little);
        var e = crc32.Crc32.init();
        const start: usize = 512;
        const end: usize = @min(self.buf.len, self.header.free_space_offset);
        if (end > start) e.update(self.buf[start..end]);
        if (e.final() != stored_events_crc) return error.BadChunkEventsChecksum;
    }

    fn records(self: *const Chunk) RecordIterator {
        // EVTX chunk header is 512 bytes; event data starts at 512
        return RecordIterator{ .chunk = self, .offset = 512 };
    }
};

const ChunkHeader = struct {
    header_size: u32,
    last_event_record_offset: u32,
    free_space_offset: u32,

    fn parse(buf: *const [65536]u8) !ChunkHeader {
        if (!std.mem.eql(u8, buf[0..8], "ElfChnk\x00")) return error.BadChunkSignature;
        const header_size = std.mem.readInt(u32, buf[40..44], .little);
        const last_event_record_offset = std.mem.readInt(u32, buf[44..48], .little);
        const free_space_offset = std.mem.readInt(u32, buf[48..52], .little);
        return .{ .header_size = header_size, .last_event_record_offset = last_event_record_offset, .free_space_offset = free_space_offset };
    }
};

const RecordIterator = struct {
    chunk: *const Chunk,
    offset: u32,

    fn next(self: *RecordIterator) !?EventRecordRaw {
        if (self.offset == 0 or self.offset + 8 > self.chunk.buf.len) return null;
        if (self.offset > self.chunk.header.free_space_offset) return null;
        const slice = self.chunk.buf[self.offset..];
        if (!std.mem.eql(u8, slice[0..4], &[_]u8{ 0x2a, 0x2a, 0x00, 0x00 })) return null;
        const size = std.mem.readInt(u32, slice[4..8], .little);
        if (size < 32 or self.offset + size > self.chunk.buf.len) return error.CorruptRecord;
        const identifier = std.mem.readInt(u64, slice[8..16], .little);
        const written = std.mem.readInt(u64, slice[16..24], .little);
        const end_slice = slice[size - 4 .. size][0..4];
        const end_copy = std.mem.readInt(u32, end_slice, .little);
        if (end_copy != size) return error.SizeMismatch;
        const event_data = slice[24 .. size - 4];
        const rec = EventRecordRaw{ .identifier = identifier, .written_time = written, .binxml = event_data, .chunk_buf = &self.chunk.buf };
        self.offset += size;
        return rec;
    }
};

const EventRecordRaw = struct {
    identifier: u64,
    written_time: u64,
    binxml: []const u8,
    chunk_buf: *const [65536]u8,
};

pub const EventRecordView = struct {
    id: u64,
    timestamp_filetime: u64,
    raw_xml: []const u8,
    chunk_buf: *const [65536]u8,

    fn writeXml(self: *const EventRecordView, w: anytype) !void {
        var ctx = try binxml.Context.init(std.heap.page_allocator);
        defer ctx.deinit();
        try binxml.renderWithContext(&ctx, self.chunk_buf, self.raw_xml, .xml, w);
        try w.writeByte('\n');
    }

    const JsonOutMode = enum { single, lines };
    fn writeJson(self: *const EventRecordView, w: anytype, mode: JsonOutMode) !void {
        const body_mode: binxml.RenderMode = switch (mode) {
            .lines => .jsonl,
            .single => .json,
        };
        try w.writeAll("{");
        try w.print("\"event_record_id\":{d},\"timestamp_filetime\":{d},\"Event\":", .{ self.id, self.timestamp_filetime });
        var ctx = try binxml.Context.init(std.heap.page_allocator);
        defer ctx.deinit();
        try binxml.renderWithContext(&ctx, self.chunk_buf, self.raw_xml, body_mode, w);
        try w.writeAll("}\n");
    }
};
