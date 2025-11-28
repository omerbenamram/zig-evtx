//! EVTX binary format types: file header, chunk, record structures.

const std = @import("std");
const crc32 = std.hash.crc;
const binxml = @import("../binxml/mod.zig");
const render_xml = @import("../render_xml.zig");
const render_json = @import("../render_json.zig");
const alloc_mod = @import("alloc");

pub const FileHeader = struct {
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

    pub fn read(reader: anytype) !FileHeader {
        var buf: [4096]u8 = undefined;
        try reader.interface.readSliceAll(&buf);
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

    pub fn validateChecksum(self: *const FileHeader) !void {
        _ = self;
    }
};

pub const Chunk = struct {
    header: ChunkHeader,
    buf: [65536]u8,

    pub fn read(reader: anytype) !Chunk {
        var buf: [65536]u8 = undefined;
        try reader.interface.readSliceAll(&buf);
        const h = try ChunkHeader.parse(&buf);
        return .{ .header = h, .buf = buf };
    }

    pub fn validateChecksums(self: *const Chunk) !void {
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

    pub fn records(self: *const Chunk) RecordIterator {
        // EVTX chunk header is 512 bytes; event data starts at 512
        return RecordIterator{ .chunk = self, .offset = 512 };
    }
};

pub const ChunkHeader = struct {
    header_size: u32,
    last_event_record_offset: u32,
    free_space_offset: u32,
    // Parsed guidance from chunk header arrays (relative offsets from chunk start)
    common_string_offsets: [64]u32 = [_]u32{0} ** 64,
    template_ptrs: [32]u32 = [_]u32{0} ** 32,
    common_strings_count: usize = 0,
    template_ptrs_count: usize = 0,

    pub fn parse(buf: *const [65536]u8) !ChunkHeader {
        if (!std.mem.eql(u8, buf[0..8], "ElfChnk\x00")) return error.BadChunkSignature;
        const header_size = std.mem.readInt(u32, buf[40..44], .little);
        const last_event_record_offset = std.mem.readInt(u32, buf[44..48], .little);
        const free_space_offset = std.mem.readInt(u32, buf[48..52], .little);
        var ch: ChunkHeader = .{ .header_size = header_size, .last_event_record_offset = last_event_record_offset, .free_space_offset = free_space_offset };
        // Common string offset array at 128: 64 u32
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            const off = std.mem.readInt(u32, buf[128 + i * 4 .. 128 + i * 4 + 4][0..4], .little);
            ch.common_string_offsets[i] = off;
            if (off != 0 and off < buf.len) ch.common_strings_count += 1;
        }
        // TemplatePtr array at 384: 32 u32
        i = 0;
        while (i < 32) : (i += 1) {
            const off = std.mem.readInt(u32, buf[384 + i * 4 .. 384 + i * 4 + 4][0..4], .little);
            ch.template_ptrs[i] = off;
            if (off != 0 and off < buf.len) ch.template_ptrs_count += 1;
        }
        return ch;
    }
};

pub const RecordIterator = struct {
    chunk: *const Chunk,
    offset: u32,

    pub fn next(self: *RecordIterator) !?EventRecordRaw {
        if (self.offset == 0 or self.offset + 8 > self.chunk.buf.len) return null;
        // Stop when we reach or pass the free-space region
        if (self.offset >= self.chunk.header.free_space_offset) return null;
        const slice = self.chunk.buf[self.offset..];
        if (!std.mem.eql(u8, slice[0..4], &[_]u8{ 0x2a, 0x2a, 0x00, 0x00 })) return null;
        const size = std.mem.readInt(u32, slice[4..8], .little);
        // Treat structurally bad tail as end-of-records rather than hard error
        if (size < 32) return null;
        // If the record claims to run past the free-space boundary or chunk buffer, stop
        if (self.offset + size > self.chunk.buf.len or (self.offset + size) > self.chunk.header.free_space_offset) return null;
        const identifier = std.mem.readInt(u64, slice[8..16], .little);
        const written = std.mem.readInt(u64, slice[16..24], .little);
        const end_slice = slice[size - 4 .. size][0..4];
        const end_copy = std.mem.readInt(u32, end_slice, .little);
        // Mismatched end size indicates a truncated tail; stop record iteration
        if (end_copy != size) return null;
        const event_data = slice[24 .. size - 4];
        const rec = EventRecordRaw{ .identifier = identifier, .written_time = written, .binxml = event_data, .chunk_buf = &self.chunk.buf };
        self.offset += size;
        return rec;
    }
};

pub const EventRecordRaw = struct {
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

    pub fn writeXml(self: *const EventRecordView, w: anytype) !void {
        // Buffer per-record output to avoid leaking partial garbage on failures
        var ctx = try binxml.Context.init(alloc_mod.get());
        defer ctx.deinit();
        var buf = std.ArrayList(u8).initCapacity(alloc_mod.get(), 0) catch return;
        defer buf.deinit(alloc_mod.get());
        var bw = buf.writer(alloc_mod.get());
        try render_xml.renderXmlWithContext(&ctx, self.chunk_buf, self.raw_xml, bw);
        try bw.writeByte('\n');
        try w.interface.writeAll(buf.items);
    }

    pub fn writeJson(self: *const EventRecordView, w: anytype) !void {
        // Buffer full JSON object per record to avoid corrupting stream on errors
        var buf = std.ArrayList(u8).initCapacity(alloc_mod.get(), 0) catch return;
        defer buf.deinit(alloc_mod.get());
        var bw = buf.writer(alloc_mod.get());
        try bw.writeAll("{");
        try bw.print("\"event_record_id\":{d},\"timestamp_filetime\":{d},\"Event\":", .{ self.id, self.timestamp_filetime });
        var ctx = try binxml.Context.init(alloc_mod.get());
        defer ctx.deinit();
        var builder = binxml.Builder.init(&ctx);
        const root = try builder.build(self.chunk_buf, self.raw_xml);
        try render_json.renderElementJson(self.chunk_buf, root, ctx.arena.allocator(), bw);
        try bw.writeAll("}\n");
        try w.interface.writeAll(buf.items);
    }
};
