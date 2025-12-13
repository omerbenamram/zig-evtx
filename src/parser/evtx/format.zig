//! EVTX binary format types: file header, chunk, record structures.

const std = @import("std");
const crc32 = std.hash.crc;
const binxml = @import("../binxml/mod.zig");
const render_xml = @import("../render_xml.zig");
const render_json = @import("../render_json.zig");
const alloc_mod = @import("alloc");

/// EVTX file header size in bytes
pub const FILE_HEADER_SIZE: usize = 4096;

/// EVTX chunk size in bytes (64 KB)
pub const CHUNK_SIZE: usize = 65536;

/// Chunk header size - event data starts after this
pub const CHUNK_HEADER_SIZE: usize = 512;

/// Number of common string offset slots in chunk header
pub const COMMON_STRING_SLOTS: usize = 64;

/// Number of template pointer slots in chunk header
pub const TEMPLATE_PTR_SLOTS: usize = 32;

/// Read all bytes into buffer from any reader type.
/// Supports both std.fs.File.reader (with .interface) and RecordStream (with .readNoEof).
fn readAll(reader: anytype, buf: []u8) !void {
    const Reader = @TypeOf(reader);
    const ReaderType = switch (@typeInfo(Reader)) {
        .pointer => |ptr| ptr.child,
        else => Reader,
    };
    if (@hasField(ReaderType, "interface")) {
        try reader.interface.readSliceAll(buf);
    } else if (@hasDecl(ReaderType, "readNoEof")) {
        try reader.readNoEof(buf);
    } else {
        @compileError("Reader must have .interface.readSliceAll or .readNoEof method");
    }
}

/// Packed struct for file header core fields at offset 8-44
pub const FileHeaderCore = packed struct {
    first_chunk: u64,
    last_chunk: u64,
    next_record_id: u64,
    header_size: u32,
    minor: u16,
    major: u16,
    header_block_size: u16,
    num_chunks: u16,
};

/// Packed struct for file header tail fields at offset 120-128
pub const FileHeaderTail = packed struct {
    flags: u32,
    checksum: u32,
};

pub const FileHeader = struct {
    core: FileHeaderCore,
    tail: FileHeaderTail,

    pub fn read(reader: anytype) !FileHeader {
        var buf: [FILE_HEADER_SIZE]u8 = undefined;
        try readAll(reader, &buf);
        if (!std.mem.eql(u8, buf[0..8], "ElfFile\x00")) return error.BadSignature;

        // Read contiguous fields via packed structs (comptime type dispatch)
        const core = std.mem.bytesToValue(FileHeaderCore, buf[8..44]);
        const tail = std.mem.bytesToValue(FileHeaderTail, buf[120..128]);

        // Verify header CRC32 over first 120 bytes
        var hasher = crc32.Crc32.init();
        hasher.update(buf[0..120]);
        const computed = hasher.final();
        if (computed != tail.checksum) return error.BadHeaderChecksum;

        return .{ .core = core, .tail = tail };
    }
};

pub const Chunk = struct {
    header: ChunkHeader,
    buf: [CHUNK_SIZE]u8,

    pub fn read(reader: anytype) !Chunk {
        var buf: [CHUNK_SIZE]u8 = undefined;
        try readAll(reader, &buf);
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
        // Event data starts after chunk header
        return RecordIterator{ .chunk = self, .offset = CHUNK_HEADER_SIZE };
    }
};

/// Packed struct for chunk header core fields at offset 40-52 (comptime type dispatch)
const ChunkHeaderCore = packed struct {
    header_size: u32,
    last_event_record_offset: u32,
    free_space_offset: u32,
};

pub const ChunkHeader = struct {
    header_size: u32,
    last_event_record_offset: u32,
    free_space_offset: u32,
    // Parsed guidance from chunk header arrays (relative offsets from chunk start)
    common_string_offsets: [COMMON_STRING_SLOTS]u32 = [_]u32{0} ** COMMON_STRING_SLOTS,
    template_ptrs: [TEMPLATE_PTR_SLOTS]u32 = [_]u32{0} ** TEMPLATE_PTR_SLOTS,
    common_strings_count: usize = 0,
    template_ptrs_count: usize = 0,

    pub fn parse(buf: *const [CHUNK_SIZE]u8) !ChunkHeader {
        if (!std.mem.eql(u8, buf[0..8], "ElfChnk\x00")) return error.BadChunkSignature;

        // Read core header fields via packed struct (comptime type dispatch)
        const core = std.mem.bytesToValue(ChunkHeaderCore, buf[40..52]);
        var ch: ChunkHeader = .{
            .header_size = core.header_size,
            .last_event_record_offset = core.last_event_record_offset,
            .free_space_offset = core.free_space_offset,
        };

        // Common string offset array at 128: COMMON_STRING_SLOTS u32
        for (0..COMMON_STRING_SLOTS) |i| {
            const off = std.mem.readInt(u32, buf[128 + i * 4 ..][0..4], .little);
            ch.common_string_offsets[i] = off;
            if (off != 0 and off < buf.len) ch.common_strings_count += 1;
        }
        // TemplatePtr array at 384: TEMPLATE_PTR_SLOTS u32
        for (0..TEMPLATE_PTR_SLOTS) |i| {
            const off = std.mem.readInt(u32, buf[384 + i * 4 ..][0..4], .little);
            ch.template_ptrs[i] = off;
            if (off != 0 and off < buf.len) ch.template_ptrs_count += 1;
        }
        return ch;
    }
};

/// Packed struct for record header fields at offset 4-24 (comptime type dispatch)
const RecordHeaderCore = packed struct {
    size: u32,
    identifier: u64,
    written_time: u64,
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

        // Read header fields via packed struct (comptime type dispatch)
        const hdr = std.mem.bytesToValue(RecordHeaderCore, slice[4..24]);
        const size = hdr.size;

        // Treat structurally bad tail as end-of-records rather than hard error
        if (size < 32) return null;
        // If the record claims to run past the free-space boundary or chunk buffer, stop
        if (self.offset + size > self.chunk.buf.len or (self.offset + size) > self.chunk.header.free_space_offset) return null;
        const end_copy = std.mem.readInt(u32, slice[size - 4 .. size][0..4], .little);
        // Mismatched end size indicates a truncated tail; stop record iteration
        if (end_copy != size) return null;
        const event_data = slice[24 .. size - 4];
        const rec = EventRecordRaw{ .identifier = hdr.identifier, .written_time = hdr.written_time, .binxml = event_data, .chunk_buf = &self.chunk.buf };
        self.offset += size;
        return rec;
    }
};

pub const EventRecordRaw = struct {
    identifier: u64,
    written_time: u64,
    binxml: []const u8,
    chunk_buf: *const [CHUNK_SIZE]u8,
};
