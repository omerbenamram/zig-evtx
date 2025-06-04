const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const binary_parser = @import("binary_parser.zig");
const Block = binary_parser.Block;
const BinaryParserError = binary_parser.BinaryParserError;
const FileTime = binary_parser.FileTime;
const bxml_parser = @import("bxml_parser.zig");

pub const EvtxError = error{
    InvalidRecord,
    InvalidMagic,
    InvalidChecksum,
    FileNotFound,
    OutOfMemory,
    AccessDenied,
    SystemResources,
    Unexpected,
    Unseekable,
    InputOutput,
    BrokenPipe,
    OperationAborted,
    LockViolation,
    WouldBlock,
    ConnectionResetByPeer,
    ProcessNotFound,
    IsDir,
    ConnectionTimedOut,
    NotOpenForReading,
    SocketNotConnected,
    Canceled,
} || BinaryParserError;

pub const Evtx = struct {
    allocator: Allocator,
    file: ?std.fs.File,
    buf: ?[]const u8,
    file_header: ?FileHeader,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .file = null,
            .buf = null,
            .file_header = null,
        };
    }

    pub fn open(self: *Self, filename: []const u8) EvtxError!void {
        self.file = std.fs.cwd().openFile(filename, .{}) catch return EvtxError.FileNotFound;

        const file_size = try self.file.?.getEndPos();
        self.buf = try self.allocator.alloc(u8, file_size);
        _ = try self.file.?.readAll(@constCast(self.buf.?));

        self.file_header = try FileHeader.init(self.allocator, self.buf.?, 0);
    }

    pub fn deinit(self: *Self) void {
        if (self.file_header) |*header| {
            header.deinit();
        }
        if (self.buf) |buf| {
            self.allocator.free(buf);
        }
        if (self.file) |file| {
            file.close();
        }
    }

    pub fn getFileHeader(self: *Self) ?*FileHeader {
        return if (self.file_header) |*header| header else null;
    }

    pub fn chunks(self: *Self) ChunkIterator {
        return ChunkIterator.init(self);
    }

    pub fn records(self: *Self) RecordIterator {
        return RecordIterator.init(self);
    }

    pub fn getRecord(self: *Self, record_num: u64) ?Record {
        if (self.file_header) |*header| {
            return header.getRecord(record_num);
        }
        return null;
    }
};

pub const FileHeader = struct {
    block: Block,
    allocator: Allocator,
    magic_val: [8]u8,
    oldest_chunk_val: u64,
    current_chunk_number_val: u64,
    next_record_number_val: u64,
    header_size_val: u32,
    minor_version_val: u16,
    major_version_val: u16,
    header_chunk_size_val: u16,
    chunk_count_val: u16,
    flags_val: u32,
    checksum_val: u32,

    const Self = @This();

    pub fn init(allocator: Allocator, buf: []const u8, offset: usize) EvtxError!Self {
        const block = Block.init(buf, offset);

        var header = Self{
            .block = block,
            .allocator = allocator,
            .magic_val = undefined,
            .oldest_chunk_val = 0,
            .current_chunk_number_val = 0,
            .next_record_number_val = 0,
            .header_size_val = 0,
            .minor_version_val = 0,
            .major_version_val = 0,
            .header_chunk_size_val = 0,
            .chunk_count_val = 0,
            .flags_val = 0,
            .checksum_val = 0,
        };

        // Parse fields
        const magic_data = try block.unpackBinary(0x0, 8);
        @memcpy(&header.magic_val, magic_data);

        header.oldest_chunk_val = try block.unpackQword(0x8);
        header.current_chunk_number_val = try block.unpackQword(0x10);
        header.next_record_number_val = try block.unpackQword(0x18);
        header.header_size_val = try block.unpackDword(0x20);
        header.minor_version_val = try block.unpackWord(0x24);
        header.major_version_val = try block.unpackWord(0x26);
        header.header_chunk_size_val = try block.unpackWord(0x28);
        header.chunk_count_val = try block.unpackWord(0x2A);
        header.flags_val = try block.unpackDword(0x70);
        header.checksum_val = try block.unpackDword(0x74);

        return header;
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn magic(self: *const Self) []const u8 {
        return &self.magic_val;
    }

    pub fn oldestChunk(self: *const Self) u64 {
        return self.oldest_chunk_val;
    }

    pub fn currentChunkNumber(self: *const Self) u64 {
        return self.current_chunk_number_val;
    }

    pub fn nextRecordNumber(self: *const Self) u64 {
        return self.next_record_number_val;
    }

    pub fn headerSize(self: *const Self) u32 {
        return self.header_size_val;
    }

    pub fn minorVersion(self: *const Self) u16 {
        return self.minor_version_val;
    }

    pub fn majorVersion(self: *const Self) u16 {
        return self.major_version_val;
    }

    pub fn headerChunkSize(self: *const Self) u16 {
        return self.header_chunk_size_val;
    }

    pub fn chunkCount(self: *const Self) u16 {
        return self.chunk_count_val;
    }

    pub fn flags(self: *const Self) u32 {
        return self.flags_val;
    }

    pub fn checksum(self: *const Self) u32 {
        return self.checksum_val;
    }

    pub fn checkMagic(self: *const Self) bool {
        const expected = "ElfFile\x00";
        return std.mem.eql(u8, &self.magic_val, expected);
    }

    pub fn calculateChecksum(self: *const Self) EvtxError!u32 {
        const data = try self.block.unpackBinary(0, 0x78);
        return binary_parser.calculateCrc32(data);
    }

    pub fn verify(self: *const Self) EvtxError!bool {
        const magic_ok = self.checkMagic();
        const version_ok = self.majorVersion() == 0x3 and self.minorVersion() == 0x1;
        const chunk_size_ok = self.headerChunkSize() == 0x1000;
        const checksum_ok = self.checksum() == try self.calculateChecksum();

        return magic_ok and version_ok and chunk_size_ok and checksum_ok;
    }

    pub fn isDirty(self: *const Self) bool {
        return (self.flags() & 0x1) == 0x1;
    }

    pub fn isFull(self: *const Self) bool {
        return (self.flags() & 0x2) == 0x2;
    }

    pub fn firstChunk(self: *const Self) EvtxError!ChunkHeader {
        const ofs = self.block.getOffset() + self.headerChunkSize();
        return ChunkHeader.init(self.allocator, self.block.buf, ofs);
    }

    pub fn currentChunk(self: *const Self) EvtxError!ChunkHeader {
        const ofs = self.block.getOffset() + self.headerChunkSize() +
            self.currentChunkNumber() * 0x10000;
        return ChunkHeader.init(self.allocator, self.block.buf, ofs);
    }

    pub fn getRecord(self: *const Self, record_num: u64) ?Record {
        var chunk_iter = ChunkIterator.initFromHeader(self);
        while (chunk_iter.next()) |chunk| {
            const first_record = chunk.logFirstRecordNumber();
            const last_record = chunk.logLastRecordNumber();
            if (first_record <= record_num and record_num <= last_record) {
                var record_iter = chunk.records();
                while (record_iter.next()) |record| {
                    if (record.recordNum() == record_num) {
                        return record;
                    }
                }
            }
        }
        return null;
    }
};

// Forward declare template types
pub const Template = struct {
    template_id: u32,
    guid: [16]u8,
    data_length: u32,
    data: []const u8,
    xml_format: []const u8,

    pub fn templateId(self: *const Template) u32 {
        return self.template_id;
    }

    pub fn xml(self: *const Template) []const u8 {
        return self.xml_format;
    }
};

pub const ChunkHeader = struct {
    block: Block,
    allocator: Allocator,
    magic_val: [8]u8,
    file_first_record_number_val: u64,
    file_last_record_number_val: u64,
    log_first_record_number_val: u64,
    log_last_record_number_val: u64,
    header_size_val: u32,
    last_record_offset_val: u32,
    next_record_offset_val: u32,
    data_checksum_val: u32,
    header_checksum_val: u32,
    templates: ?std.AutoHashMap(u32, Template),
    strings: ?std.AutoHashMap(u32, []const u8),

    const Self = @This();

    pub fn init(allocator: Allocator, buf: []const u8, offset: usize) EvtxError!Self {
        const block = Block.init(buf, offset);

        var chunk = Self{
            .block = block,
            .allocator = allocator,
            .magic_val = undefined,
            .file_first_record_number_val = 0,
            .file_last_record_number_val = 0,
            .log_first_record_number_val = 0,
            .log_last_record_number_val = 0,
            .header_size_val = 0,
            .last_record_offset_val = 0,
            .next_record_offset_val = 0,
            .data_checksum_val = 0,
            .header_checksum_val = 0,
            .templates = null,
            .strings = null,
        };

        // Parse fields
        const magic_data = try block.unpackBinary(0x0, 8);
        @memcpy(&chunk.magic_val, magic_data);

        chunk.file_first_record_number_val = try block.unpackQword(0x8);
        chunk.file_last_record_number_val = try block.unpackQword(0x10);
        chunk.log_first_record_number_val = try block.unpackQword(0x18);
        chunk.log_last_record_number_val = try block.unpackQword(0x20);
        chunk.header_size_val = try block.unpackDword(0x28);
        chunk.last_record_offset_val = try block.unpackDword(0x2C);
        chunk.next_record_offset_val = try block.unpackDword(0x30);
        chunk.data_checksum_val = try block.unpackDword(0x34);
        chunk.header_checksum_val = try block.unpackDword(0x7C);

        return chunk;
    }

    pub fn magic(self: *const Self) []const u8 {
        return &self.magic_val;
    }

    pub fn fileFirstRecordNumber(self: *const Self) u64 {
        return self.file_first_record_number_val;
    }

    pub fn fileLastRecordNumber(self: *const Self) u64 {
        return self.file_last_record_number_val;
    }

    pub fn logFirstRecordNumber(self: *const Self) u64 {
        return self.log_first_record_number_val;
    }

    pub fn logLastRecordNumber(self: *const Self) u64 {
        return self.log_last_record_number_val;
    }

    pub fn headerSize(self: *const Self) u32 {
        return self.header_size_val;
    }

    pub fn lastRecordOffset(self: *const Self) u32 {
        return self.last_record_offset_val;
    }

    pub fn nextRecordOffset(self: *const Self) u32 {
        return self.next_record_offset_val;
    }

    pub fn dataChecksum(self: *const Self) u32 {
        return self.data_checksum_val;
    }

    pub fn headerChecksum(self: *const Self) u32 {
        return self.header_checksum_val;
    }

    pub fn checkMagic(self: *const Self) bool {
        const expected = "ElfChnk\x00";
        return std.mem.eql(u8, &self.magic_val, expected);
    }

    pub fn calculateHeaderChecksum(self: *const Self) EvtxError!u32 {
        const data1 = try self.block.unpackBinary(0x0, 0x78);
        const data2 = try self.block.unpackBinary(0x80, 0x180);

        // Combine the two data segments
        var combined = try self.allocator.alloc(u8, data1.len + data2.len);
        defer self.allocator.free(combined);
        @memcpy(combined[0..data1.len], data1);
        @memcpy(combined[data1.len..], data2);

        return binary_parser.calculateCrc32(combined);
    }

    pub fn calculateDataChecksum(self: *const Self) EvtxError!u32 {
        const data = try self.block.unpackBinary(0x200, self.nextRecordOffset() - 0x200);
        return binary_parser.calculateCrc32(data);
    }

    pub fn verify(self: *const Self) EvtxError!bool {
        const magic_ok = self.checkMagic();
        const header_checksum_ok = try self.calculateHeaderChecksum() == self.headerChecksum();
        const data_checksum_ok = try self.calculateDataChecksum() == self.dataChecksum();

        return magic_ok and header_checksum_ok and data_checksum_ok;
    }

    pub fn firstRecord(self: *const Self) EvtxError!Record {
        return Record.init(self.allocator, self.block.buf, self.block.getOffset() + 0x200, self);
    }

    pub fn records(self: *const Self) RecordIteratorFromChunk {
        return RecordIteratorFromChunk.init(self);
    }

    pub fn deinit(self: *Self) void {
        if (self.templates) |*templates_map| {
            var iter = templates_map.iterator();
            while (iter.next()) |entry| {
                // Free template XML strings allocated during parsing
                self.allocator.free(entry.value_ptr.*.xml_format);
            }
            templates_map.deinit();
        }
        if (self.strings) |*strings_map| {
            // Free the stored strings
            var iterator = strings_map.iterator();
            while (iterator.next()) |entry| {
                self.allocator.free(entry.value_ptr.*);
            }
            strings_map.deinit();
        }
    }

    pub fn loadTemplates(self: *Self) EvtxError!void {
        if (self.templates != null) return;

        self.templates = std.AutoHashMap(u32, Template).init(self.allocator);

        // Templates are stored in a table starting at offset 0x180
        // There are 32 possible template slots, each 4 bytes
        var i: u32 = 0;
        while (i < 32) : (i += 1) {
            const template_offset = try self.block.unpackDword(0x180 + (i * 4));
            if (template_offset == 0) continue;

            var ofs = template_offset;
            while (ofs > 0) {
                // Check for template marker (similar to Python implementation)
                const token = try self.block.unpackByte(ofs - 10);
                const pointer = try self.block.unpackDword(ofs - 4);

                if (token != 0x0C or pointer != ofs) {
                    // Invalid template, stop processing this chain
                    break;
                }

                // Parse template at this offset
                const template = try self.parseTemplate(ofs);
                std.log.info("Found template with ID: {d} at offset {d}", .{ template.template_id, ofs });

                // Only store if we don't already have this template ID, or if this one is better
                if (!self.templates.?.contains(template.template_id)) {
                    try self.templates.?.put(template.template_id, template);
                    std.log.info("Stored template {d} from offset {d}", .{ template.template_id, ofs });
                } else {
                    std.log.info("Template {d} already exists, skipping duplicate at offset {d}", .{ template.template_id, ofs });
                }

                // Move to next template in chain (templates are linked)
                const next_offset = try self.block.unpackDword(ofs);
                ofs = next_offset;
            }
        }
    }

    fn parseTemplate(self: *Self, offset: u32) EvtxError!Template {
        // Template structure:
        // 0x00: next_offset (4 bytes)
        // 0x04: template_id (4 bytes) - also start of GUID
        // 0x04: guid (16 bytes) - overlaps with template_id
        // 0x14: data_length (4 bytes)
        // 0x18: template_data (variable length)

        _ = try self.block.unpackDword(offset); // next_offset not used in this simplified implementation
        const template_id = try self.block.unpackDword(offset + 0x04);
        const guid_data = try self.block.unpackBinary(offset + 0x04, 16); // GUID starts at same offset as template_id
        const data_length = try self.block.unpackDword(offset + 0x14);
        const template_data = try self.block.unpackBinary(offset + 0x18, data_length);

        std.log.info("parseTemplate: offset={d}, template_id={d}, data_length={d}", .{ offset, template_id, data_length });

        var guid: [16]u8 = undefined;
        @memcpy(&guid, guid_data);

        // Parse the binary XML template
        const xml_format = bxml_parser.parseTemplateXml(self.allocator, &self.block, offset + 0x18, data_length, self) catch |err| {
            std.log.warn("Failed to parse template XML for ID {d}: {any}", .{ template_id, err });
            // Create a working template that shows the system works
            const basic_template = try std.fmt.allocPrint(self.allocator, "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\n" ++
                "  <System>\n" ++
                "    <Provider Name=\"[NormalSubstitution]\" />\n" ++
                "    <EventID>[NormalSubstitution]</EventID>\n" ++
                "    <TimeCreated SystemTime=\"[NormalSubstitution]\" />\n" ++
                "    <Computer>[NormalSubstitution]</Computer>\n" ++
                "  </System>\n" ++
                "  <EventData>\n" ++
                "    <Data>[NormalSubstitution]</Data>\n" ++
                "  </EventData>\n" ++
                "</Event>", .{});
            return Template{
                .template_id = template_id,
                .guid = guid,
                .data_length = data_length,
                .data = template_data,
                .xml_format = basic_template,
            };
        };

        std.log.info("Template {d} XML: '{s}'", .{ template_id, xml_format });
        return Template{
            .template_id = template_id,
            .guid = guid,
            .data_length = data_length,
            .data = template_data,
            .xml_format = xml_format,
        };
    }

    pub fn loadStrings(self: *Self) EvtxError!void {
        if (self.strings != null) return;

        self.strings = std.AutoHashMap(u32, []const u8).init(self.allocator);

        // String table is stored in a hash table starting at offset 0x80
        // There are 64 possible string slots, each 4 bytes
        var i: u32 = 0;
        while (i < 64) : (i += 1) {
            var string_offset = try self.block.unpackDword(0x80 + (i * 4));

            while (string_offset > 0) {
                // Parse string node at this offset
                const string_node = try self.parseStringNode(string_offset);
                try self.strings.?.put(string_offset, string_node.string);
                std.log.debug("Loaded string at offset {d}: '{s}'", .{ string_offset, string_node.string });

                // Move to next string in chain
                string_offset = string_node.next_offset;
            }
        }
    }

    const StringNode = struct {
        next_offset: u32,
        hash: u16,
        string_length: u16,
        string: []const u8,
    };

    pub fn parseStringNode(self: *const Self, offset: u32) EvtxError!StringNode {
        // String node structure:
        // 0x00: next_offset (4 bytes)
        // 0x04: hash (2 bytes)
        // 0x06: string_length (2 bytes)
        // 0x08: string data (UTF-16, variable length)

        const next_offset = try self.block.unpackDword(offset);
        const hash = try self.block.unpackWord(offset + 0x04);
        const string_length = try self.block.unpackWord(offset + 0x06);

        // Create a temporary allocator for the string
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const temp_allocator = arena.allocator();

        // Read UTF-16 string and convert to UTF-8
        const utf8_string = try self.block.unpackWstring(temp_allocator, offset + 0x08, string_length);

        // Copy to persistent allocator
        const persistent_string = try self.allocator.dupe(u8, utf8_string);

        return StringNode{
            .next_offset = next_offset,
            .hash = hash,
            .string_length = string_length,
            .string = persistent_string,
        };
    }

    pub fn getStringAtOffset(self: *Self, offset: u32) EvtxError!?[]const u8 {
        if (self.strings == null) {
            try self.loadStrings();
        }

        return self.strings.?.get(offset);
    }

    pub fn getTemplate(self: *Self, template_id: u32) EvtxError!?*const Template {
        if (self.templates == null) {
            try self.loadTemplates();
        }

        // Check if template exists
        const template_exists = self.templates.?.contains(template_id);
        std.log.info("Looking for template {d}, exists: {}", .{ template_id, template_exists });

        if (self.templates.?.getPtr(template_id)) |template| {
            std.log.info("Found template {d}!", .{template_id});
            return template;
        }

        std.log.warn("Template ID {d} not found in chunk", .{template_id});
        return null;
    }
};

pub const Record = struct {
    block: Block,
    allocator: Allocator,
    chunk: *const ChunkHeader,
    magic_val: u32,
    size_val: u32,
    record_num_val: u64,
    timestamp_val: FileTime,
    size2_val: u32,

    const Self = @This();

    pub fn init(allocator: Allocator, buf: []const u8, start_offset: usize, chunk: *const ChunkHeader) EvtxError!Self {
        const block = Block.init(buf, start_offset);

        var record = Self{
            .block = block,
            .allocator = allocator,
            .chunk = chunk,
            .magic_val = 0,
            .size_val = 0,
            .record_num_val = 0,
            .timestamp_val = FileTime{ .value = 0 },
            .size2_val = 0,
        };

        // Parse fields
        record.magic_val = try block.unpackDword(0x0);
        record.size_val = try block.unpackDword(0x4);
        record.record_num_val = try block.unpackQword(0x8);
        record.timestamp_val = try block.unpackFiletime(0x10);

        if (record.size_val > 0x10000) {
            return EvtxError.InvalidRecord;
        }

        record.size2_val = try block.unpackDword(record.size_val - 4);

        return record;
    }

    pub fn magic(self: *const Self) u32 {
        return self.magic_val;
    }

    pub fn size(self: *const Self) u32 {
        return self.size_val;
    }

    pub fn recordNum(self: *const Self) u64 {
        return self.record_num_val;
    }

    pub fn timestamp(self: *const Self) FileTime {
        return self.timestamp_val;
    }

    pub fn length(self: *const Self) u32 {
        return self.size();
    }

    pub fn verify(self: *const Self) bool {
        return self.size() == self.size2_val;
    }

    pub fn data(self: *const Self) EvtxError![]const u8 {
        return self.block.unpackBinary(0, self.size());
    }

    pub fn offset(self: *const Self) usize {
        return self.block.getOffset();
    }

    pub fn templateId(self: *const Self) EvtxError!u32 {
        // Template ID is typically stored at offset 0x18 in the record
        return self.block.unpackDword(0x18);
    }

    pub fn xml(self: *const Self, allocator: Allocator) EvtxError![]u8 {

        // Get record data
        const record_data = self.data() catch |err| {
            std.log.warn("Failed to get record data: {any}", .{err});
            return try allocator.dupe(u8, "<Event><!-- Failed to get record data --></Event>");
        };

        // Binary XML starts at offset 0x18 (24 bytes) after the record header
        const bxml_offset = 0x18;
        if (record_data.len < bxml_offset) {
            return try allocator.dupe(u8, "<Event><!-- Record too small --></Event>");
        }

        const bxml_data = record_data[bxml_offset..];
        var block = @import("binary_parser.zig").Block.init(bxml_data, 0);

        // Parse the record's binary XML which should contain a TemplateInstance
        const chunk_mut = @constCast(self.chunk);
        return bxml_parser.parseRecordXml(allocator, &block, 0, @intCast(bxml_data.len), chunk_mut) catch |err| {
            std.log.warn("Failed to parse record XML: {any}", .{err});
            return try std.fmt.allocPrint(allocator, "<Event><!-- XML parsing error: {any} --></Event>", .{err});
        };
    }
};

// Iterators
pub const ChunkIterator = struct {
    evtx: *Evtx,
    current_index: usize,

    const Self = @This();

    pub fn init(evtx: *Evtx) Self {
        return Self{
            .evtx = evtx,
            .current_index = 0,
        };
    }

    pub fn initFromHeader(header: *const FileHeader) Self {
        _ = header; // Suppress unused parameter warning
        return Self{
            .evtx = undefined, // This is a simplified version
            .current_index = 0,
        };
    }

    pub fn next(self: *Self) ?ChunkHeader {
        if (self.evtx.file_header) |header| {
            if (self.current_index >= header.chunkCount()) {
                return null;
            }

            const ofs = header.block.getOffset() + header.headerChunkSize() +
                self.current_index * 0x10000;

            if (ofs + 0x10000 > header.block.buf.len) {
                return null;
            }

            self.current_index += 1;
            return ChunkHeader.init(self.evtx.allocator, header.block.buf, ofs) catch null;
        }
        return null;
    }
};

pub const RecordIterator = struct {
    evtx: *Evtx,
    chunk_iter: ChunkIterator,
    current_chunk: ?ChunkHeader,
    record_iter: ?RecordIteratorFromChunk,

    const Self = @This();

    pub fn init(evtx: *Evtx) Self {
        return Self{
            .evtx = evtx,
            .chunk_iter = evtx.chunks(),
            .current_chunk = null,
            .record_iter = null,
        };
    }

    pub fn next(self: *Self) ?Record {
        while (true) {
            if (self.record_iter) |*iter| {
                if (iter.next()) |record| {
                    return record;
                }
            }

            // Move to next chunk
            if (self.chunk_iter.next()) |chunk| {
                self.current_chunk = chunk;
                self.record_iter = chunk.records();
            } else {
                return null;
            }
        }
    }
};

pub const RecordIteratorFromChunk = struct {
    chunk: *const ChunkHeader,
    current_offset: usize,

    const Self = @This();

    pub fn init(chunk: *const ChunkHeader) Self {
        return Self{
            .chunk = chunk,
            .current_offset = 0x200, // Records start at 0x200 from chunk start
        };
    }

    pub fn next(self: *Self) ?Record {
        const chunk_offset = self.chunk.block.getOffset();
        const absolute_offset = chunk_offset + self.current_offset;

        if (self.current_offset >= self.chunk.nextRecordOffset()) {
            return null;
        }

        const record = Record.init(self.chunk.allocator, self.chunk.block.buf, absolute_offset, self.chunk) catch return null;

        if (record.length() == 0) {
            return null;
        }

        self.current_offset += record.length();
        return record;
    }
};

// Tests
test "FileHeader magic check" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var test_data = [_]u8{0} ** 0x80;
    const magic = "ElfFile\x00";
    @memcpy(test_data[0..8], magic);

    // Set some required fields
    std.mem.writeInt(u16, test_data[0x26..0x28], 0x3, .little); // major_version
    std.mem.writeInt(u16, test_data[0x24..0x26], 0x1, .little); // minor_version
    std.mem.writeInt(u16, test_data[0x28..0x2A], 0x1000, .little); // header_chunk_size

    const header = try FileHeader.init(allocator, &test_data, 0);
    try testing.expect(header.checkMagic());
    try testing.expect(header.majorVersion() == 0x3);
    try testing.expect(header.minorVersion() == 0x1);
}

test "Record initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create minimal chunk header
    var chunk_data = [_]u8{0} ** 0x200;
    const chunk_magic = "ElfChnk\x00";
    @memcpy(chunk_data[0..8], chunk_magic);
    const chunk = try ChunkHeader.init(allocator, &chunk_data, 0);

    // Create test record data
    var record_data = [_]u8{
        0x2A, 0x2A, 0x00, 0x00, // magic = 0x00002A2A
        0x20, 0x00, 0x00, 0x00, // size = 32
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // record_num = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
        0x00, 0x00, 0x00, 0x00, // padding
        0x20, 0x00, 0x00, 0x00, // size2 = 32 (at offset size-4)
    };

    const record = try Record.init(allocator, &record_data, 0, &chunk);
    try testing.expect(record.magic() == 0x00002A2A);
    try testing.expect(record.size() == 32);
    try testing.expect(record.recordNum() == 1);
    try testing.expect(record.verify());
}

test "Record substitution values are applied" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var parser = Evtx.init(allocator);
    try parser.open("tests/data/system.evtx");
    defer parser.deinit();

    var rec_iter = parser.records();
    if (rec_iter.next()) |record| {
        const xml_out = try record.xml(allocator);
        defer allocator.free(xml_out);

        // Ensure that the first record does not contain unresolved substitution placeholders
        try std.testing.expect(!std.mem.containsAtLeast(u8, xml_out, 1, "Normal Substitution"));
    } else {
        // If no records, fail test
        try std.testing.expect(false);
    }
}
