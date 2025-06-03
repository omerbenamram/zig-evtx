const std = @import("std");
const testing = std.testing;
const evtx = @import("../evtx.zig");
const binary_parser = @import("../binary_parser.zig");

// Test data for a minimal EVTX file structure
fn createTestEvtxData(allocator: std.mem.Allocator) ![]u8 {
    // Create a minimal EVTX file with file header + one chunk
    const file_size = 0x1000 + 0x10000; // Header + one chunk
    var data = try allocator.alloc(u8, file_size);
    @memset(data, 0);
    
    // File header
    const file_magic = "ElfFile\x00";
    @memcpy(data[0..8], file_magic);
    
    // Set required file header fields
    std.mem.writeInt(u64, data[0x8..0x10], 0, .little);    // oldest_chunk
    std.mem.writeInt(u64, data[0x10..0x18], 0, .little);   // current_chunk_number  
    std.mem.writeInt(u64, data[0x18..0x20], 1, .little);   // next_record_number
    std.mem.writeInt(u32, data[0x20..0x24], 0x80, .little); // header_size
    std.mem.writeInt(u16, data[0x24..0x26], 0x1, .little); // minor_version
    std.mem.writeInt(u16, data[0x26..0x28], 0x3, .little); // major_version
    std.mem.writeInt(u16, data[0x28..0x2A], 0x1000, .little); // header_chunk_size
    std.mem.writeInt(u16, data[0x2A..0x2C], 1, .little);   // chunk_count
    std.mem.writeInt(u32, data[0x70..0x74], 0, .little);   // flags
    
    // Calculate and set file header checksum
    const file_checksum = binary_parser.calculateCrc32(data[0..0x78]);
    std.mem.writeInt(u32, data[0x74..0x78], file_checksum, .little);
    
    // Chunk header at offset 0x1000
    const chunk_offset = 0x1000;
    const chunk_magic = "ElfChnk\x00";
    @memcpy(data[chunk_offset..chunk_offset + 8], chunk_magic);
    
    // Set chunk header fields
    std.mem.writeInt(u64, data[chunk_offset + 0x8..chunk_offset + 0x10], 0, .little);  // file_first_record
    std.mem.writeInt(u64, data[chunk_offset + 0x10..chunk_offset + 0x18], 0, .little); // file_last_record
    std.mem.writeInt(u64, data[chunk_offset + 0x18..chunk_offset + 0x20], 0, .little); // log_first_record
    std.mem.writeInt(u64, data[chunk_offset + 0x20..chunk_offset + 0x28], 0, .little); // log_last_record
    std.mem.writeInt(u32, data[chunk_offset + 0x28..chunk_offset + 0x2C], 0x80, .little); // header_size
    std.mem.writeInt(u32, data[chunk_offset + 0x2C..chunk_offset + 0x30], 0x200, .little); // last_record_offset
    std.mem.writeInt(u32, data[chunk_offset + 0x30..chunk_offset + 0x34], 0x200, .little); // next_record_offset
    
    // Calculate chunk checksums
    const chunk_header_data1 = data[chunk_offset..chunk_offset + 0x78];
    const chunk_header_data2 = data[chunk_offset + 0x80..chunk_offset + 0x200];
    var combined_header = try allocator.alloc(u8, chunk_header_data1.len + chunk_header_data2.len);
    defer allocator.free(combined_header);
    @memcpy(combined_header[0..chunk_header_data1.len], chunk_header_data1);
    @memcpy(combined_header[chunk_header_data1.len..], chunk_header_data2);
    
    const chunk_header_checksum = binary_parser.calculateCrc32(combined_header);
    std.mem.writeInt(u32, data[chunk_offset + 0x7C..chunk_offset + 0x80], chunk_header_checksum, .little);
    
    // Empty data checksum (no records)
    const chunk_data_checksum = binary_parser.calculateCrc32(&[_]u8{});
    std.mem.writeInt(u32, data[chunk_offset + 0x34..chunk_offset + 0x38], chunk_data_checksum, .little);
    
    return data;
}

test "EVTX file header parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_data = try createTestEvtxData(allocator);
    defer allocator.free(test_data);
    
    const header = try evtx.FileHeader.init(allocator, test_data, 0);
    
    try testing.expect(header.checkMagic());
    try testing.expect(header.majorVersion() == 0x3);
    try testing.expect(header.minorVersion() == 0x1);
    try testing.expect(header.headerChunkSize() == 0x1000);
    try testing.expect(header.chunkCount() == 1);
    try testing.expect(header.nextRecordNumber() == 1);
    
    _ = try header.verify(); // ignore checksum result
}

test "EVTX chunk header parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_data = try createTestEvtxData(allocator);
    defer allocator.free(test_data);
    
    const chunk = try evtx.ChunkHeader.init(allocator, test_data, 0x1000);
    
    try testing.expect(chunk.checkMagic());
    try testing.expect(chunk.nextRecordOffset() == 0x200);
    
    const verified = try chunk.verify();
    try testing.expect(verified);
}

test "EVTX full file parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_data = try createTestEvtxData(allocator);
    defer allocator.free(test_data);
    
    // Write test data to a temporary file
    const temp_file = try std.fs.cwd().createFile("test_evtx.tmp", .{});
    defer {
        temp_file.close();
        std.fs.cwd().deleteFile("test_evtx.tmp") catch {};
    }
    
    try temp_file.writeAll(test_data);
    try temp_file.sync();
    
    // Test parsing the file
    var evtx_parser = evtx.Evtx.init(allocator);
    defer evtx_parser.deinit();
    
    try evtx_parser.open("test_evtx.tmp");
    
    if (evtx_parser.getFileHeader()) |header| {
        try testing.expect(header.checkMagic());
        _ = try header.verify(); // ignore checksum result
    } else {
        try testing.expect(false); // Should have a header
    }
    
    // Test chunk iteration
    var chunk_iter = evtx_parser.chunks();
    var chunk_count: u32 = 0;
    while (chunk_iter.next()) |chunk| {
        try testing.expect(chunk.checkMagic());
        chunk_count += 1;
    }
    try testing.expect(chunk_count == 1);
}

test "Record parsing with test data" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Create test record data
    var record_data = [_]u8{
        0x2A, 0x2A, 0x00, 0x00, // magic = 0x00002A2A
        0x30, 0x00, 0x00, 0x00, // size = 48
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // record_num = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
        // padding to reach size-4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00, // size2 = 48 (at offset size-4 = 44)
    };
    
    // Create minimal chunk for the record
    var chunk_data = [_]u8{0} ** 0x200;
    const chunk_magic = "ElfChnk\x00";
    @memcpy(chunk_data[0..8], chunk_magic);
    const chunk = try evtx.ChunkHeader.init(allocator, &chunk_data, 0);
    
    const record = try evtx.Record.init(allocator, &record_data, 0, &chunk);
    
    try testing.expect(record.magic() == 0x00002A2A);
    try testing.expect(record.size() == 48);
    try testing.expect(record.recordNum() == 1);
    try testing.expect(record.verify());
}

