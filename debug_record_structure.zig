const std = @import("std");
const evtx = @import("src/evtx.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== RECORD STRUCTURE ANALYSIS ===", .{});

    // Open the EVTX file
    var parser = evtx.Evtx.init(allocator);
    defer parser.deinit();
    
    try parser.open("tests/data/security.evtx");
    
    // Get the first chunk
    var chunk_iter = parser.chunks();
    if (chunk_iter.next()) |chunk| {
        std.log.info("Chunk offset: 0x{x}", .{chunk.offset});
        
        // Get the first record
        var record_iter = chunk.records();
        if (record_iter.next()) |record| {
            std.log.info("Record offset: 0x{x}", .{record.offset});
            
            // Get raw record data
            const record_data = try record.data();
            std.log.info("Record data length: {d} bytes", .{record_data.len});
            
            // Show first 64 bytes of record
            std.log.info("First 64 bytes of record data:");
            if (record_data.len >= 64) {
                for (0..64) |i| {
                    if (i % 16 == 0) std.log.info("0x{x:0>4}: ", .{i});
                    std.print("{x:0>2} ", .{record_data[i]});
                    if (i % 16 == 15) std.print("\n");
                }
            }
            
            // Binary XML starts at offset 0x18
            const bxml_offset = 0x18;
            if (record_data.len >= bxml_offset + 32) {
                std.log.info("\nBinary XML section (starting at 0x18):");
                for (0..32) |i| {
                    if (i % 16 == 0) std.log.info("0x{x:0>4}: ", .{i + bxml_offset});
                    std.print("{x:0>2} ", .{record_data[bxml_offset + i]});
                    if (i % 16 == 15) std.print("\n");
                }
                
                // Analyze the structure
                std.log.info("\nStructure analysis:");
                std.log.info("Byte at 0x18 (expected StartOfStream 0x0f): 0x{x:0>2}", .{record_data[bxml_offset]});
                if (record_data.len >= bxml_offset + 1) {
                    std.log.info("Byte at 0x19 (expected TemplateInstance 0x0c): 0x{x:0>2}", .{record_data[bxml_offset + 1]});
                }
                if (record_data.len >= bxml_offset + 10) {
                    // Parse TemplateInstance structure (if it's there)
                    const ti_unknown = record_data[bxml_offset + 2];
                    const template_id = std.mem.readInt(u32, record_data[bxml_offset + 3..bxml_offset + 7], .little);
                    const template_offset = std.mem.readInt(u32, record_data[bxml_offset + 7..bxml_offset + 11], .little);
                    
                    std.log.info("Potential TemplateInstance data:");
                    std.log.info("  Unknown: 0x{x:0>2}", .{ti_unknown});
                    std.log.info("  Template ID: {d} (0x{x})", .{template_id, template_id});
                    std.log.info("  Template offset: {d} (0x{x})", .{template_offset, template_offset});
                }
            }
        } else {
            std.log.err("No records found in chunk");
        }
    } else {
        std.log.err("No chunks found in file");
    }
    
    std.log.info("\n=== ANALYSIS COMPLETE ===");
}