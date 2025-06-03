const std = @import("std");
const evtx = @import("src/evtx.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== RECORD PARSING TEST ===", .{});

    // Open EVTX file
    var evtx_file = evtx.Evtx.init(allocator);
    defer evtx_file.deinit();
    
    try evtx_file.open("tests/data/security.evtx");
    
    // Get first chunk
    var chunk_iter = evtx_file.chunks();
    if (chunk_iter.next()) |chunk| {
        var chunk_mut = chunk;
        defer chunk_mut.deinit();
        
        // Load templates first
        try chunk_mut.loadTemplates();
        
        std.log.info("=== ANALYZING FIRST 5 RECORDS ===", .{});
        var record_iter = chunk_mut.records();
        var count: u32 = 0;
        
        while (record_iter.next()) |record| {
            count += 1;
            if (count > 5) break;
            
            const template_id = try record.templateId();
            std.log.info("\nRecord {d}:", .{count});
            std.log.info("  Record number: {d}", .{record.recordNum()});
            std.log.info("  Template ID: {d}", .{template_id});
            std.log.info("  Record size: {d}", .{record.size()});
            
            // Check if template exists
            if (try chunk_mut.getTemplate(template_id)) |template| {
                std.log.info("  Template found: {d} chars", .{template.xml_format.len});
                std.log.info("  Template XML preview: {s}...", .{template.xml_format[0..@min(100, template.xml_format.len)]});
            } else {
                std.log.info("  Template NOT FOUND!", .{});
            }
            
            // Show record binary data start
            const record_data = try record.data();
            std.log.info("  Record data length: {d}", .{record_data.len});
            if (record_data.len >= 32) {
                std.log.info("  First 32 bytes: {x}", .{record_data[0..32].*});
                
                // Check what's at offset 0x18 (24) - should be binary XML
                if (record_data.len > 24) {
                    const bxml_start = record_data[24..];
                    const preview_len = @min(16, bxml_start.len);
                    std.log.info("  Binary XML starts ({d} bytes): {x}", .{preview_len, bxml_start[0..preview_len]});
                }
            }
            
            // Try to generate XML for records with found templates
            if (try chunk_mut.getTemplate(template_id)) |_| {
                const xml = record.xml(allocator) catch |err| {
                    std.log.info("  XML generation failed: {any}", .{err});
                    continue;
                };
                defer allocator.free(xml);
                
                std.log.info("  Generated XML length: {d}", .{xml.len});
                if (xml.len < 200) {
                    std.log.info("  Generated XML: {s}", .{xml});
                } else {
                    std.log.info("  Generated XML preview: {s}...", .{xml[0..200]});
                }
            }
        }
    }
    
    std.log.info("\n=== TEST COMPLETE ===", .{});
}