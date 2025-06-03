const std = @import("std");
const evtx = @import("src/evtx.zig");
const bxml_parser = @import("src/bxml_parser.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var evtx_parser = evtx.Evtx.init(allocator);
    defer evtx_parser.deinit();

    try evtx_parser.open("tests/data/security.evtx");

    if (evtx_parser.getFileHeader()) |header| {
        const first_chunk = try header.firstChunk();
        var chunk = first_chunk;
        defer chunk.deinit();
        
        try chunk.loadStrings();
        
        std.log.info("=== MANUAL TEMPLATE PARSING DEBUG ===", .{});
        
        // Manually parse template at offset 550 (where template 3346188909 should be)
        const template_offset: u32 = 550;
        std.log.info("Parsing template at chunk offset: {d}", .{template_offset});
        
        // Let's check the template header structure first
        std.log.info("Template header structure:", .{});
        std.log.info("  next_offset (0x00): 0x{x:0>8}", .{try chunk.block.unpackDword(template_offset + 0x00)});
        std.log.info("  template_id (0x04): {d}", .{try chunk.block.unpackDword(template_offset + 0x04)});
        std.log.info("  data_length (0x14): {d}", .{try chunk.block.unpackDword(template_offset + 0x14)});
        
        // Parse template header
        const template_id = try chunk.block.unpackDword(template_offset + 0x04);
        const data_length = try chunk.block.unpackDword(template_offset + 0x14);
        
        std.log.info("Template ID: {d}", .{template_id});
        std.log.info("Data length: {d}", .{data_length});
        
        // Calculate where binary XML data starts
        const xml_data_offset = template_offset + 0x18;
        std.log.info("Binary XML data starts at chunk offset: {d}", .{xml_data_offset});
        
        // Show first 20 bytes of binary XML data
        std.log.info("First 20 bytes of binary XML data:", .{});
        var i: u32 = 0;
        while (i < 20) : (i += 1) {
            const byte_val = try chunk.block.unpackByte(xml_data_offset + i);
            std.log.info("  [{d}]: 0x{x:0>2}", .{i, byte_val});
        }
        
        // Now try parsing with our binary XML parser
        std.log.info("=== CALLING parseTemplateXml ===", .{});
        std.log.info("Calling with offset={d}, length={d}", .{xml_data_offset, data_length});
        
        const xml_result = bxml_parser.parseTemplateXml(allocator, &chunk.block, xml_data_offset, data_length, &chunk) catch |err| {
            std.log.err("parseTemplateXml failed: {any}", .{err});
            return;
        };
        defer allocator.free(xml_result);
        
        std.log.info("SUCCESS! XML result length: {d}", .{xml_result.len});
        std.log.info("XML content: '{s}'", .{xml_result});
    }
}