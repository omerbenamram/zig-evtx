const std = @import("std");
const evtx = @import("src/evtx.zig");

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
        
        std.log.info("=== ZIG OFFSET ANALYSIS ===", .{});
        std.log.info("Chunk offset: 0x{x}", .{chunk.block.getOffset()});
        
        // Load templates manually to see what's happening
        try chunk.loadTemplates();
        
        if (try chunk.getTemplate(3346188909)) |template| {
            std.log.info("Template ID: {d}", .{template.template_id});
            std.log.info("Template data length: {d}", .{template.data_length});
            
            // Find where this template comes from in our template loading
            std.log.info("\n=== DEBUGGING TEMPLATE DISCOVERY ===", .{});
            
            // Look at template table entries
            var i: u32 = 0;
            while (i < 32) : (i += 1) {
                const template_offset = chunk.block.unpackDword(0x180 + (i * 4)) catch continue;
                if (template_offset == 0) continue;
                
                std.log.info("Template table slot {d}: offset {d} (0x{x})", .{i, template_offset, template_offset});
                
                // Check for template at this offset
                const token = chunk.block.unpackByte(template_offset - 10) catch continue;
                const pointer = chunk.block.unpackDword(template_offset - 4) catch continue;
                
                if (token == 0x0C and pointer == template_offset) {
                    const tmpl_id = chunk.block.unpackDword(template_offset + 0x04) catch continue;
                    const data_len = chunk.block.unpackDword(template_offset + 0x14) catch continue;
                    
                    std.log.info("  Valid template: ID={d}, data_length={d}", .{tmpl_id, data_len});
                    std.log.info("  Absolute offset: 0x{x} ({d})", .{chunk.block.getOffset() + template_offset, chunk.block.getOffset() + template_offset});
                    std.log.info("  Data starts at: 0x{x} ({d})", .{chunk.block.getOffset() + template_offset + 0x18, chunk.block.getOffset() + template_offset + 0x18});
                    
                    if (tmpl_id == 3346188909) {
                        std.log.info("  *** THIS IS OUR TARGET TEMPLATE! ***", .{});
                        
                        // Show first few bytes of data
                        std.log.info("  First 10 bytes of template data:", .{});
                        var j: u32 = 0;
                        while (j < 10) : (j += 1) {
                            const byte_val = chunk.block.unpackByte(template_offset + 0x18 + j) catch break;
                            std.log.info("    [{d}]: 0x{x:0>2}", .{j, byte_val});
                        }
                    }
                }
            }
        }
    }
}