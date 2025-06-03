const std = @import("std");
const bxml_parser = @import("src/bxml_parser.zig");
const evtx = @import("src/evtx.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== POSITION TRACKING DEBUG ===", .{});
    
    // Load the same template that's causing issues
    var evtx_file = evtx.Evtx.init(allocator);
    defer evtx_file.deinit();
    try evtx_file.open("tests/data/security.evtx");
    
    const chunk = try evtx_file.chunk(0);
    var chunk_mut = @constCast(chunk);
    
    // Parse template at offset 550 (template ID 3346188909) step by step
    const template_offset: u32 = 550;
    const template_data_start = template_offset + 0x18; // Skip header
    const template_data_length: u32 = 1170;
    
    std.log.info("Parsing template at offset {d}, data starts at {d}, length {d}", .{template_offset, template_data_start, template_data_length});
    
    // Manual step-by-step parsing with detailed position tracking
    var pos: usize = template_data_start;
    const end_pos: usize = template_data_start + template_data_length;
    var step: u32 = 0;
    
    std.log.info("=== STEP-BY-STEP PARSING ===", .{});
    
    while (pos < end_pos and step < 10) { // Only first 10 steps
        step += 1;
        
        std.log.info("STEP {d}: pos={d} (0x{x}), remaining_bytes={d}", .{step, pos, pos, end_pos - pos});
        
        // Show next 16 bytes for context
        const preview_len = @min(32, end_pos - pos);
        const preview_data = try chunk_mut.block.unpackBinary(pos, preview_len);
        std.log.info("  Next bytes: {any}", .{preview_data[0..@min(16, preview_len)]});
        
        // Read token byte
        const token_byte = try chunk_mut.block.unpackByte(pos);
        std.log.info("  Token byte: 0x{x:0>2}", .{token_byte});
        
        // Check if this looks like a valid token
        const maybe_token = @import("src/tokens.zig").BXmlToken.fromByte(token_byte);
        if (maybe_token) |token| {
            std.log.info("  Valid token: {s}", .{@tagName(token)});
            
            // If this is EndOfStream, check if it's at a valid position
            if (token == .EndOfStream) {
                std.log.warn("  FOUND EndOfStream at pos {d} - checking if valid", .{pos});
                std.log.warn("  Distance from start: {d} bytes", .{pos - template_data_start});
                std.log.warn("  Expected end at: {d}", .{end_pos});
                
                if (pos + 50 < end_pos) {
                    std.log.err("  FALSE EndOfStream - still {d} bytes remaining!", .{end_pos - pos});
                    // Show what comes after this false EndOfStream
                    const after_data = try chunk_mut.block.unpackBinary(pos + 1, @min(16, end_pos - pos - 1));
                    std.log.err("  Data after false EndOfStream: {any}", .{after_data});
                }
                break;
            }
        } else {
            std.log.warn("  INVALID token byte 0x{x:0>2} at pos {d}", .{token_byte, pos});
            break;
        }
        
        // Try to parse this token and see how position advances
        const pos_before = pos;
        var pos_copy = pos;
        
        const node = bxml_parser.BXmlNode.parse(allocator, &chunk_mut.block, &pos_copy, chunk_mut) catch |err| {
            std.log.err("  Failed to parse node: {any}", .{err});
            break;
        };
        
        const pos_after = pos_copy;
        std.log.info("  Parsed node: {s}, pos advanced from {d} to {d} (+{d})", .{@tagName(node), pos_before, pos_after, pos_after - pos_before});
        
        pos = pos_after;
    }
}