const std = @import("std");
const evtx = @import("src/evtx.zig");
const bxml_parser = @import("src/bxml_parser.zig");
const Block = @import("src/binary_parser.zig").Block;

pub fn debugBinaryXmlParsing(allocator: std.mem.Allocator, block: *Block, offset: u32, length: u32, chunk: ?*const evtx.ChunkHeader) !void {
    std.log.info("=== DEBUGGING BINARY XML PARSING ===", .{});
    std.log.info("Offset: {d}, Length: {d}", .{ offset, length });
    
    // Show first 20 bytes of data
    const debug_bytes = try block.unpackBinary(offset, @min(20, length));
    std.log.info("First 20 bytes:", .{});
    for (debug_bytes, 0..) |byte, i| {
        std.log.info("  [{d}]: 0x{x:0>2}", .{ i, byte });
    }
    
    var pos: usize = offset;
    const end_pos: usize = offset + length;
    var token_count: u32 = 0;
    const max_tokens = 10; // Limit for debugging
    
    std.log.info("\n=== TOKEN PARSING ===", .{});
    while (pos < end_pos and token_count < max_tokens) {
        const start_pos = pos;
        std.log.info("Token {d} at pos {d}:", .{ token_count, pos - offset });
        
        // Peek at the token byte
        const token_byte = try block.unpackByte(pos);
        const token = token_byte & 0x0F;
        const flags = token_byte >> 4;
        
        const token_names = [_][]const u8{
            "EndOfStream",         // 0x00
            "OpenStartElement",    // 0x01
            "CloseStartElement",   // 0x02
            "CloseEmptyElement",   // 0x03
            "CloseElement",        // 0x04
            "Value",               // 0x05
            "Attribute",           // 0x06
            "CDataSection",        // 0x07
            "EntityReference",     // 0x08
            "CharRef",             // 0x09
            "ProcessingInstructionTarget", // 0x0A
            "ProcessingInstructionData",   // 0x0B
            "TemplateInstance",    // 0x0C
            "NormalSubstitution",  // 0x0D
            "ConditionalSubstitution", // 0x0E
            "StartOfStream"        // 0x0F
        };
        
        const token_name = if (token < token_names.len) token_names[token] else "Unknown";
        std.log.info("  Token byte: 0x{x:0>2} -> {s} (token={d}, flags={d})", .{ token_byte, token_name, token, flags });
        
        // Try to parse the token
        const node_result = bxml_parser.BXmlNode.parse(allocator, block, &pos, chunk);
        if (node_result) |node| {
            const bytes_consumed = pos - start_pos;
            std.log.info("  Successfully parsed, consumed {d} bytes", .{bytes_consumed});
            
            switch (node) {
                .end_of_stream => {
                    std.log.info("  -> EndOfStream encountered, stopping", .{});
                    break;
                },
                .start_of_stream => {
                    std.log.info("  -> StartOfStream", .{});
                },
                .open_start_element => |elem| {
                    std.log.info("  -> OpenStartElement: name='{s}', data_size={d}", .{ elem.name.string, elem.data_size });
                },
                else => {
                    std.log.info("  -> Other token type", .{});
                }
            }
        } else |err| {
            std.log.err("  -> Parse error: {any}", .{err});
            break;
        }
        
        token_count += 1;
    }
    
    std.log.info("=== END DEBUG ===", .{});
}

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
        
        try chunk.loadTemplates();
        try chunk.loadStrings();
        
        if (try chunk.getTemplate(3346188909)) |_| {
            std.log.info("Found template 3346188909", .{});
            
            // Debug the binary XML parsing for this template
            try debugBinaryXmlParsing(allocator, &chunk.block, 574 + 0x18, 1170, &chunk);
        }
    }
}