const std = @import("std");
const evtx = @import("src/evtx.zig");
const binary_parser = @import("src/binary_parser.zig");
const template_processor = @import("src/template_processor.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Open and parse the EVTX file
    var evtx_file = evtx.Evtx.init(allocator);
    try evtx_file.open("tests/data/security.evtx");
    defer evtx_file.deinit();
    
    const file_header = evtx_file.file_header orelse {
        std.debug.print("No file header\n", .{});
        return;
    };
    std.debug.print("File header parsed, chunk count: {d}\n", .{file_header.chunk_count_val});

    // Get the first chunk
    var chunk_iter = evtx_file.chunks();
    const chunk_opt = chunk_iter.next();
    var chunk = chunk_opt orelse {
        std.debug.print("No chunks found\n", .{});
        return;
    };
    std.debug.print("Chunk at offset: 0x{x}\n", .{chunk.block.getOffset()});

    // Get the first record
    var record_iter = chunk.records();
    const record_opt = record_iter.next();
    const record = record_opt orelse {
        std.debug.print("No records found\n", .{});
        return;
    };
    std.debug.print("Record at offset: 0x{x}, number: {d}\n", .{ record.block.getOffset(), record.record_num_val });

    // Get the binary XML offset and size
    const bxml_offset = record.block.getOffset() + 24; // Skip record header
    const bxml_size = record.size_val - 24;
    std.debug.print("Binary XML at offset: 0x{x}, size: {d}\n", .{ bxml_offset, bxml_size });

    // Create a block for the binary XML
    const data = evtx_file.buf orelse unreachable;
    var bxml_block = binary_parser.Block.init(data, bxml_offset);
    
    // Parse to find template instance
    var pos: usize = 0;
    
    // First token should be StartOfStream (0x0f)
    const first_token = try bxml_block.unpackByte(pos);
    std.debug.print("First token: 0x{x:0>2}\n", .{first_token});
    pos += 1;
    
    // Skip StartOfStream data (3 bytes)
    pos += 3;
    
    // Next should be TemplateInstance (0x0c)
    const second_token = try bxml_block.unpackByte(pos);
    std.debug.print("Second token: 0x{x:0>2}\n", .{second_token});
    
    if (second_token == 0x0c) {
        pos += 1;
        
        // Parse template instance
        const unknown0 = try bxml_block.unpackByte(pos);
        pos += 1;
        const template_id = try bxml_block.unpackDword(pos);
        pos += 4;
        const template_offset = try bxml_block.unpackDword(pos);
        pos += 4;
        
        std.debug.print("Template Instance:\n", .{});
        std.debug.print("  unknown0: 0x{x:0>2}\n", .{unknown0});
        std.debug.print("  template_id: {d}\n", .{template_id});
        std.debug.print("  template_offset: {d}\n", .{template_offset});
        
        // Next should be EndOfStream (0x00)
        const third_token = try bxml_block.unpackByte(pos);
        std.debug.print("Third token: 0x{x:0>2} (should be 0x00 for EndOfStream)\n", .{third_token});
        pos += 1;
        
        // Now we should be at the substitution array
        std.debug.print("\n=== SUBSTITUTION ARRAY ===\n", .{});
        std.debug.print("Substitution array starts at pos: {d} (0x{x})\n", .{ pos, pos });
        
        // Show raw bytes at this position
        std.debug.print("Raw bytes at substitution position:\n", .{});
        const preview_size = @min(64, bxml_block.getSize() - pos);
        var i: usize = 0;
        while (i < preview_size) : (i += 16) {
            const line_size = @min(16, preview_size - i);
            std.debug.print("  {x:0>4}: ", .{pos + i});
            
            var j: usize = 0;
            while (j < line_size) : (j += 1) {
                const byte = try bxml_block.unpackByte(pos + i + j);
                std.debug.print("{x:0>2} ", .{byte});
            }
            std.debug.print("\n", .{});
        }
        
        // Try to parse substitution count
        if (pos + 4 <= bxml_block.getSize()) {
            const sub_count = try bxml_block.unpackDword(pos);
            std.debug.print("\nSubstitution count: {d}\n", .{sub_count});
            
            // Try to parse declarations
            var decl_pos = pos + 4;
            std.debug.print("\nDeclarations (size, type, padding):\n", .{});
            
            var idx: usize = 0;
            while (idx < sub_count and decl_pos + 4 <= bxml_block.getSize()) : (idx += 1) {
                const size = try bxml_block.unpackWord(decl_pos);
                const typ = try bxml_block.unpackByte(decl_pos + 2);
                const pad = try bxml_block.unpackByte(decl_pos + 3);
                
                std.debug.print("  [{d}]: size={d}, type=0x{x:0>2}, padding=0x{x:0>2}\n", .{ idx, size, typ, pad });
                decl_pos += 4;
            }
            
            // Show where values should start
            std.debug.print("\nValues should start at pos: {d} (0x{x})\n", .{ decl_pos, decl_pos });
            
            // Try parseWithDeclarations
            std.debug.print("\n=== ATTEMPTING PARSE WITH DECLARATIONS ===\n", .{});
            var subs = template_processor.SubstitutionArray.parseWithDeclarations(allocator, &bxml_block, pos) catch |err| {
                std.debug.print("ERROR: Failed to parse: {any}\n", .{err});
                return;
            };
            defer subs.deinit();
            
            std.debug.print("SUCCESS: Parsed {d} substitutions\n", .{subs.entries.len});
            
            // Show parsed values
            for (subs.entries, 0..) |entry, entry_idx| {
                std.debug.print("Substitution [{d}]: ", .{entry_idx});
                const str = try entry.toString(allocator);
                defer allocator.free(str);
                std.debug.print("{s}\n", .{str});
            }
        }
    }
}