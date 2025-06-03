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
        
        try chunk.loadTemplates();
        
        // Get the first record and examine different offsets for template ID
        var record_iter = chunk.records();
        if (record_iter.next()) |first_record| {
            
            std.log.info("=== TEMPLATE ID DEBUGGING ===", .{});
            
            const record_data = first_record.data() catch |err| {
                std.log.err("Failed to get record data: {any}", .{err});
                return;
            };
            
            std.log.info("Record data length: {d}", .{record_data.len});
            
            // Show first 64 bytes in hex
            std.log.info("First 64 bytes:", .{});
            for (0..@min(64, record_data.len)) |i| {
                if (i % 16 == 0) {
                    std.log.info("", .{});
                }
                std.log.info("{x:0>2} ", .{record_data[i]});
            }
            std.log.info("", .{});
            
            // Try reading template ID from different offsets
            const offsets = [_]u32{0x18, 0x1c, 0x20, 0x24, 0x28};
            for (offsets) |offset| {
                if (offset + 4 <= record_data.len) {
                    const bytes = record_data[offset..offset+4];
                    const template_id = @as(u32, bytes[0]) |
                                       (@as(u32, bytes[1]) << 8) |
                                       (@as(u32, bytes[2]) << 16) |
                                       (@as(u32, bytes[3]) << 24);
                    std.log.info("Template ID at offset 0x{x:0>2} ({d}): {d}", .{offset, offset, template_id});
                }
            }
            
            // Show what templates are actually available
            std.log.info("\nAvailable templates:", .{});
            // This is a simplified way to check - ideally we'd iterate through templates
            const known_templates = [_]u32{3346188909, 3590499104, 2876772270};
            for (known_templates) |template_id| {
                const exists = chunk.getTemplate(template_id) catch null;
                std.log.info("Template {d}: {s}", .{template_id, if (exists != null) "EXISTS" else "not found"});
            }
        }
    }
}