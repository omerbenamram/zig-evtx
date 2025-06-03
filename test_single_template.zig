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
            
            // Load templates and find template 3346188909
            try chunk.loadTemplates();
            
            if (try chunk.getTemplate(3346188909)) |template| {
                std.log.info("Found template 3346188909", .{});
                std.log.info("Template XML length: {d}", .{template.xml_format.len});
                std.log.info("Template XML: '{s}'", .{template.xml_format});
                
                // Also load strings to help with debugging
                try chunk.loadStrings();
                std.log.info("Loaded {d} strings", .{chunk.strings.?.count()});
                
                // Check if we can get first record
                const first_record = try chunk.firstRecord();
                std.log.info("First record number: {d}", .{first_record.recordNum()});
                std.log.info("First record size: {d}", .{first_record.size()});
            } else {
                std.log.err("Template 3346188909 not found in first chunk", .{});
            }
            
        chunk.deinit();
    }
}