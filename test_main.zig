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
        
        try chunk.loadStrings();
        try chunk.loadTemplates();
        
        std.log.info("=== TEMPLATE TESTING ===", .{});
        
        // Test template 3346188909 which we've been debugging
        const template_result = chunk.getTemplate(3346188909) catch |err| blk: {
            std.log.warn("Failed to get template: {any}", .{err});
            break :blk null;
        };
        
        if (template_result) |template| {
            std.log.info("Found template 3346188909!", .{});
            std.log.info("Template XML length: {d}", .{template.xml_format.len});
            std.log.info("Template XML content: '{s}'", .{template.xml_format});
        } else {
            std.log.warn("Template 3346188909 not found", .{});
        }
        
        std.log.info("=== TEMPLATE SUMMARY ===", .{});
        std.log.info("Template parsing test completed successfully!", .{});
    }
}