const std = @import("std");
const evtx = @import("src/evtx.zig");
const bxml_parser = @import("src/bxml_parser.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== TEMPLATE PARSING COMPARISON TEST ===", .{});

    // Open EVTX file
    var evtx_file = evtx.Evtx.init(allocator);
    defer evtx_file.deinit();
    
    try evtx_file.open("tests/data/security.evtx");
    
    // Get first chunk
    var chunk_iter = evtx_file.chunks();
    if (chunk_iter.next()) |chunk| {
        var chunk_mut = chunk;
        defer chunk_mut.deinit();
        
        // Load templates
        try chunk_mut.loadTemplates();
        
        std.log.info("\n=== TEMPLATES IN CHUNK ===", .{});
        var template_iter = chunk_mut.templates.?.iterator();
        while (template_iter.next()) |entry| {
            std.log.info("Template ID {d} at offset {d}", .{entry.key_ptr.*, entry.value_ptr.*.template_id});
        }
        
        // Look for template ID 3346188909 (used by first record)
        const target_template_id: u32 = 3346188909;
        std.log.info("\n=== LOOKING FOR TEMPLATE {d} ===", .{target_template_id});
        
        if (try chunk_mut.getTemplate(target_template_id)) |template| {
            std.log.info("Found template!", .{});
            std.log.info("Template XML format length: {d}", .{template.xml_format.len});
            std.log.info("Template XML format:", .{});
            std.log.info("{s}", .{template.xml_format});
            
            // Count substitution placeholders
            var sub_count: u32 = 0;
            var i: usize = 0;
            while (i < template.xml_format.len) : (i += 1) {
                if (template.xml_format[i] == '[' and 
                    i + 20 < template.xml_format.len and
                    std.mem.startsWith(u8, template.xml_format[i..], "[NormalSubstitution]")) {
                    sub_count += 1;
                } else if (template.xml_format[i] == '[' and 
                    i + 25 < template.xml_format.len and
                    std.mem.startsWith(u8, template.xml_format[i..], "[ConditionalSubstitution]")) {
                    sub_count += 1;
                }
            }
            std.log.info("\nSubstitution placeholder count: {d}", .{sub_count});
            
            // Compare with Python output
            std.log.info("\n=== COMPARISON WITH PYTHON ===", .{});
            std.log.info("Python XML length: 705 characters", .{});
            std.log.info("Python has 18 conditional substitutions", .{});
            std.log.info("Zig XML length: {d} characters", .{template.xml_format.len});
            std.log.info("Zig substitution count: {d}", .{sub_count});
            
            if (template.xml_format.len < 700) {
                std.log.info("\n⚠️ Template is much shorter than expected!", .{});
                std.log.info("This suggests the binary XML parser stopped early.", .{});
            }
        } else {
            std.log.err("Template {d} not found!", .{target_template_id});
            
            // Let's check what templates are available
            std.log.info("\nAvailable template IDs:", .{});
            var iter = chunk_mut.templates.?.iterator();
            while (iter.next()) |entry| {
                std.log.info("  - {d}", .{entry.key_ptr.*});
            }
        }
        
        // Now let's test getting the first record
        std.log.info("\n=== FIRST RECORD TEST ===", .{});
        var record_iter = chunk_mut.records();
        if (record_iter.next()) |record| {
            std.log.info("Record number: {d}", .{record.recordNum()});
            
            const template_id = try record.templateId();
            std.log.info("Record template ID: {d}", .{template_id});
            
            // Try to generate XML
            const xml = record.xml(allocator) catch |err| {
                std.log.err("Failed to generate XML: {any}", .{err});
                return;
            };
            defer allocator.free(xml);
            
            std.log.info("Generated XML length: {d}", .{xml.len});
            if (xml.len < 100) {
                std.log.info("Generated XML: {s}", .{xml});
            } else {
                std.log.info("Generated XML (first 100 chars): {s}...", .{xml[0..100]});
            }
        }
    }
    
    std.log.info("\n=== TEST COMPLETE ===", .{});
}