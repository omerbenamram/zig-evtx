const std = @import("std");
const evtx = @import("../evtx.zig");
const nodes = @import("../nodes.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        std.debug.print("Usage: {s} <evtx_file>\n", .{args[0]});
        std.debug.print("Builds and prints templates used throughout the event log.\n", .{});
        std.process.exit(1);
    }

    const filename = args[1];

    var evtx_parser = evtx.Evtx.init(allocator);
    defer evtx_parser.deinit();

    evtx_parser.open(filename) catch |err| {
        std.debug.print("Error opening file {s}: {}\n", .{ filename, err });
        std.process.exit(1);
    };

    std.debug.print("Analyzing templates in EVTX file: {s}\n", .{filename});
    std.debug.print("=" ** 50 ++ "\n", .{});

    var chunk_iter = evtx_parser.chunks();
    var chunk_index: u32 = 0;
    var total_templates: u32 = 0;

    while (chunk_iter.next()) |chunk| {
        std.debug.print("\nChunk {d} (offset: 0x{X:0>8}):\n", .{ chunk_index, chunk.block.getOffset() });
        std.debug.print("  Magic: {s}\n", .{chunk.magic()});
        std.debug.print("  First Record: {d}\n", .{chunk.logFirstRecordNumber()});
        std.debug.print("  Last Record: {d}\n", .{chunk.logLastRecordNumber()});
        std.debug.print("  Next Record Offset: 0x{X:0>8}\n", .{chunk.nextRecordOffset()});

        // In a full implementation, we would parse and display templates here
        // For now, we'll show basic chunk information and note where templates would be
        std.debug.print("  Templates: [Template parsing not fully implemented in this port]\n", .{});

        // Show that we can detect template locations
        // Templates are stored in the chunk header at specific offsets
        var template_count: u32 = 0;
        var i: u32 = 0;
        while (i < 32) : (i += 1) {
            const template_offset = chunk.block.unpackDword(0x180 + (i * 4)) catch 0;
            if (template_offset > 0) {
                std.debug.print("    Template {d}: offset 0x{X:0>4}\n", .{ template_count, template_offset });
                template_count += 1;
            }
        }

        if (template_count == 0) {
            std.debug.print("    No templates found in this chunk\n", .{});
        }

        total_templates += template_count;
        chunk_index += 1;
    }

    std.debug.print("\n" ++ "=" ** 50 ++ "\n", .{});
    std.debug.print("Summary:\n", .{});
    std.debug.print("  Total chunks analyzed: {d}\n", .{chunk_index});
    std.debug.print("  Total template references: {d}\n", .{total_templates});

    std.debug.print("\nNote: Full template parsing and XML generation is not yet\n", .{});
    std.debug.print("implemented in this Zig port. This tool shows template\n", .{});
    std.debug.print("locations and basic structure information.\n", .{});
}
