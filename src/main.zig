const std = @import("std");
const evtx = @import("evtx.zig");
const views = @import("views.zig");

const CliError = error{
    InvalidArguments,
    FileNotFound,
    OutOfMemory,
} || evtx.EvtxError || views.ViewsError;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        std.debug.print("Usage: {s} <evtx_file>\n", .{args[0]});
        return CliError.InvalidArguments;
    }

    const filename = args[1];

    std.debug.print("Opening EVTX file: {s}\n", .{filename});

    var evtx_parser = evtx.Evtx.init(allocator);
    defer evtx_parser.deinit();

    try evtx_parser.open(filename);

    // Get file header information
    if (evtx_parser.getFileHeader()) |header| {
        std.debug.print("File Header Information:\n", .{});
        std.debug.print("  Magic: {s}\n", .{header.magic()});
        std.debug.print("  Major Version: {d}\n", .{header.majorVersion()});
        std.debug.print("  Minor Version: {d}\n", .{header.minorVersion()});
        std.debug.print("  Chunk Count: {d}\n", .{header.chunkCount()});
        std.debug.print("  Next Record Number: {d}\n", .{header.nextRecordNumber()});

        const verified = try header.verify();
        std.debug.print("  File Verified: {}\n", .{verified});
        std.debug.print("  Is Dirty: {}\n", .{header.isDirty()});
        std.debug.print("  Is Full: {}\n", .{header.isFull()});
    }

    const stdout = std.io.getStdOut().writer();
    
    // Print XML header
    try stdout.print("{s}", .{views.XML_HEADER});
    try stdout.print("<Events>\n", .{});

    // Process all chunks to ensure templates are loaded
    var chunk_iter = evtx_parser.chunks();
    var chunks = std.ArrayList(evtx.ChunkHeader).init(allocator);
    defer chunks.deinit();
    
    while (chunk_iter.next()) |chunk| {
        var chunk_copy = chunk;
        try chunk_copy.loadTemplates();
        try chunks.append(chunk_copy);
    }
    
    // Now iterate through records and output XML
    var error_count: u32 = 0;
    var record_count: u32 = 0;
    
    for (chunks.items) |*chunk| {
        var record_iter = chunk.records();
        while (record_iter.next()) |record| {
            record_count += 1;
            
            // Generate XML for this record
            const xml = record.xml(allocator) catch |err| {
                error_count += 1;
                std.debug.print("<!-- Error processing record {d}: {} -->\n", .{record.record_num_val, err});
                continue;
            };
            defer allocator.free(xml);
            
            try stdout.print("{s}\n", .{xml});
        }
    }
    
    try stdout.print("</Events>\n", .{});
    
    // Print summary to stderr
    std.debug.print("\nProcessed {d} records", .{record_count});
    if (error_count > 0) {
        std.debug.print(" ({d} errors)", .{error_count});
    }
    std.debug.print("\n", .{});
}
