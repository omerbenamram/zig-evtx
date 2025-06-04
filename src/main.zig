const std = @import("std");
const evtx = @import("evtx.zig");
const views = @import("views.zig");

const CliError = error{
    InvalidArguments,
    FileNotFound,
    OutOfMemory,
} || evtx.EvtxError || views.ViewsError;

fn printUsage(program_name: []const u8) void {
    std.debug.print("EVTX Parser - Windows Event Log Binary Parser\n\n", .{});
    std.debug.print("USAGE:\n", .{});
    std.debug.print("    {s} [OPTIONS] <evtx_file>\n\n", .{program_name});
    std.debug.print("ARGS:\n", .{});
    std.debug.print("    <evtx_file>    Path to the EVTX file to parse\n\n", .{});
    std.debug.print("OPTIONS:\n", .{});
    std.debug.print("    -h, --help     Print this help message and exit\n\n", .{});
    std.debug.print("DESCRIPTION:\n", .{});
    std.debug.print("    Parses Windows Event Log (EVTX) binary files and outputs structured XML.\n", .{});
    std.debug.print("    The parser extracts templates from chunk headers and generates XML with\n", .{});
    std.debug.print("    proper substitution handling for all supported binary XML tokens.\n\n", .{});
    std.debug.print("EXAMPLES:\n", .{});
    std.debug.print("    {s} System.evtx\n", .{program_name});
    std.debug.print("    {s} /path/to/Security.evtx > events.xml\n", .{program_name});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Error: Missing required argument\n\n", .{});
        printUsage(args[0]);
        return CliError.InvalidArguments;
    }

    // Check for help flag
    if (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
        printUsage(args[0]);
        return;
    }

    if (args.len != 2) {
        std.debug.print("Error: Too many arguments\n\n", .{});
        printUsage(args[0]);
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
        std.debug.print("  File Verified: {any}\n", .{verified});
        std.debug.print("  Is Dirty: {any}\n", .{header.isDirty()});
        std.debug.print("  Is Full: {any}\n", .{header.isFull()});
    }

    const stdout = std.io.getStdOut().writer();

    // Print XML header
    try stdout.print("{s}", .{views.XML_HEADER});
    try stdout.print("<Events>\n", .{});

    // Process all chunks to ensure templates are loaded
    var chunk_iter = evtx_parser.chunks();
    var chunks = std.ArrayList(evtx.ChunkHeader).init(allocator);
    defer {
        for (chunks.items) |*c| {
            c.deinit();
        }
        chunks.deinit();
    }

    while (chunk_iter.next()) |chunk| {
        var chunk_copy = chunk;
        errdefer chunk_copy.deinit();
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
                std.debug.print("<!-- Error processing record {d}: {any} -->\n", .{ record.record_num_val, err });
                continue;
            };
            defer allocator.free(xml);

            try stdout.print("{s}\n", .{xml});
        }
    }

    // Chunks and associated resources freed by deferred block above

    try stdout.print("</Events>\n", .{});

    // Print summary to stderr
    std.debug.print("\nProcessed {d} records", .{record_count});
    if (error_count > 0) {
        std.debug.print(" ({d} errors)", .{error_count});
    }
    std.debug.print("\n", .{});
}
