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
    
    // Generate XML output
    std.debug.print("\nGenerating XML output...\n", .{});
    const xml_output = try views.renderEvtxAsXml(allocator, &evtx_parser);
    defer allocator.free(xml_output);
    
    // Write to output file
    const output_file = try std.fs.cwd().createFile("output.xml", .{});
    defer output_file.close();
    
    try output_file.writeAll(xml_output);
    std.debug.print("XML output written to output.xml\n", .{});
    
    // Count records
    var record_count: u32 = 0;
    var record_iter = evtx_parser.records();
    while (record_iter.next()) |_| {
        record_count += 1;
    }
    
    std.debug.print("Total records processed: {d}\n", .{record_count});
}