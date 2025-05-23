const std = @import("std");
const evtx = @import("../evtx.zig");
const views = @import("../views.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2 or args.len > 3) {
        std.debug.print("Usage: {s} <evtx_file> [output_file]\n", .{args[0]});
        std.debug.print("Parses event log and transforms binary XML into JSON.\n", .{});
        std.debug.print("If no output file is specified, JSON is printed to stdout.\n", .{});
        std.process.exit(1);
    }

    const filename = args[1];
    const output_filename = if (args.len == 3) args[2] else null;

    var evtx_parser = evtx.Evtx.init(allocator);
    defer evtx_parser.deinit();

    evtx_parser.open(filename) catch |err| {
        std.debug.print("Error opening file {s}: {}\n", .{ filename, err });
        std.process.exit(1);
    };

    std.debug.print("Parsing EVTX file: {s}\n", .{filename});

    const json_output = views.renderEvtxAsJson(allocator, &evtx_parser) catch |err| {
        std.debug.print("Error generating JSON: {any}\n", .{err});
        std.process.exit(1);
    };
    defer allocator.free(json_output);

    if (output_filename) |out_file| {
        const output_file = std.fs.cwd().createFile(out_file, .{}) catch |err| {
            std.debug.print("Error creating output file {s}: {}\n", .{ out_file, err });
            std.process.exit(1);
        };
        defer output_file.close();

        output_file.writeAll(json_output) catch |err| {
            std.debug.print("Error writing to output file: {any}\n", .{err});
            std.process.exit(1);
        };

        std.debug.print("JSON output written to: {s}\n", .{out_file});
    } else {
        // Print to stdout
        const stdout = std.io.getStdOut().writer();
        try stdout.print("{s}", .{json_output});
    }

    // Count records for summary
    var record_count: u32 = 0;
    var record_iter = evtx_parser.records();
    while (record_iter.next()) |_| {
        record_count += 1;
    }

    if (output_filename != null) {
        std.debug.print("Total records processed: {d}\n", .{record_count});
    }
}
