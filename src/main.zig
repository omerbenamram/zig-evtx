const std = @import("std");
const alloc = @import("alloc");
const fs = std.fs;

const evtx = @import("parser/evtx.zig");

pub fn main() !void {
    // Default allocator is selectable at build time (libc or GPA)
    const allocator = alloc.get();

    var args_iter = try std.process.argsWithAllocator(allocator);
    defer args_iter.deinit();

    // Program name
    _ = args_iter.next();

    var output_mode: OutputMode = .xml;
    var input_path: ?[]const u8 = null;
    var verbosity: u8 = 0;
    var max_records: usize = 0;
    var skip_first: usize = 0;
    var validate_checksums: bool = true;
    var threads_opt: ?usize = null;

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "-o")) {
            const mode = args_iter.next() orelse return error.InvalidArgs;
            if (std.mem.eql(u8, mode, "xml")) output_mode = .xml else if (std.mem.eql(u8, mode, "json")) output_mode = .json else if (std.mem.eql(u8, mode, "jsonl")) output_mode = .jsonl else return error.InvalidArgs;
        } else if (std.mem.eql(u8, arg, "-v")) {
            if (verbosity < 1) verbosity = 1;
        } else if (std.mem.eql(u8, arg, "-vv")) {
            if (verbosity < 2) verbosity = 2;
        } else if (std.mem.eql(u8, arg, "-vvv")) {
            if (verbosity < 3) verbosity = 3;
        } else if (std.mem.eql(u8, arg, "-n")) {
            const n_str = args_iter.next() orelse return error.InvalidArgs;
            max_records = try std.fmt.parseUnsigned(usize, n_str, 10);
        } else if (std.mem.eql(u8, arg, "-s")) {
            const s_str = args_iter.next() orelse return error.InvalidArgs;
            skip_first = try std.fmt.parseUnsigned(usize, s_str, 10);
        } else if (std.mem.eql(u8, arg, "--no-checks")) {
            validate_checksums = false;
        } else if (std.mem.eql(u8, arg, "-t")) {
            const t_str = args_iter.next() orelse return error.InvalidArgs;
            threads_opt = try std.fmt.parseUnsigned(usize, t_str, 10);
        } else if (arg.len > 0 and arg[0] == '-') {
            return error.InvalidArgs;
        } else {
            input_path = arg;
        }
    }

    const in_path = input_path orelse return usage();

    var file = try fs.cwd().openFile(in_path, .{ .mode = .read_only });
    defer file.close();

    var reader = file.reader();

    var parser = try evtx.EvtxParser.init(allocator, .{ .validate_checksums = validate_checksums, .verbosity = verbosity, .max_records = max_records, .skip_first = skip_first });
    defer parser.deinit();

    const cpu_count = try std.Thread.getCpuCount();
    var num_threads: usize = threads_opt orelse cpu_count;
    if (num_threads == 0) num_threads = 1;

    if (num_threads <= 1) {
        var output = switch (output_mode) {
            .xml => evtx.Output.xml(std.io.getStdOut().writer()),
            .json => evtx.Output.json(std.io.getStdOut().writer(), .single),
            .jsonl => evtx.Output.json(std.io.getStdOut().writer(), .lines),
        };
        try parser.parse(&reader, &output);
        output.flush();
    } else {
        const out_kind: evtx.EvtxParser.OutKind = switch (output_mode) {
            .xml => .xml,
            .json => .json_single,
            .jsonl => .json_lines,
        };
        try parser.parseConcurrent(&reader, out_kind, num_threads);
    }
}

fn usage() noreturn {
    const w = std.io.getStdErr().writer();
    w.print("Usage: evtx_dump_zig [-v|-vv|-vvv] [-o xml|json|jsonl] [-s N] [-n N] [-t NUM_THREADS] <file.evtx>\n", .{}) catch {};
    std.process.exit(2);
}

const OutputMode = enum { xml, json, jsonl };
