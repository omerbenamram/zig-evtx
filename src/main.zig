const std = @import("std");
const builtin = @import("builtin");
const alloc = @import("alloc");
const fs = std.fs;

const evtx = @import("parser/evtx/mod.zig");
const logger = @import("logger.zig");
const runtime = @import("runtime.zig");

/// Default read buffer size for file I/O
const READ_BUFFER_SIZE: usize = 8192;

const help_message =
    \\evtx_dump_zig - fast Windows EVTX event log dumper
    \\
    \\Usage:
    \\  evtx_dump_zig [options] <file.evtx>
    \\
    \\Options:
    \\  -h, --help          Show this help and exit
    \\  -o FORMAT           Output format: xml (default), json, jsonl
    \\  -v                  Increase log verbosity (info)
    \\  -vv                 More verbose logging (debug)
    \\  -vvv                Maximum verbosity (trace)
    \\  -n N                Stop after N records (0 = all)
    \\  -s N                Skip first N records
    \\  --no-checks         Disable EVTX checksum validation
    \\  --carve             Scan all chunks until EOF (ignore header's chunk count)
    \\  --unordered         Output chunks as they complete (faster, non-deterministic order)
    \\  -t NUM_THREADS      Override number of worker threads (default: CPU count)
    \\
    \\Examples:
    \\  evtx_dump_zig system.evtx
    \\  evtx_dump_zig -o jsonl -vv system.evtx
    \\  evtx_dump_zig -n 100 -s 200 security.evtx
    \\
;

const invalid_args_prefix = "error: invalid arguments\n\n";
const invalid_usage_message = invalid_args_prefix ++ help_message;

const CliOptions = struct {
    output_mode: OutputMode = .xml,
    input_path: []const u8,
    verbosity: u8 = 0,
    max_records: usize = 0,
    skip_first: usize = 0,
    validate_checksums: bool = true,
    carve: bool = false,
    ordered: bool = true,
    threads_opt: ?usize = null,
};

const CliAction = union(enum) {
    help,
    run: CliOptions,
};

pub fn main(init: std.process.Init) void {
    const exit_code = run(init) catch |err| switch (err) {
        error.BrokenPipe, error.WriteFailed => 0,
        else => reportError(init.io, err),
    };
    std.process.exit(exit_code);
}

fn run(init: std.process.Init) !u8 {
    // Avoid SIGPIPE termination when stdout is closed (e.g. piped to head).
    runtime.ignoreSigpipe();

    const allocator = init.gpa;
    const io = init.io;
    logger.initEnvironment(init.environ_map);

    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    var args = std.ArrayList([]const u8).empty;
    defer args.deinit(allocator);

    while (args_iter.next()) |arg| {
        try args.append(allocator, arg);
    }

    const action = parseCliArgs(args.items) catch |err| switch (err) {
        error.InvalidArgs => {
            try printInvalidUsage(io);
            return 2;
        },
    };

    switch (action) {
        .help => {
            try printHelp(io, false);
            return 0;
        },
        .run => |opts| try runCli(allocator, io, opts),
    }

    return 0;
}

fn runCli(allocator: std.mem.Allocator, io: std.Io, opts: CliOptions) !void {
    var file = try std.Io.Dir.cwd().openFile(io, opts.input_path, .{ .mode = .read_only });
    defer file.close(io);

    var read_buf: [READ_BUFFER_SIZE]u8 = undefined;
    var reader = file.reader(io, &read_buf);

    var parser = evtx.EvtxParser.init(allocator, .{
        .validate_checksums = opts.validate_checksums,
        .verbosity = opts.verbosity,
        .max_records = opts.max_records,
        .skip_first = opts.skip_first,
        .carve = opts.carve,
        .ordered = opts.ordered,
    });

    const cpu_count = try std.Thread.getCpuCount();
    var num_threads: usize = opts.threads_opt orelse cpu_count;
    if (num_threads == 0) num_threads = 1;

    if (num_threads <= 1) {
        var write_buf: [8192]u8 = undefined;
        const stdout_file = std.Io.File.stdout();
        var stdout_writer = stdout_file.writer(io, &write_buf);
        var output = switch (opts.output_mode) {
            .xml => try evtx.OutputWriter.initXml(allocator, &stdout_writer),
            .json => try evtx.OutputWriter.initJson(allocator, &stdout_writer, .single),
            .jsonl => try evtx.OutputWriter.initJson(allocator, &stdout_writer, .lines),
        };
        defer output.deinit();
        parser.parse(&reader, &output) catch |e| {
            if (e == error.WriteFailed and isPipeOrSocket(stdout_file)) return;
            return e;
        };
        output.flush() catch |e| {
            if (e == error.WriteFailed and isPipeOrSocket(stdout_file)) return;
            return e;
        };
    } else {
        const out_kind: evtx.EvtxParser.OutKind = switch (opts.output_mode) {
            .xml => .xml,
            .json => .json_single,
            .jsonl => .json_lines,
        };
        var stdout_file = std.Io.File.stdout();
        try parser.parseConcurrent(.{ .io = io, .stdout_file = &stdout_file }, &reader, out_kind, num_threads);
    }
}

fn parseCliArgs(args: []const []const u8) error{InvalidArgs}!CliAction {
    var opts = CliOptions{ .input_path = undefined };
    var input_path: ?[]const u8 = null;
    var index: usize = if (args.len == 0) 0 else 1;

    while (index < args.len) {
        const arg = args[index];
        index += 1;

        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            return .help;
        } else if (std.mem.eql(u8, arg, "-o")) {
            if (index >= args.len) return error.InvalidArgs;
            const mode = args[index];
            index += 1;
            opts.output_mode = output_mode_map.get(mode) orelse return error.InvalidArgs;
        } else if (std.mem.eql(u8, arg, "-v")) {
            if (opts.verbosity < 1) opts.verbosity = 1;
        } else if (std.mem.eql(u8, arg, "-vv")) {
            if (opts.verbosity < 2) opts.verbosity = 2;
        } else if (std.mem.eql(u8, arg, "-vvv")) {
            if (opts.verbosity < 3) opts.verbosity = 3;
        } else if (std.mem.eql(u8, arg, "-n")) {
            if (index >= args.len) return error.InvalidArgs;
            const n_str = args[index];
            index += 1;
            opts.max_records = std.fmt.parseUnsigned(usize, n_str, 10) catch return error.InvalidArgs;
        } else if (std.mem.eql(u8, arg, "-s")) {
            if (index >= args.len) return error.InvalidArgs;
            const s_str = args[index];
            index += 1;
            opts.skip_first = std.fmt.parseUnsigned(usize, s_str, 10) catch return error.InvalidArgs;
        } else if (std.mem.eql(u8, arg, "--no-checks")) {
            opts.validate_checksums = false;
        } else if (std.mem.eql(u8, arg, "--carve")) {
            opts.carve = true;
        } else if (std.mem.eql(u8, arg, "--unordered")) {
            opts.ordered = false;
        } else if (std.mem.eql(u8, arg, "-t")) {
            if (index >= args.len) return error.InvalidArgs;
            const t_str = args[index];
            index += 1;
            opts.threads_opt = std.fmt.parseUnsigned(usize, t_str, 10) catch return error.InvalidArgs;
        } else if (arg.len > 0 and arg[0] == '-') {
            return error.InvalidArgs;
        } else if (input_path != null) {
            return error.InvalidArgs;
        } else {
            input_path = arg;
        }
    }

    opts.input_path = input_path orelse return error.InvalidArgs;
    return .{ .run = opts };
}

fn isPipeOrSocket(file: std.Io.File) bool {
    if (comptime builtin.os.tag == .windows) return false;

    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    const st = file.stat(threaded.io()) catch return false;
    return st.kind == .named_pipe or st.kind == .unix_domain_socket;
}

fn reportError(io: std.Io, err: anyerror) u8 {
    var write_buf: [512]u8 = undefined;
    const stderr_file = std.Io.File.stderr();
    var stderr = stderr_file.writer(io, &write_buf);
    _ = stderr.interface.print("error: {s}\n", .{@errorName(err)}) catch {};
    stderr.flush() catch {};
    return 1;
}

fn printInvalidUsage(io: std.Io) !void {
    var write_buf: [1024]u8 = undefined;
    const stderr_file = std.Io.File.stderr();
    var stderr = stderr_file.writer(io, &write_buf);
    try stderr.interface.writeAll(invalid_usage_message);
    try stderr.flush();
}

fn printHelp(io: std.Io, to_stderr: bool) !void {
    var write_buf: [512]u8 = undefined;
    if (to_stderr) {
        const stderr_file = std.Io.File.stderr();
        var w = stderr_file.writer(io, &write_buf);
        try w.interface.writeAll(help_message);
        try w.flush();
    } else {
        const stdout_file = std.Io.File.stdout();
        var w = stdout_file.writer(io, &write_buf);
        try w.interface.writeAll(help_message);
        try w.flush();
    }
}

const OutputMode = enum { xml, json, jsonl };

const output_mode_map = std.StaticStringMap(OutputMode).initComptime(.{
    .{ "xml", .xml },
    .{ "json", .json },
    .{ "jsonl", .jsonl },
});

// Test imports - Zig discovers test blocks transitively from imports.
// These bring in test-only modules not used by the main code path.
test {
    _ = @import("test/snapshot_tests.zig");
    _ = @import("test/concurrency_tests.zig");
    // util_string.zig and util_simd.zig tests are discovered via parser imports
}

test "cli parse recognizes help action" {
    const action = try parseCliArgs(&.{ "evtx_dump_zig", "--help" });
    try std.testing.expect(action == .help);
}

test "cli parse rejects invalid flags" {
    try std.testing.expectError(error.InvalidArgs, parseCliArgs(&.{ "evtx_dump_zig", "--definitely-invalid" }));
}

test "cli parse keeps valid options and input path" {
    const action = try parseCliArgs(&.{
        "evtx_dump_zig",
        "-o",
        "jsonl",
        "-vv",
        "-n",
        "2",
        "-s",
        "1",
        "--no-checks",
        "--carve",
        "--unordered",
        "-t",
        "4",
        "samples/system.evtx",
    });

    switch (action) {
        .help => return error.TestUnexpectedResult,
        .run => |opts| {
            try std.testing.expectEqual(OutputMode.jsonl, opts.output_mode);
            try std.testing.expectEqual(@as(u8, 2), opts.verbosity);
            try std.testing.expectEqual(@as(usize, 2), opts.max_records);
            try std.testing.expectEqual(@as(usize, 1), opts.skip_first);
            try std.testing.expectEqual(false, opts.validate_checksums);
            try std.testing.expectEqual(true, opts.carve);
            try std.testing.expectEqual(false, opts.ordered);
            try std.testing.expectEqual(@as(?usize, 4), opts.threads_opt);
            try std.testing.expectEqualStrings("samples/system.evtx", opts.input_path);
        },
    }
}

test "cli invalid usage message includes help text" {
    try std.testing.expect(std.mem.startsWith(u8, invalid_usage_message, invalid_args_prefix));
    try std.testing.expect(std.mem.indexOf(u8, invalid_usage_message, "Usage:") != null);
    try std.testing.expect(std.mem.indexOf(u8, invalid_usage_message, "--help") != null);
}
