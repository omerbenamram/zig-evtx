const std = @import("std");
const builtin = @import("builtin");
const alloc = @import("alloc");
const fs = std.fs;

const evtx = @import("parser/evtx/mod.zig");

/// Default read buffer size for file I/O
const READ_BUFFER_SIZE: usize = 8192;

pub fn main(init: std.process.Init) !void {
    // Avoid SIGPIPE termination when stdout is closed (e.g. piped to head).
    ignoreSigpipe();

    const allocator = init.gpa;
    const io = init.io;

    var args_iter = std.process.Args.Iterator.init(init.minimal.args);

    // Program name
    _ = args_iter.next();

    var output_mode: OutputMode = .xml;
    var input_path: ?[]const u8 = null;
    var verbosity: u8 = 0;
    var max_records: usize = 0;
    var skip_first: usize = 0;
    var validate_checksums: bool = true;
    var carve: bool = false;
    var ordered: bool = true;
    var threads_opt: ?usize = null;

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            help(io);
        } else if (std.mem.eql(u8, arg, "-o")) {
            const mode = args_iter.next() orelse return error.InvalidArgs;
            output_mode = output_mode_map.get(mode) orelse return error.InvalidArgs;
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
        } else if (std.mem.eql(u8, arg, "--carve")) {
            carve = true;
        } else if (std.mem.eql(u8, arg, "--unordered")) {
            ordered = false;
        } else if (std.mem.eql(u8, arg, "-t")) {
            const t_str = args_iter.next() orelse return error.InvalidArgs;
            threads_opt = try std.fmt.parseUnsigned(usize, t_str, 10);
        } else if (arg.len > 0 and arg[0] == '-') {
            return error.InvalidArgs;
        } else {
            input_path = arg;
        }
    }

    const in_path = input_path orelse return usage(io, 2);

    var file = try std.Io.Dir.cwd().openFile(io, in_path, .{ .mode = .read_only });
    defer file.close(io);

    var read_buf: [READ_BUFFER_SIZE]u8 = undefined;
    var reader = file.reader(io, &read_buf);

    var parser = evtx.EvtxParser.init(allocator, .{ .validate_checksums = validate_checksums, .verbosity = verbosity, .max_records = max_records, .skip_first = skip_first, .carve = carve, .ordered = ordered });

    const cpu_count = try std.Thread.getCpuCount();
    var num_threads: usize = threads_opt orelse cpu_count;
    if (num_threads == 0) num_threads = 1;

    if (num_threads <= 1) {
        var write_buf: [8192]u8 = undefined;
        const stdout_file = std.Io.File.stdout();
        var stdout_writer = stdout_file.writer(io, &write_buf);
        var output = switch (output_mode) {
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
        const out_kind: evtx.EvtxParser.OutKind = switch (output_mode) {
            .xml => .xml,
            .json => .json_single,
            .jsonl => .json_lines,
        };
        var stdout_file = std.Io.File.stdout();
        try parser.parseConcurrent(.{ .io = io, .stdout_file = &stdout_file }, &reader, out_kind, num_threads);
    }
}

/// Ignore SIGPIPE to prevent crashes when stdout is closed (e.g. piped to head).
fn ignoreSigpipe() void {
    if (comptime builtin.os.tag != .windows) {
        const act = std.posix.Sigaction{
            .handler = .{ .handler = std.posix.SIG.IGN },
            .mask = std.mem.zeroes(std.posix.sigset_t),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.PIPE, &act, null);
    }
}

fn isPipeOrSocket(file: std.Io.File) bool {
    if (comptime builtin.os.tag == .windows) return false;

    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    const st = file.stat(threaded.io()) catch return false;
    return st.kind == .named_pipe or st.kind == .unix_domain_socket;
}

fn usage(io: std.Io, exit_code: u8) noreturn {
    printHelpAndExit(io, true, exit_code);
}

fn help(io: std.Io) noreturn {
    printHelpAndExit(io, false, 0);
}

fn printHelpAndExit(io: std.Io, to_stderr: bool, exit_code: u8) noreturn {
    const msg =
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

    var code: u8 = exit_code;
    var write_buf: [512]u8 = undefined;
    if (to_stderr) {
        const stderr_file = std.Io.File.stderr();
        var w = stderr_file.writer(io, &write_buf);
        w.writeAll(msg) catch |e| switch (e) {
            error.WriteFailed => {
                if (code == 0) code = 1;
            },
        };
        w.flush() catch |e| switch (e) {
            error.WriteFailed => {
                if (code == 0) code = 1;
            },
        };
    } else {
        const stdout_file = std.Io.File.stdout();
        var w = stdout_file.writer(io, &write_buf);
        w.writeAll(msg) catch |e| switch (e) {
            error.WriteFailed => {
                if (code == 0) code = 1;
            },
        };
        w.flush() catch |e| switch (e) {
            error.WriteFailed => {
                if (code == 0) code = 1;
            },
        };
    }
    std.process.exit(code);
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
