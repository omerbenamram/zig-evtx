const std = @import("std");
const builtin = @import("builtin");
const alloc = @import("alloc");
const fs = std.fs;

const evtx = @import("parser/evtx/mod.zig");

/// Default read buffer size for file I/O
const READ_BUFFER_SIZE: usize = 8192;

pub fn main() !void {
    // Avoid SIGPIPE termination when stdout is closed (e.g. piped to head).
    ignoreSigpipe();

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
    var carve: bool = false;
    var ordered: bool = true;
    var threads_opt: ?usize = null;

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            help();
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

    const in_path = input_path orelse return usage();

    var file = try fs.cwd().openFile(in_path, .{ .mode = .read_only });
    defer file.close();

    var read_buf: [READ_BUFFER_SIZE]u8 = undefined;
    var reader = file.reader(&read_buf);

    var parser = evtx.EvtxParser.init(allocator, .{ .validate_checksums = validate_checksums, .verbosity = verbosity, .max_records = max_records, .skip_first = skip_first, .carve = carve, .ordered = ordered });

    const cpu_count = try std.Thread.getCpuCount();
    var num_threads: usize = threads_opt orelse cpu_count;
    if (num_threads == 0) num_threads = 1;

    if (num_threads <= 1) {
        var write_buf: [8192]u8 = undefined;
        var stdout_file = std.fs.File.stdout();
        var stdout_writer = stdout_file.writer(&write_buf);
        var output = switch (output_mode) {
            .xml => try evtx.OutputWriter.initXml(allocator, &stdout_writer.interface),
            .json => try evtx.OutputWriter.initJson(allocator, &stdout_writer.interface, .single),
            .jsonl => try evtx.OutputWriter.initJson(allocator, &stdout_writer.interface, .lines),
        };
        defer output.deinit();
        parser.parse(&reader, &output) catch |e| switch (e) {
            error.WriteFailed => if (isPipeOrSocket(stdout_file)) return else return e,
            else => return e,
        };
        output.flush() catch |e| switch (e) {
            error.WriteFailed => if (isPipeOrSocket(stdout_file)) return else return e,
            else => return e,
        };
    } else {
        const out_kind: evtx.EvtxParser.OutKind = switch (output_mode) {
            .xml => .xml,
            .json => .json_single,
            .jsonl => .json_lines,
        };
        try parser.parseConcurrent(&reader, out_kind, num_threads);
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

fn isPipeOrSocket(file: std.fs.File) bool {
    if (comptime builtin.os.tag == .windows) return false;
    const st = std.posix.fstat(file.handle) catch return false;
    const kind = st.mode & std.posix.S.IFMT;
    return kind == std.posix.S.IFIFO or kind == std.posix.S.IFSOCK;
}

fn usage() noreturn {
    printHelpAndExit(true, 2);
}

fn help() noreturn {
    printHelpAndExit(false, 0);
}

fn printHelpAndExit(to_stderr: bool, exit_code: u8) noreturn {
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
        var stderr_file = std.fs.File.stderr();
        var w = stderr_file.writer(&write_buf);
        w.interface.writeAll(msg) catch |e| switch (e) {
            error.WriteFailed => {
                if (code == 0) code = 1;
            },
        };
        w.interface.flush() catch |e| switch (e) {
            error.WriteFailed => {
                if (code == 0) code = 1;
            },
        };
    } else {
        var stdout_file = std.fs.File.stdout();
        var w = stdout_file.writer(&write_buf);
        w.interface.writeAll(msg) catch |e| switch (e) {
            error.WriteFailed => {
                if (code == 0) code = 1;
            },
        };
        w.interface.flush() catch |e| switch (e) {
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
    // util_string.zig and util_simd.zig tests are discovered via parser imports
}
