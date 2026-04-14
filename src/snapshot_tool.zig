//! Snapshot test CLI tool.
//!
//! Usage:
//!     snapshot_test                     # Run all tests
//!     snapshot_test --update            # Update snapshots from current output
//!     snapshot_test --test <name>       # Run specific test

const std = @import("std");
const snapshot_tests = @import("test/snapshot_tests.zig");
const alloc_mod = @import("alloc");

const project_root = getProjectRoot();
const samples_dir = project_root ++ "/samples";
const snapshots_dir = project_root ++ "/tests/snapshots";

const CliError = error{
    UnknownTest,
};

fn getProjectRoot() []const u8 {
    // This file is at src/snapshot_tool.zig
    // Project root is one directory up
    const src_path = @src().file;
    // Find the last slash and return everything before
    var i = src_path.len;
    while (i > 0) : (i -= 1) {
        if (src_path[i - 1] == '/') {
            // Found /src/file.zig, go up one more
            var j = i - 1;
            while (j > 0) : (j -= 1) {
                if (src_path[j - 1] == '/') {
                    return src_path[0 .. j - 1];
                }
            }
            return src_path[0 .. i - 1];
        }
    }
    return ".";
}

pub fn main(init: std.process.Init) void {
    const exit_code = run(init) catch |err| {
        // If stdout/stderr is closed (piped to head, etc), exit successfully.
        if (err == error.WriteFailed) return;
        // Error already reported to stderr.
        if (err == error.UnknownTest) std.process.exit(1);

        var write_buf: [512]u8 = undefined;
        const stderr_file = std.Io.File.stderr();
        var stderr = stderr_file.writer(init.io, &write_buf);
        _ = stderr.interface.print("snapshot_test: {s}\n", .{@errorName(err)}) catch {};
        stderr.flush() catch {};
        std.process.exit(1);
    };
    std.process.exit(exit_code);
}

fn run(init: std.process.Init) !u8 {
    const allocator = init.gpa;
    const io = init.io;

    var args_iter = std.process.Args.Iterator.init(init.minimal.args);

    // Skip program name
    _ = args_iter.next();

    var update_mode = false;
    var test_filter: ?[]const u8 = null;

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--update") or std.mem.eql(u8, arg, "-u")) {
            update_mode = true;
        } else if (std.mem.eql(u8, arg, "--test") or std.mem.eql(u8, arg, "-t")) {
            test_filter = args_iter.next();
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp(io);
            return 0;
        }
    }

    // Determine which tests to run
    var tests_to_run: []const snapshot_tests.SnapshotTest = &snapshot_tests.tests;

    // Filter if requested
    var filtered_tests: [snapshot_tests.tests.len]snapshot_tests.SnapshotTest = undefined;
    var filtered_count: usize = 0;

    if (test_filter) |filter| {
        for (snapshot_tests.tests) |t| {
            if (std.mem.eql(u8, t.name, filter)) {
                filtered_tests[filtered_count] = t;
                filtered_count += 1;
            }
        }
        if (filtered_count == 0) {
            var write_buf: [512]u8 = undefined;
            const stderr_file = std.Io.File.stderr();
            var stderr = stderr_file.writer(io, &write_buf);
            try stderr.interface.print("Unknown test: {s}\n", .{filter});
            try stderr.interface.writeAll("Available tests: ");
            for (snapshot_tests.tests, 0..) |t, i| {
                if (i > 0) try stderr.interface.writeAll(", ");
                try stderr.interface.writeAll(t.name);
            }
            try stderr.interface.writeAll("\n");
            try stderr.flush();
            return error.UnknownTest;
        }
        tests_to_run = filtered_tests[0..filtered_count];
    }

    var write_buf: [4096]u8 = undefined;
    const stdout_file = std.Io.File.stdout();
    var stdout = stdout_file.writer(io, &write_buf);
    const w = &stdout.interface;

    try w.writeAll("Running snapshot tests...\n\n");

    var passed: usize = 0;
    var failed: usize = 0;
    var skipped: usize = 0;

    for (tests_to_run) |t| {
        try w.print("[{s}] {s}\n", .{ t.name, t.description });

        const result = snapshot_tests.runTest(allocator, t, samples_dir, snapshots_dir, update_mode);

        switch (result.result) {
            .pass => {
                try w.writeAll("  PASS\n");
                passed += 1;
            },
            .fail => {
                try w.writeAll("  FAIL: ");
                if (result.message) |msg| {
                    try w.print("{s}\n", .{msg});
                } else {
                    try w.writeAll("Output differs\n");
                }

                // Show first difference if we have both
                if (result.actual != null and result.expected != null) {
                    const actual = result.actual.?;
                    const expected = result.expected.?;
                    defer allocator.free(actual);
                    defer allocator.free(expected);

                    var actual_lines = std.mem.splitScalar(u8, actual, '\n');
                    var expected_lines = std.mem.splitScalar(u8, expected, '\n');
                    var line_num: usize = 1;

                    while (true) {
                        const exp_line = expected_lines.next();
                        const act_line = actual_lines.next();

                        if (exp_line == null and act_line == null) break;

                        const exp = exp_line orelse "";
                        const act = act_line orelse "";

                        if (!std.mem.eql(u8, exp, act)) {
                            try w.print("        First diff at line {d}:\n", .{line_num});
                            const max_len: usize = 80;
                            const exp_preview = if (exp.len > max_len) exp[0..max_len] else exp;
                            const act_preview = if (act.len > max_len) act[0..max_len] else act;
                            try w.print("          Expected: {s}\n", .{exp_preview});
                            try w.print("          Actual:   {s}\n", .{act_preview});
                            break;
                        }
                        line_num += 1;
                    }
                }
                failed += 1;
            },
            .skip => {
                try w.writeAll("  SKIP: ");
                if (result.message) |msg| {
                    try w.print("{s}\n", .{msg});
                } else {
                    try w.writeAll("Skipped\n");
                }
                skipped += 1;
            },
            .updated => {
                try w.print("  UPDATED: {s}\n", .{t.expected_file});
                passed += 1;
            },
            .@"error" => {
                try w.writeAll("  ERROR: ");
                if (result.message) |msg| {
                    try w.print("{s}\n", .{msg});
                } else {
                    try w.writeAll("Unknown error\n");
                }
                failed += 1;
            },
        }
        try w.writeAll("\n");
    }

    try w.print("Results: {d} passed, {d} failed", .{ passed, failed });
    if (skipped > 0) {
        try w.print(", {d} skipped", .{skipped});
    }
    try w.writeAll("\n");
    try w.flush();

    return if (failed > 0) 1 else 0;
}

fn printHelp(io: std.Io) !void {
    var write_buf: [1024]u8 = undefined;
    const stdout_file = std.Io.File.stdout();
    var stdout = stdout_file.writer(io, &write_buf);
    try stdout.interface.writeAll(
        \\snapshot_test - Snapshot-based regression tests for EVTX parser
        \\
        \\Usage:
        \\  snapshot_test                     Run all tests
        \\  snapshot_test --update            Update snapshots from current output
        \\  snapshot_test --test <name>       Run specific test
        \\  snapshot_test --help              Show this help
        \\
        \\Options:
        \\  -u, --update      Update expected snapshots from current output
        \\  -t, --test NAME   Run only the specified test
        \\  -h, --help        Show this help message
        \\
    );
    try stdout.flush();
}
