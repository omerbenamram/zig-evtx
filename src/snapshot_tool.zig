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

pub fn main() !void {
    const allocator = alloc_mod.get();

    var args_iter = try std.process.argsWithAllocator(allocator);
    defer args_iter.deinit();

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
            printHelp();
            return;
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
            var stderr_file = std.fs.File.stderr();
            var stderr = stderr_file.writer(&write_buf);
            stderr.interface.print("Unknown test: {s}\n", .{filter}) catch {};
            stderr.interface.writeAll("Available tests: ") catch {};
            for (snapshot_tests.tests, 0..) |t, i| {
                if (i > 0) stderr.interface.writeAll(", ") catch {};
                stderr.interface.writeAll(t.name) catch {};
            }
            stderr.interface.writeAll("\n") catch {};
            stderr.interface.flush() catch {};
            std.process.exit(1);
        }
        tests_to_run = filtered_tests[0..filtered_count];
    }

    var write_buf: [4096]u8 = undefined;
    var stdout_file = std.fs.File.stdout();
    var stdout = stdout_file.writer(&write_buf);
    const w = &stdout.interface;

    w.writeAll("Running snapshot tests...\n\n") catch {};

    var passed: usize = 0;
    var failed: usize = 0;
    var skipped: usize = 0;

    for (tests_to_run) |t| {
        w.print("[{s}] {s}\n", .{ t.name, t.description }) catch {};

        const result = snapshot_tests.runTest(allocator, t, samples_dir, snapshots_dir, update_mode);

        switch (result.result) {
            .pass => {
                w.writeAll("  PASS\n") catch {};
                passed += 1;
            },
            .fail => {
                w.writeAll("  FAIL: ") catch {};
                if (result.message) |msg| {
                    w.print("{s}\n", .{msg}) catch {};
                } else {
                    w.writeAll("Output differs\n") catch {};
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
                            w.print("        First diff at line {d}:\n", .{line_num}) catch {};
                            const max_len: usize = 80;
                            const exp_preview = if (exp.len > max_len) exp[0..max_len] else exp;
                            const act_preview = if (act.len > max_len) act[0..max_len] else act;
                            w.print("          Expected: {s}\n", .{exp_preview}) catch {};
                            w.print("          Actual:   {s}\n", .{act_preview}) catch {};
                            break;
                        }
                        line_num += 1;
                    }
                }
                failed += 1;
            },
            .skip => {
                w.writeAll("  SKIP: ") catch {};
                if (result.message) |msg| {
                    w.print("{s}\n", .{msg}) catch {};
                } else {
                    w.writeAll("Skipped\n") catch {};
                }
                skipped += 1;
            },
            .updated => {
                w.print("  UPDATED: {s}\n", .{t.expected_file}) catch {};
                passed += 1;
            },
            .@"error" => {
                w.writeAll("  ERROR: ") catch {};
                if (result.message) |msg| {
                    w.print("{s}\n", .{msg}) catch {};
                } else {
                    w.writeAll("Unknown error\n") catch {};
                }
                failed += 1;
            },
        }
        w.writeAll("\n") catch {};
    }

    w.print("Results: {d} passed, {d} failed", .{ passed, failed }) catch {};
    if (skipped > 0) {
        w.print(", {d} skipped", .{skipped}) catch {};
    }
    w.writeAll("\n") catch {};
    w.flush() catch {};

    if (failed > 0) {
        std.process.exit(1);
    }
}

fn printHelp() void {
    var write_buf: [1024]u8 = undefined;
    var stdout_file = std.fs.File.stdout();
    var stdout = stdout_file.writer(&write_buf);
    stdout.interface.writeAll(
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
    ) catch {};
    stdout.interface.flush() catch {};
}

