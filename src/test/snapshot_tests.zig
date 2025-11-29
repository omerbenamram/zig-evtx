//! Snapshot test definitions and runner.
//!
//! Compares parser output against saved expected snapshots.
//! Similar to cargo insta - stores expected output as files.

const std = @import("std");
const normalize_xml = @import("normalize_xml.zig");
const evtx = @import("../parser/evtx/mod.zig");
const alloc_mod = @import("alloc");

pub const SnapshotTest = struct {
    name: []const u8,
    description: []const u8,
    evtx_file: []const u8,
    record_id: u64,
    expected_file: []const u8,
};

/// All snapshot test definitions
pub const tests = [_]SnapshotTest{
    .{
        .name = "trailing_spaces",
        .description = "String values should have trailing spaces trimmed (e.g., 'Advapi  ' -> 'Advapi')",
        .evtx_file = "security.evtx",
        .record_id = 16,
        .expected_file = "record_16_trailing_spaces.expected.xml",
    },
    .{
        .name = "nested_binxml",
        .description = "Nested BinXML (type 0x21) should render child elements (e.g., UserData/ServiceShutdown)",
        .evtx_file = "security.evtx",
        .record_id = 38,
        .expected_file = "record_38_nested_binxml.expected.xml",
    },
    .{
        .name = "ansi_string_array",
        .description = "ANSI string arrays should be comma-separated (e.g., '10.00.,15063,,Multiprocessor Free,0')",
        .evtx_file = "system.evtx",
        .record_id = 1,
        .expected_file = "record_1_ansi_string_array.expected.xml",
    },
    .{
        .name = "ansi_string_null",
        .description = "ANSI strings should have trailing null stripped (e.g., 'NOEXECUTE=OPTIN')",
        .evtx_file = "system.evtx",
        .record_id = 5,
        .expected_file = "record_5_ansi_string_null.expected.xml",
    },
};

pub const TestResult = enum {
    pass,
    fail,
    skip,
    updated,
    @"error",
};

pub const TestOutput = struct {
    result: TestResult,
    message: ?[]const u8 = null,
    actual: ?[]const u8 = null,
    expected: ?[]const u8 = null,
};

/// Get record XML by EventRecordID from an EVTX file.
fn getRecordById(allocator: std.mem.Allocator, evtx_path: []const u8, record_id: u64) ![]u8 {
    var file = std.fs.cwd().openFile(evtx_path, .{ .mode = .read_only }) catch |err| {
        return err;
    };
    defer file.close();

    var read_buf: [8192]u8 = undefined;
    var reader = file.reader(&read_buf);

    // Read file header
    const hdr = try evtx.FileHeader.read(&reader);
    _ = hdr; // We'll iterate all chunks in carve mode

    // Create an output writer to serialize records
    var out = evtx.OutputWriter.initSerializeOnly(.xml);
    defer out.deinit();

    // Create context for parsing
    var ctx = try evtx.Context.init(allocator);
    defer ctx.deinit();

    // Read chunks until EOF or we find the record
    while (true) {
        const chunk = evtx.Chunk.read(&reader) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };

        // Reset context for each chunk and pre-cache common strings
        ctx.resetPerChunk();
        ctx.preCacheFromChunkHeader(&chunk.buf, &chunk.header.common_string_offsets);

        var rec_iter = chunk.records();
        while (try rec_iter.next()) |rec| {
            if (rec.identifier == record_id) {
                // Found it! Serialize to XML
                const view = evtx.EventRecordView{
                    .id = rec.identifier,
                    .timestamp_filetime = rec.written_time,
                    .raw_xml = rec.binxml,
                    .chunk_buf = rec.chunk_buf,
                };

                const bytes = try out.serializeRecord(view, &ctx);
                // Copy because the output buffer is reused
                return try allocator.dupe(u8, bytes);
            }
        }
    }

    return error.RecordNotFound;
}

/// Run a single snapshot test.
pub fn runTest(
    allocator: std.mem.Allocator,
    test_def: SnapshotTest,
    samples_dir: []const u8,
    snapshots_dir: []const u8,
    update_mode: bool,
) TestOutput {
    // Build paths
    const evtx_path = std.fs.path.join(allocator, &.{ samples_dir, test_def.evtx_file }) catch {
        return .{ .result = .@"error", .message = "Failed to build evtx path" };
    };
    defer allocator.free(evtx_path);

    const expected_path = std.fs.path.join(allocator, &.{ snapshots_dir, test_def.expected_file }) catch {
        return .{ .result = .@"error", .message = "Failed to build expected path" };
    };
    defer allocator.free(expected_path);

    // Check if evtx file exists
    std.fs.cwd().access(evtx_path, .{}) catch {
        return .{ .result = .skip, .message = "EVTX file not found" };
    };

    // Get actual output
    const actual_raw = getRecordById(allocator, evtx_path, test_def.record_id) catch |err| {
        const msg = std.fmt.allocPrint(allocator, "Failed to get record: {s}", .{@errorName(err)}) catch "Parse error";
        return .{ .result = .@"error", .message = msg };
    };
    defer allocator.free(actual_raw);

    // Normalize actual
    const actual_normalized = normalize_xml.normalize(allocator, actual_raw) catch {
        return .{ .result = .@"error", .message = "Failed to normalize actual" };
    };
    defer allocator.free(actual_normalized);

    if (update_mode) {
        // Write actual to expected file
        const dir = std.fs.path.dirname(expected_path) orelse ".";
        std.fs.cwd().makePath(dir) catch {};

        var out_file = std.fs.cwd().createFile(expected_path, .{}) catch {
            return .{ .result = .@"error", .message = "Failed to create expected file" };
        };
        defer out_file.close();

        out_file.writeAll(actual_raw) catch {
            return .{ .result = .@"error", .message = "Failed to write expected file" };
        };

        return .{ .result = .updated };
    }

    // Load expected
    const expected_raw = std.fs.cwd().readFileAlloc(allocator, expected_path, 1024 * 1024) catch {
        return .{ .result = .fail, .message = "Expected file not found. Run with --update to create it." };
    };
    defer allocator.free(expected_raw);

    // Normalize expected
    const expected_normalized = normalize_xml.normalize(allocator, expected_raw) catch {
        return .{ .result = .@"error", .message = "Failed to normalize expected" };
    };
    defer allocator.free(expected_normalized);

    // Compare
    if (std.mem.eql(u8, actual_normalized, expected_normalized)) {
        return .{ .result = .pass };
    } else {
        // Find first difference for helpful output
        const actual_dupe = allocator.dupe(u8, actual_normalized) catch null;
        const expected_dupe = allocator.dupe(u8, expected_normalized) catch null;
        return .{
            .result = .fail,
            .message = "Output differs from expected",
            .actual = actual_dupe,
            .expected = expected_dupe,
        };
    }
}

// ============================================================================
// Comptime Test Generation - integrates with `zig test` / `make test`
// ============================================================================

/// Get project root from source file path at comptime
fn getProjectRoot() []const u8 {
    const src_path = @src().file;
    // This file is at src/test/snapshot_tests.zig (3 path components from root)
    comptime var i = src_path.len;
    comptime var count: usize = 0;
    inline while (i > 0) : (i -= 1) {
        if (src_path[i - 1] == '/') {
            count += 1;
            if (count == 3) {
                return src_path[0 .. i - 1];
            }
        }
    }
    return ".";
}

const project_root = getProjectRoot();
const default_samples_dir = project_root ++ "/samples";
const default_snapshots_dir = project_root ++ "/tests/snapshots";

/// Helper to run a snapshot test and return error on failure
fn runSnapshotTestOrFail(comptime test_def: SnapshotTest) !void {
    const allocator = std.testing.allocator;
    const result = runTest(allocator, test_def, default_samples_dir, default_snapshots_dir, false);

    // Free any allocated error messages
    defer if (result.actual) |a| allocator.free(a);
    defer if (result.expected) |e| allocator.free(e);

    switch (result.result) {
        .pass => {},
        .skip => {
            // Skip is not a failure for zig test - just return success
            return;
        },
        .fail => {
            std.debug.print("\n[FAIL] snapshot/{s}: {s}\n", .{ test_def.name, result.message orelse "mismatch" });
            if (result.actual != null and result.expected != null) {
                var act_lines = std.mem.splitScalar(u8, result.actual.?, '\n');
                var exp_lines = std.mem.splitScalar(u8, result.expected.?, '\n');
                var line: usize = 1;
                while (true) : (line += 1) {
                    const exp = exp_lines.next() orelse break;
                    const act = act_lines.next() orelse break;
                    if (!std.mem.eql(u8, exp, act)) {
                        std.debug.print("  Line {d} differs:\n", .{line});
                        std.debug.print("    Expected: {s}\n", .{exp[0..@min(exp.len, 70)]});
                        std.debug.print("    Actual:   {s}\n", .{act[0..@min(act.len, 70)]});
                        break;
                    }
                }
            }
            return error.SnapshotMismatch;
        },
        .@"error" => {
            std.debug.print("\n[ERROR] snapshot/{s}: {s}\n", .{ test_def.name, result.message orelse "unknown" });
            return error.SnapshotTestError;
        },
        .updated => unreachable, // update_mode is false
    }
}

// Generate test cases at comptime using the anonymous struct pattern
comptime {
    for (tests) |t| {
        _ = struct {
            // Each struct gets its own test block that captures `t` from the comptime scope
            test {
                try runSnapshotTestOrFail(t);
            }
        };
    }
}
