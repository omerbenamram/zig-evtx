//! Snapshot test definitions and runner.
//!
//! Compares parser output against saved expected snapshots.
//! Similar to cargo insta - stores expected output as files.

const std = @import("std");
const normalize_xml = @import("normalize_xml.zig");
const evtx = @import("../parser/evtx/mod.zig");
const alloc_mod = @import("alloc");

const READ_BUFFER_SIZE: usize = 8192;
const MAX_EXPECTED_FILE_SIZE: usize = 1024 * 1024;

pub const OutputFormat = enum { xml, json };

pub const SnapshotTest = struct {
    name: []const u8,
    description: []const u8,
    evtx_file: []const u8,
    record_id: u64,
    expected_file: []const u8,
    format: OutputFormat = .xml,
};

/// All snapshot test definitions
pub const tests = [_]SnapshotTest{
    // XML tests
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
    // JSON tests - verify Rust-compatible output format
    .{
        .name = "json_basic_structure",
        .description = "Null elements (Correlation/Security), GUID format (uppercase, no braces), numeric values",
        .evtx_file = "security.evtx",
        .record_id = 1,
        .expected_file = "record_1_json.expected.json",
        .format = .json,
    },
    .{
        .name = "json_eventdata_flattening",
        .description = "EventData Data elements should flatten to key-value pairs (Name attr becomes key)",
        .evtx_file = "security.evtx",
        .record_id = 2,
        .expected_file = "record_2_eventdata.expected.json",
        .format = .json,
    },
    .{
        .name = "json_logon_event",
        .description = "Full logon event with EventData fields and numeric ProcessID/ThreadID",
        .evtx_file = "security.evtx",
        .record_id = 16,
        .expected_file = "record_16_logon.expected.json",
        .format = .json,
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

/// Get record output by EventRecordID from an EVTX file.
fn getRecordById(io: std.Io, allocator: std.mem.Allocator, evtx_path: []const u8, record_id: u64, format: OutputFormat) ![]u8 {
    var file = try std.Io.Dir.cwd().openFile(io, evtx_path, .{ .mode = .read_only });
    defer file.close(io);

    var read_buf: [READ_BUFFER_SIZE]u8 = undefined;
    var reader = file.reader(io, &read_buf);

    // Read file header
    const hdr = try evtx.FileHeader.read(&reader.interface);
    _ = hdr; // We'll iterate all chunks in carve mode

    // Create a serializer for record output
    var out = try evtx.Serializer.init(allocator, switch (format) {
        .xml => .xml,
        .json => .json_lines,
    });
    defer out.deinit();

    // Create context for parsing
    var ctx = evtx.Context.init(allocator);
    defer ctx.deinit();

    // Read chunks until EOF or we find the record
    while (true) {
        const chunk = evtx.Chunk.read(allocator, &reader.interface) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };
        defer chunk.deinit();

        // Reset context for each chunk and pre-cache common strings
        ctx.resetPerChunk();
        try ctx.preCacheFromChunkHeader(chunk.buf, &chunk.header.common_string_offsets);

        var rec_iter = chunk.records();
        while (try rec_iter.next()) |rec| {
            if (rec.identifier == record_id) {
                // Found it! Serialize
                const bytes = try out.serializeRecord(rec, &ctx);
                // Copy because the output buffer is reused
                // Trim trailing newline for JSON comparison
                const trimmed = std.mem.trim(u8, bytes, "\n");
                return try allocator.dupe(u8, trimmed);
            }
        }
    }

    return error.RecordNotFound;
}

/// Normalize JSON by parsing and re-serializing to a canonical form.
/// This allows comparing pretty-printed vs compact JSON.
fn normalizeJson(allocator: std.mem.Allocator, json_str: []const u8) ![]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch {
        return error.JsonParseError;
    };
    defer parsed.deinit();

    // Use fmt to serialize to canonical form
    return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(parsed.value, .{})}) catch {
        return error.JsonStringifyError;
    };
}

fn pathExists(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn makePath(io: std.Io, path: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, path);
}

fn writeFile(io: std.Io, path: []const u8, contents: []const u8) !void {
    var out_file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer out_file.close(io);

    var write_buf: [READ_BUFFER_SIZE]u8 = undefined;
    var writer = out_file.writer(io, &write_buf);
    try writer.interface.writeAll(contents);
    try writer.flush();
}

fn readFileAlloc(io: std.Io, allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.size > max_bytes) return error.FileTooBig;

    const file_size: usize = @intCast(stat.size);
    const contents = try allocator.alloc(u8, file_size);
    errdefer allocator.free(contents);

    if (file_size == 0) return contents;

    var read_buf: [READ_BUFFER_SIZE]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    try reader.interface.readSliceAll(contents);

    return contents;
}

/// Run a single snapshot test.
pub fn runTest(
    allocator: std.mem.Allocator,
    test_def: SnapshotTest,
    samples_dir: []const u8,
    snapshots_dir: []const u8,
    update_mode: bool,
) TestOutput {
    var io_impl = std.Io.Threaded.init(allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();

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
    if (!pathExists(io, evtx_path)) {
        return .{ .result = .skip, .message = "EVTX file not found" };
    }

    // Get actual output
    const actual_raw = getRecordById(io, allocator, evtx_path, test_def.record_id, test_def.format) catch |err| {
        const msg = std.fmt.allocPrint(allocator, "Failed to get record: {s}", .{@errorName(err)}) catch "Parse error";
        return .{ .result = .@"error", .message = msg };
    };
    defer allocator.free(actual_raw);

    // Normalize actual output for comparison
    var actual_normalized: ?[]u8 = null;
    actual_normalized = switch (test_def.format) {
        .xml => normalize_xml.normalize(allocator, actual_raw) catch {
            return .{ .result = .@"error", .message = "Failed to normalize actual" };
        },
        .json => normalizeJson(allocator, actual_raw) catch {
            return .{ .result = .@"error", .message = "Failed to normalize actual JSON" };
        },
    };
    defer if (actual_normalized) |s| allocator.free(s);

    const actual_compare = actual_normalized.?;

    if (update_mode) {
        // Write actual to expected file
        const dir = std.fs.path.dirname(expected_path) orelse ".";
        makePath(io, dir) catch {
            return .{ .result = .@"error", .message = "Failed to create snapshots directory" };
        };

        writeFile(io, expected_path, actual_raw) catch {
            return .{ .result = .@"error", .message = "Failed to write expected file" };
        };

        return .{ .result = .updated };
    }

    // Load expected
    const expected_raw = readFileAlloc(io, allocator, expected_path, MAX_EXPECTED_FILE_SIZE) catch {
        return .{ .result = .fail, .message = "Expected file not found. Run with --update to create it." };
    };
    defer allocator.free(expected_raw);

    // Normalize expected output for comparison
    var expected_normalized: ?[]u8 = null;
    expected_normalized = switch (test_def.format) {
        .xml => normalize_xml.normalize(allocator, expected_raw) catch {
            return .{ .result = .@"error", .message = "Failed to normalize expected" };
        },
        .json => normalizeJson(allocator, std.mem.trim(u8, expected_raw, "\n\r \t")) catch {
            return .{ .result = .@"error", .message = "Failed to normalize expected JSON" };
        },
    };
    defer if (expected_normalized) |s| allocator.free(s);

    const expected_compare = expected_normalized.?;

    // Compare
    if (std.mem.eql(u8, actual_compare, expected_compare)) {
        return .{ .result = .pass };
    } else {
        // Return the normalized outputs to the caller (no extra allocation).
        const actual_out = actual_normalized.?;
        const expected_out = expected_normalized.?;
        actual_normalized = null;
        expected_normalized = null;
        return .{
            .result = .fail,
            .message = "Output differs from expected",
            .actual = actual_out,
            .expected = expected_out,
        };
    }
}

// ============================================================================
// Comptime Test Generation - integrates with `zig test` / `make test`
// ============================================================================

const test_util = @import("util.zig");

fn getProjectRoot() []const u8 {
    return comptime test_util.getProjectRoot(@src().file);
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
