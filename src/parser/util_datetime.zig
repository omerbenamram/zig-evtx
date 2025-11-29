//! DateTime formatting utilities for Windows FILETIME and SystemTime.
//!
//! Provides conversion from Windows time formats to ISO8601 UTC strings.

const std = @import("std");

// ============================================================================
// Date/Time Calculation
// ============================================================================

const DateTimeParts = struct {
    year: i64,
    month: i64,
    day: i64,
    hour: u32,
    minute: u32,
    second: u32,
};

/// Convert Unix seconds to date/time components using Howard Hinnant's algorithm.
/// Reference: http://howardhinnant.github.io/date_algorithms.html
fn computeUtcFromUnixSeconds(unix_seconds: i64) DateTimeParts {
    const z0: i64 = @divFloor(unix_seconds, 86_400);
    const sod: i64 = unix_seconds - z0 * 86_400;
    const z = z0 + 719_468;
    const era = @divFloor(z, 146_097);
    const doe = z - era * 146_097;
    const yoe = @divFloor(doe - @divFloor(doe, 1_460) + @divFloor(doe, 36_524) - @divFloor(doe, 146_096), 365);
    var y: i64 = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = mp + 3 - 12 * @as(i32, @intFromBool(mp >= 10));
    y += @as(i64, @intFromBool(m <= 2));
    const hour: u32 = @intCast(@divFloor(sod, 3_600));
    const sod_rem: i64 = sod - @as(i64, hour) * 3_600;
    const minute: u32 = @intCast(@divFloor(sod_rem, 60));
    const second: u32 = @intCast(sod_rem - @as(i64, minute) * 60);
    return .{ .year = y, .month = m, .day = d, .hour = hour, .minute = minute, .second = second };
}

// ============================================================================
// FILETIME Formatting
// ============================================================================

/// Format a Windows FILETIME value as ISO8601 UTC string with microsecond precision.
///
/// FILETIME is 100-nanosecond intervals since January 1, 1601 UTC.
/// Output format: "YYYY-MM-DDTHH:MM:SS.ffffffZ"
pub fn formatIso8601UtcFromFiletimeMicros(buf: []u8, filetime: u64) ![]const u8 {
    const TICKS_PER_SEC: u64 = 10_000_000;
    const TICKS_PER_MICRO: u64 = 10;
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600; // Seconds between 1601 and 1970

    // Handle pre-Unix-epoch times
    if (filetime < EPOCH_DIFF_SECS * TICKS_PER_SEC) {
        return std.fmt.bufPrint(buf, "1970-01-01T00:00:00.000000Z", .{});
    }

    const total_seconds_1601: u64 = filetime / TICKS_PER_SEC;
    const unix_seconds: u64 = total_seconds_1601 - EPOCH_DIFF_SECS;
    const ticks_remainder: u64 = filetime % TICKS_PER_SEC;
    const micros: u32 = @intCast(ticks_remainder / TICKS_PER_MICRO);

    const parts = computeUtcFromUnixSeconds(@as(i64, @intCast(unix_seconds)));
    const year: u32 = @intCast(parts.year);
    const month: u32 = @intCast(parts.month);
    const day: u32 = @intCast(parts.day);

    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z", .{
        year, month, day, parts.hour, parts.minute, parts.second, micros,
    });
}

// ============================================================================
// Tests
// ============================================================================

test "computeUtcFromUnixSeconds - Unix epoch" {
    const parts = computeUtcFromUnixSeconds(0);
    try std.testing.expectEqual(@as(i64, 1970), parts.year);
    try std.testing.expectEqual(@as(i64, 1), parts.month);
    try std.testing.expectEqual(@as(i64, 1), parts.day);
    try std.testing.expectEqual(@as(u32, 0), parts.hour);
    try std.testing.expectEqual(@as(u32, 0), parts.minute);
    try std.testing.expectEqual(@as(u32, 0), parts.second);
}

test "computeUtcFromUnixSeconds - known date 2024-01-15 10:30:45" {
    // 2024-01-15 10:30:45 UTC
    const unix_secs: i64 = 1705314645;
    const parts = computeUtcFromUnixSeconds(unix_secs);
    try std.testing.expectEqual(@as(i64, 2024), parts.year);
    try std.testing.expectEqual(@as(i64, 1), parts.month);
    try std.testing.expectEqual(@as(i64, 15), parts.day);
    try std.testing.expectEqual(@as(u32, 10), parts.hour);
    try std.testing.expectEqual(@as(u32, 30), parts.minute);
    try std.testing.expectEqual(@as(u32, 45), parts.second);
}

test "computeUtcFromUnixSeconds - leap year Feb 29" {
    // 2024-02-29 12:00:00 UTC (2024 is a leap year)
    const unix_secs: i64 = 1709208000;
    const parts = computeUtcFromUnixSeconds(unix_secs);
    try std.testing.expectEqual(@as(i64, 2024), parts.year);
    try std.testing.expectEqual(@as(i64, 2), parts.month);
    try std.testing.expectEqual(@as(i64, 29), parts.day);
    try std.testing.expectEqual(@as(u32, 12), parts.hour);
}

test "computeUtcFromUnixSeconds - year boundary Dec 31 to Jan 1" {
    // 2023-12-31 23:59:59 UTC
    const parts1 = computeUtcFromUnixSeconds(1704067199);
    try std.testing.expectEqual(@as(i64, 2023), parts1.year);
    try std.testing.expectEqual(@as(i64, 12), parts1.month);
    try std.testing.expectEqual(@as(i64, 31), parts1.day);
    try std.testing.expectEqual(@as(u32, 23), parts1.hour);
    try std.testing.expectEqual(@as(u32, 59), parts1.minute);
    try std.testing.expectEqual(@as(u32, 59), parts1.second);

    // 2024-01-01 00:00:00 UTC
    const parts2 = computeUtcFromUnixSeconds(1704067200);
    try std.testing.expectEqual(@as(i64, 2024), parts2.year);
    try std.testing.expectEqual(@as(i64, 1), parts2.month);
    try std.testing.expectEqual(@as(i64, 1), parts2.day);
    try std.testing.expectEqual(@as(u32, 0), parts2.hour);
    try std.testing.expectEqual(@as(u32, 0), parts2.minute);
    try std.testing.expectEqual(@as(u32, 0), parts2.second);
}

test "formatIso8601UtcFromFiletimeMicros - known EVTX timestamp" {
    // FILETIME for 2017-07-12T21:56:05.539657Z
    // 131443701655396570 (100-ns intervals since 1601-01-01)
    const filetime: u64 = 131443701655396570;
    var buf: [40]u8 = undefined;
    const result = try formatIso8601UtcFromFiletimeMicros(&buf, filetime);
    try std.testing.expectEqualStrings("2017-07-12T21:56:05.539657Z", result);
}

test "formatIso8601UtcFromFiletimeMicros - Unix epoch as FILETIME" {
    // FILETIME for 1970-01-01 00:00:00.000000Z
    // 11644473600 seconds * 10_000_000 ticks/sec = 116444736000000000
    const filetime: u64 = 116444736000000000;
    var buf: [40]u8 = undefined;
    const result = try formatIso8601UtcFromFiletimeMicros(&buf, filetime);
    try std.testing.expectEqualStrings("1970-01-01T00:00:00.000000Z", result);
}

test "formatIso8601UtcFromFiletimeMicros - pre-Unix-epoch returns epoch" {
    // Any FILETIME before Unix epoch should return 1970-01-01
    const filetime: u64 = 100; // Way before Unix epoch
    var buf: [40]u8 = undefined;
    const result = try formatIso8601UtcFromFiletimeMicros(&buf, filetime);
    try std.testing.expectEqualStrings("1970-01-01T00:00:00.000000Z", result);
}

test "formatIso8601UtcFromFiletimeMicros - microsecond precision" {
    // Test that we get exactly 6 fractional digits
    // FILETIME for 2024-01-15 10:30:45.123456Z
    // Unix: 1705314645.123456 seconds
    // FILETIME: (1705314645 + 11644473600) * 10_000_000 + 1234560
    const filetime: u64 = (1705314645 + 11644473600) * 10_000_000 + 1234560;
    var buf: [40]u8 = undefined;
    const result = try formatIso8601UtcFromFiletimeMicros(&buf, filetime);
    try std.testing.expectEqualStrings("2024-01-15T10:30:45.123456Z", result);
}

test "formatIso8601UtcFromFiletimeMicros - zero microseconds" {
    // Test that zero microseconds produces .000000
    const filetime: u64 = (1705314645 + 11644473600) * 10_000_000;
    var buf: [40]u8 = undefined;
    const result = try formatIso8601UtcFromFiletimeMicros(&buf, filetime);
    try std.testing.expectEqualStrings("2024-01-15T10:30:45.000000Z", result);
}
