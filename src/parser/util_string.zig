//! String encoding utilities for UTF-16LE and CP-1252 conversion.
//!
//! Provides unified UTF-16LE to UTF-8 conversion with configurable escaping
//! for XML, JSON, or raw output. Also handles Windows CP-1252 (ANSI) encoding.
//!
//! ## Why not use stdlib directly?
//!
//! The standard library provides useful building blocks:
//!
//! - `std.unicode.Wtf16LeIterator` - iterates UTF-16LE bytes → codepoints
//!   (handles unpaired surrogates gracefully). We use this internally.
//!
//! - `std.unicode.utf8Encode` - encodes a codepoint → UTF-8 bytes.
//!   We use this internally.
//!
//! - `std.json.Stringify.encodeJsonStringChars` - escapes UTF-8 for JSON.
//!   However, this takes UTF-8 input, not UTF-16.
//!
//! - No XML escaping exists in stdlib (no `std.xml` module).
//!
//! ## Why our fused approach is optimal
//!
//! Using stdlib's JSON escaper would require:
//!
//! 1. **Two-pass approach**: Convert UTF-16 → UTF-8 buffer, then escape UTF-8.
//!    This requires intermediate memory allocation or fixed buffer management.
//!
//! 2. **Per-codepoint calls**: Call stdlib escaper for each character.
//!    Function call overhead dominates for small strings.
//!
//! Our implementation fuses conversion and escaping in a single pass:
//! - Iterate UTF-16 codepoints (via stdlib iterator)
//! - Encode to UTF-8 and escape in one step
//! - Write directly to output buffer
//!
//! This eliminates intermediate allocations and reduces memory bandwidth.
//!
//! ## Why []const u8 instead of []const u16?
//!
//! EVTX binary data comes from raw file reads with no alignment guarantee.
//! Using `[]const u16` would require `@alignCast` which can crash on
//! unaligned data. The stdlib iterator handles this by using `mem.readInt`
//! internally, which works on unaligned bytes.

const std = @import("std");
const simd = @import("util_simd.zig");

/// Writer error type for output functions.
pub const WriterError = std.Io.Writer.Error;

/// SIMD threshold: use SIMD for inputs >= 16 UTF-16 code units (32 bytes).
const SIMD_THRESHOLD: usize = 16;

// ============================================================================
// Escape Mode
// ============================================================================

/// Escaping mode for UTF-16 to UTF-8 conversion.
pub const EscapeMode = enum {
    /// No escaping - raw UTF-8 output
    none,
    /// XML escaping: & < > " ' → &amp; &lt; &gt; &quot; &apos;
    xml,
    /// JSON escaping: " \ and control chars → \", \\, \n, \uXXXX etc.
    json,
};

// ============================================================================
// Public API - UTF-16LE Conversion
// ============================================================================

/// Write UTF-16LE input as XML-escaped UTF-8.
/// Uses SIMD acceleration for inputs >= 16 code units.
pub fn writeUtf16LeXmlEscaped(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    const max_chars = @min(num_chars, utf16le.len / 2);
    if (max_chars >= SIMD_THRESHOLD) {
        return simd.writeUtf16LeXmlEscaped_simd(w, utf16le, num_chars);
    }
    return writeUtf16LeScalar(w, utf16le, num_chars, .xml);
}

/// Write UTF-16LE input as JSON-escaped UTF-8.
/// Uses SIMD acceleration for inputs >= 16 code units.
pub fn writeUtf16LeJsonEscaped(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    const max_chars = @min(num_chars, utf16le.len / 2);
    if (max_chars >= SIMD_THRESHOLD) {
        return simd.writeUtf16LeJsonEscaped_simd(w, utf16le, num_chars);
    }
    return writeUtf16LeScalar(w, utf16le, num_chars, .json);
}

/// Write UTF-16LE input as raw UTF-8 (no escaping).
pub fn writeUtf16LeRawToUtf8(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    return writeUtf16LeScalar(w, utf16le, num_chars, .none);
}

// Re-exports for benchmark compatibility
pub const writeUtf16LeXmlEscaped_simd_utf16 = simd.writeUtf16LeXmlEscaped_simd;
pub const writeUtf16LeJsonEscaped_simd = simd.writeUtf16LeJsonEscaped_simd;

/// Scalar XML-escaped conversion (for benchmarking).
pub fn writeUtf16LeXmlEscaped_scalar(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    return writeUtf16LeScalar(w, utf16le, num_chars, .xml);
}

/// Scalar JSON-escaped conversion (for benchmarking).
pub fn writeUtf16LeJsonEscaped_scalar(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    return writeUtf16LeScalar(w, utf16le, num_chars, .json);
}

// ============================================================================
// Shared ASCII Fast Path
// ============================================================================

/// Check if an ASCII byte needs escaping for the given mode.
/// Used by the ASCII fast path to detect when to bail to the slow path.
inline fn asciiNeedsEscape(c: u8, comptime mode: EscapeMode) bool {
    return switch (mode) {
        .none => false,
        .xml => switch (c) {
            '&', '<', '>', '"', '\'' => true,
            else => false,
        },
        .json => switch (c) {
            '"', '\\' => true,
            0x00...0x1F => true, // Control characters
            else => false,
        },
    };
}

/// Shared ASCII fast path for UTF-16LE to UTF-8 conversion.
///
/// Processes pure ASCII characters (hi byte = 0, lo byte <= 0x7F) that don't
/// need escaping, copying the low bytes directly to the output buffer.
///
/// Returns: (bytes_consumed_from_input, bytes_written_to_output)
///
/// This is shared between `writeUtf16LeScalar` and `convertUtf16ToUtf8` to
/// avoid code duplication. The ASCII fast path is the critical optimization
/// for EVTX parsing where ~95% of strings are pure ASCII.
///
/// ## Why not use stdlib?
///
/// `std.unicode.wtf16LeToWtf8` requires `[]const u16` (aligned memory).
/// EVTX data comes from raw file reads as `[]const u8` with no alignment
/// guarantee. The stdlib `Wtf16LeIterator` handles this via `mem.readInt`,
/// which is what we use for the fallback path.
fn asciiConvertFastPath(
    utf16le: []const u8,
    out_buf: []u8,
    comptime escape_mode: EscapeMode,
) struct { in_consumed: usize, out_written: usize } {
    var byte_pos: usize = 0;
    var out_len: usize = 0;

    while (byte_pos + 1 < utf16le.len and out_len < out_buf.len) {
        const lo = utf16le[byte_pos];
        const hi = utf16le[byte_pos + 1];

        // Non-ASCII: high byte non-zero OR low byte > 0x7F
        // (Latin-1 chars like é = 0xE9 need 2-byte UTF-8 encoding)
        if (hi != 0 or lo > 0x7F) break;

        // Check if this ASCII byte needs escaping (for XML/JSON modes)
        if (asciiNeedsEscape(lo, escape_mode)) break;

        // Pure ASCII, no escape needed - copy low byte directly
        // (ASCII bytes are valid UTF-8 as-is)
        out_buf[out_len] = lo;
        out_len += 1;
        byte_pos += 2;
    }

    return .{ .in_consumed = byte_pos, .out_written = out_len };
}

// ============================================================================
// Unified Scalar Implementation
// ============================================================================

/// Unified UTF-16LE to UTF-8 conversion with configurable escaping.
///
/// Uses a two-phase approach optimized for EVTX data:
/// 1. **ASCII Fast Path** (via `asciiConvertFastPath`) - handles ~95% of strings
/// 2. **Iterator Fallback** - handles non-ASCII, surrogates, and escaping
///
/// See `asciiConvertFastPath` for details on why we don't use stdlib directly.
fn writeUtf16LeScalar(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize, comptime mode: EscapeMode) WriterError!void {
    var out_buf: [2048]u8 = undefined;

    const max_bytes = @min(num_chars * 2, utf16le.len);
    if (max_bytes < 2) return;

    // Phase 1: ASCII Fast Path (shared implementation)
    const fast = asciiConvertFastPath(utf16le[0..max_bytes], &out_buf, mode);
    var out_len = fast.out_written;
    const byte_pos = fast.in_consumed;

    // If we processed everything in fast path, flush and return
    if (byte_pos >= max_bytes) {
        if (out_len > 0) try w.writeAll(out_buf[0..out_len]);
        return;
    }

    // Phase 2: Iterator Fallback for non-ASCII / escape chars
    var it: std.unicode.Wtf16LeIterator = .{
        .bytes = utf16le[byte_pos..max_bytes],
        .i = 0,
    };

    while (it.nextCodepoint()) |codepoint| {
        // Skip surrogate codepoints (WTF-16 may return them for unpaired surrogates)
        if (std.unicode.isSurrogateCodepoint(codepoint)) continue;

        // Encode codepoint to UTF-8
        var utf8_buf: [4]u8 = undefined;
        const utf8_len = std.unicode.utf8Encode(codepoint, &utf8_buf) catch continue;

        // Apply escape mode to each UTF-8 byte
        for (utf8_buf[0..utf8_len]) |c| {
            const escaped = switch (mode) {
                .none => null,
                .xml => xmlEscape(c),
                .json => jsonEscape(c),
            };

            if (escaped) |esc| {
                if (out_len + esc.len > out_buf.len) {
                    try w.writeAll(out_buf[0..out_len]);
                    out_len = 0;
                }
                @memcpy(out_buf[out_len..][0..esc.len], esc);
                out_len += esc.len;
            } else if (mode == .json and c < 0x20) {
                // JSON: control characters need \uXXXX encoding
                if (out_len + 6 > out_buf.len) {
                    try w.writeAll(out_buf[0..out_len]);
                    out_len = 0;
                }
                const hex = "0123456789ABCDEF";
                out_buf[out_len + 0] = '\\';
                out_buf[out_len + 1] = 'u';
                out_buf[out_len + 2] = '0';
                out_buf[out_len + 3] = '0';
                out_buf[out_len + 4] = hex[@as(usize, c >> 4)];
                out_buf[out_len + 5] = hex[@as(usize, c & 0xF)];
                out_len += 6;
            } else {
                // No escaping needed
                if (out_len == out_buf.len) {
                    try w.writeAll(out_buf[0..out_len]);
                    out_len = 0;
                }
                out_buf[out_len] = c;
                out_len += 1;
            }
        }
    }

    if (out_len > 0) try w.writeAll(out_buf[0..out_len]);
}

/// Get XML entity escape sequence for a character.
inline fn xmlEscape(c: u8) ?[]const u8 {
    return switch (c) {
        '&' => "&amp;",
        '<' => "&lt;",
        '>' => "&gt;",
        '"' => "&quot;",
        '\'' => "&apos;",
        else => null,
    };
}

/// Get JSON escape sequence for a character.
inline fn jsonEscape(c: u8) ?[]const u8 {
    return switch (c) {
        '"' => "\\\"",
        '\\' => "\\\\",
        0x08 => "\\b",
        0x0C => "\\f",
        '\n' => "\\n",
        '\r' => "\\r",
        '\t' => "\\t",
        else => null,
    };
}

// ============================================================================
// UTF-16LE to UTF-8 Allocation (for name caching)
// ============================================================================

/// Convert UTF-16LE bytes to UTF-8, allocating the result.
///
/// This is used for pre-converting element/attribute names at parse time.
/// Names are cached as UTF-8 and written directly during rendering.
///
/// Uses the shared `asciiConvertFastPath` - see its documentation for why
/// we don't use stdlib directly (alignment issues with unaligned EVTX data).
pub fn convertUtf16ToUtf8(allocator: std.mem.Allocator, utf16le: []const u8, num_chars: usize) ![]u8 {
    const max_bytes = @min(num_chars * 2, utf16le.len);
    if (max_bytes < 2) {
        return allocator.alloc(u8, 0);
    }

    // Use stack buffer for conversion (names are typically short)
    // Worst case: each UTF-16 code unit becomes 3 UTF-8 bytes
    var stack_buf: [512]u8 = undefined;

    // Phase 1: ASCII Fast Path (shared implementation, no escaping)
    const fast = asciiConvertFastPath(utf16le[0..max_bytes], &stack_buf, .none);
    var out_len = fast.out_written;
    const byte_pos = fast.in_consumed;

    // Phase 2: Iterator Fallback for non-ASCII bytes
    if (byte_pos < max_bytes) {
        var it: std.unicode.Wtf16LeIterator = .{
            .bytes = utf16le[byte_pos..max_bytes],
            .i = 0,
        };

        while (it.nextCodepoint()) |codepoint| {
            if (std.unicode.isSurrogateCodepoint(codepoint)) continue;
            const len = std.unicode.utf8Encode(codepoint, stack_buf[out_len..][0..4]) catch continue;
            out_len += len;
        }
    }

    // Allocate exact size and copy
    const result = try allocator.alloc(u8, out_len);
    @memcpy(result, stack_buf[0..out_len]);
    return result;
}

// ============================================================================
// CP-1252 (Windows ANSI) Encoding
// ============================================================================

/// Convert a CP-1252 byte to Unicode codepoint.
///
/// CP-1252 is a superset of ISO-8859-1 with extra characters in 0x80-0x9F.
pub fn cp1252ToCodepoint(b: u8) u21 {
    if (b < 0x80) return b;
    if (b >= 0xA0) return b;
    return switch (b) {
        0x80 => 0x20AC, // Euro sign
        0x82 => 0x201A, // Single low-9 quotation mark
        0x83 => 0x0192, // Latin small f with hook
        0x84 => 0x201E, // Double low-9 quotation mark
        0x85 => 0x2026, // Horizontal ellipsis
        0x86 => 0x2020, // Dagger
        0x87 => 0x2021, // Double dagger
        0x88 => 0x02C6, // Modifier letter circumflex accent
        0x89 => 0x2030, // Per mille sign
        0x8A => 0x0160, // Latin capital S with caron
        0x8B => 0x2039, // Single left-pointing angle quotation
        0x8C => 0x0152, // Latin capital ligature OE
        0x8E => 0x017D, // Latin capital Z with caron
        0x91 => 0x2018, // Left single quotation mark
        0x92 => 0x2019, // Right single quotation mark
        0x93 => 0x201C, // Left double quotation mark
        0x94 => 0x201D, // Right double quotation mark
        0x95 => 0x2022, // Bullet
        0x96 => 0x2013, // En dash
        0x97 => 0x2014, // Em dash
        0x98 => 0x02DC, // Small tilde
        0x99 => 0x2122, // Trade mark sign
        0x9A => 0x0161, // Latin small s with caron
        0x9B => 0x203A, // Single right-pointing angle quotation
        0x9C => 0x0153, // Latin small ligature oe
        0x9E => 0x017E, // Latin small z with caron
        0x9F => 0x0178, // Latin capital Y with diaeresis
        else => 0xFFFD, // Replacement character for undefined
    };
}

/// Write CP-1252 (ANSI) bytes as XML-escaped UTF-8.
pub fn writeAnsiCp1252Escaped(w: *std.Io.Writer, bytes: []const u8) WriterError!void {
    var utf8_buf: [4]u8 = undefined;
    for (bytes) |b| {
        const codepoint = cp1252ToCodepoint(b);
        const len = std.unicode.utf8Encode(codepoint, &utf8_buf) catch continue;

        // Apply XML escaping to each UTF-8 byte
        for (utf8_buf[0..len]) |c| {
            if (xmlEscape(c)) |esc| {
                try w.writeAll(esc);
            } else {
                try w.writeByte(c);
            }
        }
    }
}

// ============================================================================
// String Comparison Utilities
// ============================================================================

/// Check if UTF-16LE bytes equal an ASCII string.
///
/// This is useful for checking element/attribute names against known strings
/// without allocating or converting the entire UTF-16 string.
pub fn utf16EqualsAscii(utf16le: []const u8, num_chars: usize, ascii: []const u8) bool {
    if (ascii.len != num_chars) return false;
    for (ascii, 0..) |c, i| {
        const lo = utf16le[i * 2];
        const hi = utf16le[i * 2 + 1];
        if (hi != 0 or lo != c) return false;
    }
    return true;
}

// ============================================================================
// Tests
// ============================================================================

/// Convert ASCII string to UTF-16LE bytes (test helper)
fn asciiToUtf16(buf: []u8, ascii: []const u8) []u8 {
    for (ascii, 0..) |c, i| {
        buf[i * 2] = c;
        buf[i * 2 + 1] = 0;
    }
    return buf[0 .. ascii.len * 2];
}

// ----------------------------------------------------------------------------
// XML Escaping Tests
// ----------------------------------------------------------------------------

test "XML escape: ampersand" {
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = asciiToUtf16(&buf, "a&b");
    try writeUtf16LeXmlEscaped(&w, input, 3);
    try std.testing.expectEqualStrings("a&amp;b", w.buffer[0..w.end]);
}

test "XML escape: less than" {
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = asciiToUtf16(&buf, "a<b");
    try writeUtf16LeXmlEscaped(&w, input, 3);
    try std.testing.expectEqualStrings("a&lt;b", w.buffer[0..w.end]);
}

test "XML escape: greater than" {
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = asciiToUtf16(&buf, "a>b");
    try writeUtf16LeXmlEscaped(&w, input, 3);
    try std.testing.expectEqualStrings("a&gt;b", w.buffer[0..w.end]);
}

test "XML escape: double quote" {
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = asciiToUtf16(&buf, "a\"b");
    try writeUtf16LeXmlEscaped(&w, input, 3);
    try std.testing.expectEqualStrings("a&quot;b", w.buffer[0..w.end]);
}

test "XML escape: single quote" {
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = asciiToUtf16(&buf, "a'b");
    try writeUtf16LeXmlEscaped(&w, input, 3);
    try std.testing.expectEqualStrings("a&apos;b", w.buffer[0..w.end]);
}

test "XML escape: all entities" {
    var buf: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = asciiToUtf16(&buf, "&<>\"'");
    try writeUtf16LeXmlEscaped(&w, input, 5);
    try std.testing.expectEqualStrings("&amp;&lt;&gt;&quot;&apos;", w.buffer[0..w.end]);
}

test "XML escape: plain ASCII passthrough" {
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = asciiToUtf16(&buf, "Hello World 123");
    try writeUtf16LeXmlEscaped(&w, input, 15);
    try std.testing.expectEqualStrings("Hello World 123", w.buffer[0..w.end]);
}

test "XML escape: 2-byte UTF-8 passthrough (e-acute)" {
    // U+00E9 (é) = UTF-16LE: 0xE9, 0x00 → UTF-8: 0xC3 0xA9
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 0xE9, 0x00 };
    try writeUtf16LeXmlEscaped(&w, &input, 1);
    try std.testing.expectEqualStrings("\xC3\xA9", w.buffer[0..w.end]);
}

test "XML escape: 3-byte UTF-8 passthrough (euro)" {
    // U+20AC (€) = UTF-16LE: 0xAC, 0x20 → UTF-8: 0xE2 0x82 0xAC
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 0xAC, 0x20 };
    try writeUtf16LeXmlEscaped(&w, &input, 1);
    try std.testing.expectEqualStrings("\xE2\x82\xAC", w.buffer[0..w.end]);
}

test "XML escape: 4-byte UTF-8 passthrough (grinning face)" {
    // U+1F600 (😀) = UTF-16LE surrogate pair: 0xD83D 0xDE00
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 0x3D, 0xD8, 0x00, 0xDE };
    try writeUtf16LeXmlEscaped(&w, &input, 2);
    try std.testing.expectEqualStrings("\xF0\x9F\x98\x80", w.buffer[0..w.end]);
}

// ----------------------------------------------------------------------------
// JSON Escaping Tests
// ----------------------------------------------------------------------------

test "JSON escape: double quote" {
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = asciiToUtf16(&buf, "a\"b");
    try writeUtf16LeJsonEscaped(&w, input, 3);
    try std.testing.expectEqualStrings("a\\\"b", w.buffer[0..w.end]);
}

test "JSON escape: backslash" {
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = asciiToUtf16(&buf, "a\\b");
    try writeUtf16LeJsonEscaped(&w, input, 3);
    try std.testing.expectEqualStrings("a\\\\b", w.buffer[0..w.end]);
}

test "JSON escape: backspace" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 'a', 0, 0x08, 0, 'b', 0 };
    try writeUtf16LeJsonEscaped(&w, &input, 3);
    try std.testing.expectEqualStrings("a\\bb", w.buffer[0..w.end]);
}

test "JSON escape: form feed" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 'a', 0, 0x0C, 0, 'b', 0 };
    try writeUtf16LeJsonEscaped(&w, &input, 3);
    try std.testing.expectEqualStrings("a\\fb", w.buffer[0..w.end]);
}

test "JSON escape: newline" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 'a', 0, '\n', 0, 'b', 0 };
    try writeUtf16LeJsonEscaped(&w, &input, 3);
    try std.testing.expectEqualStrings("a\\nb", w.buffer[0..w.end]);
}

test "JSON escape: carriage return" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 'a', 0, '\r', 0, 'b', 0 };
    try writeUtf16LeJsonEscaped(&w, &input, 3);
    try std.testing.expectEqualStrings("a\\rb", w.buffer[0..w.end]);
}

test "JSON escape: tab" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 'a', 0, '\t', 0, 'b', 0 };
    try writeUtf16LeJsonEscaped(&w, &input, 3);
    try std.testing.expectEqualStrings("a\\tb", w.buffer[0..w.end]);
}

test "JSON escape: control char as unicode escape" {
    // 0x1F (unit separator) has no named escape, becomes \u001F
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 'a', 0, 0x1F, 0, 'b', 0 };
    try writeUtf16LeJsonEscaped(&w, &input, 3);
    try std.testing.expectEqualStrings("a\\u001Fb", w.buffer[0..w.end]);
}

test "JSON escape: null char as unicode escape" {
    // 0x00 (null) becomes \u0000
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 'a', 0, 0x00, 0, 'b', 0 };
    try writeUtf16LeJsonEscaped(&w, &input, 3);
    try std.testing.expectEqualStrings("a\\u0000b", w.buffer[0..w.end]);
}

test "JSON escape: plain ASCII passthrough" {
    var buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = asciiToUtf16(&buf, "Hello World 123");
    try writeUtf16LeJsonEscaped(&w, input, 15);
    try std.testing.expectEqualStrings("Hello World 123", w.buffer[0..w.end]);
}

// ----------------------------------------------------------------------------
// CP-1252 (ANSI) Tests
// ----------------------------------------------------------------------------

test "CP-1252: euro sign (0x80)" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try writeAnsiCp1252Escaped(&w, &[_]u8{0x80});
    try std.testing.expectEqualStrings("\xE2\x82\xAC", w.buffer[0..w.end]); // U+20AC in UTF-8
}

test "CP-1252: left double quotation mark (0x93)" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try writeAnsiCp1252Escaped(&w, &[_]u8{0x93});
    try std.testing.expectEqualStrings("\xE2\x80\x9C", w.buffer[0..w.end]); // U+201C in UTF-8
}

test "CP-1252: em dash (0x97)" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try writeAnsiCp1252Escaped(&w, &[_]u8{0x97});
    try std.testing.expectEqualStrings("\xE2\x80\x94", w.buffer[0..w.end]); // U+2014 in UTF-8
}

test "CP-1252: trademark (0x99)" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try writeAnsiCp1252Escaped(&w, &[_]u8{0x99});
    try std.testing.expectEqualStrings("\xE2\x84\xA2", w.buffer[0..w.end]); // U+2122 in UTF-8
}

test "CP-1252: undefined byte (0x81) becomes replacement char" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try writeAnsiCp1252Escaped(&w, &[_]u8{0x81});
    try std.testing.expectEqualStrings("\xEF\xBF\xBD", w.buffer[0..w.end]); // U+FFFD in UTF-8
}

test "CP-1252: ASCII passthrough" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try writeAnsiCp1252Escaped(&w, "Hello");
    try std.testing.expectEqualStrings("Hello", w.buffer[0..w.end]);
}

test "CP-1252: high Latin-1 passthrough (0xA0+)" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    // 0xE9 is é in both CP-1252 and Latin-1
    try writeAnsiCp1252Escaped(&w, &[_]u8{0xE9});
    try std.testing.expectEqualStrings("\xC3\xA9", w.buffer[0..w.end]); // U+00E9 in UTF-8
}

test "CP-1252: XML escaping applied" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try writeAnsiCp1252Escaped(&w, "a&b");
    try std.testing.expectEqualStrings("a&amp;b", w.buffer[0..w.end]);
}

// ----------------------------------------------------------------------------
// utf16EqualsAscii Tests
// ----------------------------------------------------------------------------

test "utf16EqualsAscii: exact match" {
    var buf: [64]u8 = undefined;
    const utf16 = asciiToUtf16(&buf, "Hello");
    try std.testing.expect(utf16EqualsAscii(utf16, 5, "Hello"));
}

test "utf16EqualsAscii: different content" {
    var buf: [64]u8 = undefined;
    const utf16 = asciiToUtf16(&buf, "Hello");
    try std.testing.expect(!utf16EqualsAscii(utf16, 5, "World"));
}

test "utf16EqualsAscii: different length" {
    var buf: [64]u8 = undefined;
    const utf16 = asciiToUtf16(&buf, "Hello");
    try std.testing.expect(!utf16EqualsAscii(utf16, 5, "Hell"));
    try std.testing.expect(!utf16EqualsAscii(utf16, 5, "Hello!"));
}

test "utf16EqualsAscii: empty strings" {
    const utf16 = [_]u8{};
    try std.testing.expect(utf16EqualsAscii(&utf16, 0, ""));
}

test "utf16EqualsAscii: non-BMP UTF-16 with high byte set" {
    // U+20AC (€) = UTF-16LE: 0xAC, 0x20 - high byte is 0x20, not 0
    const utf16 = [_]u8{ 0xAC, 0x20 };
    // Cannot match any single ASCII byte since high byte != 0
    try std.testing.expect(!utf16EqualsAscii(&utf16, 1, "\xAC"));
}

// ----------------------------------------------------------------------------
// convertUtf16ToUtf8 Tests
// ----------------------------------------------------------------------------

test "convertUtf16ToUtf8: pure ASCII" {
    var buf: [64]u8 = undefined;
    const utf16 = asciiToUtf16(&buf, "Hello");
    const utf8 = try convertUtf16ToUtf8(std.testing.allocator, utf16, 5);
    defer std.testing.allocator.free(utf8);
    try std.testing.expectEqualStrings("Hello", utf8);
}

test "convertUtf16ToUtf8: empty string" {
    const utf8 = try convertUtf16ToUtf8(std.testing.allocator, &[_]u8{}, 0);
    defer std.testing.allocator.free(utf8);
    try std.testing.expectEqualStrings("", utf8);
}

test "convertUtf16ToUtf8: 2-byte UTF-8 (e-acute)" {
    // U+00E9 (é) = UTF-16LE: 0xE9, 0x00 → UTF-8: 0xC3 0xA9
    const input = [_]u8{ 0xE9, 0x00 };
    const utf8 = try convertUtf16ToUtf8(std.testing.allocator, &input, 1);
    defer std.testing.allocator.free(utf8);
    try std.testing.expectEqualStrings("\xC3\xA9", utf8);
}

test "convertUtf16ToUtf8: 3-byte UTF-8 (euro)" {
    // U+20AC (€) = UTF-16LE: 0xAC, 0x20 → UTF-8: 0xE2 0x82 0xAC
    const input = [_]u8{ 0xAC, 0x20 };
    const utf8 = try convertUtf16ToUtf8(std.testing.allocator, &input, 1);
    defer std.testing.allocator.free(utf8);
    try std.testing.expectEqualStrings("\xE2\x82\xAC", utf8);
}

test "convertUtf16ToUtf8: surrogate pair (grinning face)" {
    // U+1F600 (😀) = UTF-16LE surrogate pair: 0xD83D 0xDE00 → UTF-8: 0xF0 0x9F 0x98 0x80
    const input = [_]u8{ 0x3D, 0xD8, 0x00, 0xDE };
    const utf8 = try convertUtf16ToUtf8(std.testing.allocator, &input, 2);
    defer std.testing.allocator.free(utf8);
    try std.testing.expectEqualStrings("\xF0\x9F\x98\x80", utf8);
}

test "convertUtf16ToUtf8: mixed ASCII and non-ASCII" {
    // "Hé" = H (0x48, 0x00) + é (0xE9, 0x00)
    const input = [_]u8{ 0x48, 0x00, 0xE9, 0x00 };
    const utf8 = try convertUtf16ToUtf8(std.testing.allocator, &input, 2);
    defer std.testing.allocator.free(utf8);
    try std.testing.expectEqualStrings("H\xC3\xA9", utf8);
}

// ----------------------------------------------------------------------------
// Edge Case Tests
// ----------------------------------------------------------------------------

test "empty input produces no output" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try writeUtf16LeXmlEscaped(&w, &[_]u8{}, 0);
    try std.testing.expectEqual(@as(usize, 0), w.end);
}

test "single character" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 'X', 0 };
    try writeUtf16LeXmlEscaped(&w, &input, 1);
    try std.testing.expectEqualStrings("X", w.buffer[0..w.end]);
}

test "lone high surrogate produces no output" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 0x00, 0xD8 }; // 0xD800 high surrogate
    try writeUtf16LeXmlEscaped(&w, &input, 1);
    try std.testing.expectEqual(@as(usize, 0), w.end);
}

test "lone low surrogate produces no output" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const input = [_]u8{ 0x00, 0xDC }; // 0xDC00 low surrogate
    try writeUtf16LeXmlEscaped(&w, &input, 1);
    try std.testing.expectEqual(@as(usize, 0), w.end);
}
