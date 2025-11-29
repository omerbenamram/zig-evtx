//! String encoding utilities for UTF-16LE and CP-1252 conversion.
//!
//! Provides unified UTF-16LE to UTF-8 conversion with configurable escaping
//! for XML, JSON, or raw output. Also handles Windows CP-1252 (ANSI) encoding.

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
// Unified Scalar Implementation
// ============================================================================

/// Unified UTF-16LE to UTF-8 conversion with configurable escaping.
///
/// This is the single implementation that handles all escape modes.
/// The escape mode is comptime-known, so the compiler eliminates dead branches.
fn writeUtf16LeScalar(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize, comptime mode: EscapeMode) WriterError!void {
    var out_buf: [2048]u8 = undefined;
    var out_len: usize = 0;

    const max_chars: usize = @min(num_chars, utf16le.len / 2);
    if (max_chars == 0) return;

    var i: usize = 0;
    var p: usize = 0;

    while (i < max_chars) : (i += 1) {
        const b0: u8 = utf16le[p];
        const b1: u8 = utf16le[p + 1];
        p += 2;

        const code_unit: u16 = @as(u16, b0) | (@as(u16, b1) << 8);

        // Decode UTF-16 to codepoint, handling surrogate pairs
        var codepoint: u21 = undefined;
        if (code_unit < 0xD800 or code_unit > 0xDFFF) {
            // BMP character (not a surrogate)
            codepoint = code_unit;
        } else if (code_unit >= 0xD800 and code_unit <= 0xDBFF) {
            // High surrogate - need low surrogate
            if (i + 1 >= max_chars) break;
            const lo_b0: u8 = utf16le[p];
            const lo_b1: u8 = utf16le[p + 1];
            const lo_sur: u16 = @as(u16, lo_b0) | (@as(u16, lo_b1) << 8);
            if (lo_sur < 0xDC00 or lo_sur > 0xDFFF) continue; // Invalid - skip
            p += 2;
            i += 1;
            // Decode surrogate pair
            const high_ten: u21 = code_unit - 0xD800;
            const low_ten: u21 = lo_sur - 0xDC00;
            codepoint = 0x10000 + (high_ten << 10) + low_ten;
        } else {
            // Lone low surrogate - invalid, skip
            continue;
        }

        // Encode codepoint to UTF-8 and apply escaping
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
