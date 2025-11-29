//! SIMD-accelerated UTF-16LE to UTF-8 conversion with XML/JSON escaping.
//!
//! This module provides vectorized string conversion for the BinXML parser.
//! It processes 8 UTF-16 code units per iteration using 128-bit SIMD vectors.
//!
//! ## Algorithm Overview
//!
//! The SIMD approach works in two phases per 8-unit block:
//!
//! 1. **Classification Phase** (vectorized): Analyze all 8 code units in parallel
//!    to determine their type (ASCII, escape char, 2/3/4-byte UTF-8, surrogate).
//!
//! 2. **Emission Phase** (scalar): Walk through the 8 units using the classification
//!    masks to emit the correct UTF-8 bytes. This is scalar because output lengths
//!    vary per character.
//!
//! ## Why SIMD for Classification Only?
//!
//! Full SIMD UTF-8 encoding is complex because characters produce 1-4 bytes,
//! making output positions data-dependent. The classification-only approach
//! still wins because:
//! - Range checks parallelize well (8 comparisons → 1 vector op)
//! - The scalar emission loop has perfect branch prediction from masks
//! - Memory bandwidth is the bottleneck anyway for large strings
//!
//! ## UTF-16 Surrogate Pair Handling
//!
//! Characters outside the BMP (U+10000+) are encoded as surrogate pairs:
//! - High surrogate: 0xD800-0xDBFF (first code unit)
//! - Low surrogate:  0xDC00-0xDFFF (second code unit)
//!
//! When a high surrogate appears at position 7 (last in block), its low
//! surrogate is in the next block. We handle this by reading ahead.

const std = @import("std");

/// Writer error type (same as util.zig).
pub const WriterError = std.Io.Writer.Error;

// ============================================================================
// Type Aliases for Readability
// ============================================================================

/// 8-lane vector of UTF-16 code units (128 bits total).
const Vec8u16 = @Vector(8, u16);

/// 8-lane boolean mask for classification results.
const Mask8 = @Vector(8, bool);

/// 8-lane bit mask (for boolean operations that need bitwise ops).
const Bits8 = @Vector(8, u1);

// ============================================================================
// Vector Helper Functions
// ============================================================================

/// Create a splat vector (all lanes same value).
inline fn splat(val: u16) Vec8u16 {
    return @splat(val);
}

/// Convert bool mask to bit mask for bitwise operations.
inline fn toBits(mask: Mask8) Bits8 {
    return @bitCast(mask);
}

/// Convert bit mask back to bool mask.
inline fn toBool(bits: Bits8) Mask8 {
    return @bitCast(bits);
}

/// Bitwise AND of two bool masks.
inline fn maskAnd(a: Mask8, b: Mask8) Mask8 {
    return toBool(toBits(a) & toBits(b));
}

/// Bitwise OR of two bool masks.
inline fn maskOr(a: Mask8, b: Mask8) Mask8 {
    return toBool(toBits(a) | toBits(b));
}

/// Bitwise NOT of a bool mask.
inline fn maskNot(m: Mask8) Mask8 {
    return toBool(~toBits(m));
}

// ============================================================================
// Classification Results
// ============================================================================

/// Results of classifying 8 UTF-16 code units for XML escaping.
/// Each mask has one bool per lane indicating if that classification applies.
const XmlClassification = struct {
    /// Lane is ASCII (0x00-0x7F) - outputs 1 byte
    is_ascii: Mask8,
    /// Lane is ASCII AND needs XML escaping (& < > " ')
    needs_escape: Mask8,
    /// Lane needs 2-byte UTF-8 encoding (0x80-0x7FF, non-surrogate)
    is_two_byte: Mask8,
    /// Lane needs 3-byte UTF-8 encoding (0x800-0xFFFF, non-surrogate)
    is_three_byte: Mask8,
    /// Lane is a high surrogate (0xD800-0xDBFF) - starts a pair
    is_high_surrogate: Mask8,
    /// Lane is a low surrogate (0xDC00-0xDFFF) - ends a pair
    is_low_surrogate: Mask8,
};

/// Results of classifying 8 UTF-16 code units for JSON escaping.
const JsonClassification = struct {
    /// Lane is ASCII (0x00-0x7F) - outputs 1 byte
    is_ascii: Mask8,
    /// Lane is control char (0x00-0x1F) - needs \uXXXX encoding
    is_control: Mask8,
    /// Lane needs special JSON escape: " \ \b \f \n \r \t
    needs_special_escape: Mask8,
    /// Lane needs 2-byte UTF-8 encoding (0x80-0x7FF, non-surrogate)
    is_two_byte: Mask8,
    /// Lane needs 3-byte UTF-8 encoding (0x800-0xFFFF, non-surrogate)
    is_three_byte: Mask8,
    /// Lane is a high surrogate (0xD800-0xDBFF) - starts a pair
    is_high_surrogate: Mask8,
    /// Lane is a low surrogate (0xDC00-0xDFFF) - ends a pair
    is_low_surrogate: Mask8,
};

/// Classify 8 UTF-16 code units for XML escaping.
fn classifyXml(v: Vec8u16) XmlClassification {
    // === ASCII Detection ===
    const is_ascii = v <= splat(0x7F);

    // === XML Escape Detection ===
    // Check for each escapable character: & (38), < (60), > (62), " (34), ' (39)
    const is_amp = v == splat('&');
    const is_lt = v == splat('<');
    const is_gt = v == splat('>');
    const is_quot = v == splat('"');
    const is_apos = v == splat('\'');

    // Combine all escape checks: needs_escape = is_ascii AND (any escape char)
    const any_escape = maskOr(maskOr(maskOr(maskOr(is_amp, is_lt), is_gt), is_quot), is_apos);
    const needs_escape = maskAnd(is_ascii, any_escape);

    // === Surrogate Detection ===
    // High surrogate range: 0xD800-0xDBFF
    const is_high_surrogate = maskAnd(v >= splat(0xD800), v <= splat(0xDBFF));
    // Low surrogate range: 0xDC00-0xDFFF
    const is_low_surrogate = maskAnd(v >= splat(0xDC00), v <= splat(0xDFFF));
    // Not a surrogate (needed for 2/3 byte classification)
    const not_surrogate = maskAnd(maskNot(is_high_surrogate), maskNot(is_low_surrogate));

    // === UTF-8 Length Classification ===
    // 2-byte: 0x80-0x7FF (non-ASCII, non-surrogate, <= 0x7FF)
    const gt_7f = v > splat(0x7F);
    const le_7ff = v <= splat(0x7FF);
    const is_two_byte = maskAnd(maskAnd(not_surrogate, gt_7f), le_7ff);

    // 3-byte: 0x800-0xFFFF (non-ASCII, non-2-byte, non-surrogate)
    const is_three_byte = maskAnd(maskAnd(not_surrogate, maskNot(is_ascii)), maskNot(is_two_byte));

    return .{
        .is_ascii = is_ascii,
        .needs_escape = needs_escape,
        .is_two_byte = is_two_byte,
        .is_three_byte = is_three_byte,
        .is_high_surrogate = is_high_surrogate,
        .is_low_surrogate = is_low_surrogate,
    };
}

/// Classify 8 UTF-16 code units for JSON escaping.
fn classifyJson(v: Vec8u16) JsonClassification {
    // === ASCII Detection ===
    const is_ascii = v <= splat(0x7F);

    // === Control Character Detection (0x00-0x1F) ===
    const is_control = v < splat(0x20);

    // === JSON Special Escape Detection ===
    // Characters with named escapes: " \ \b \f \n \r \t
    const is_quot = v == splat('"');
    const is_backslash = v == splat('\\');
    const is_backspace = v == splat(0x08); // \b
    const is_formfeed = v == splat(0x0C); // \f
    const is_newline = v == splat('\n'); // \n
    const is_carriage = v == splat('\r'); // \r
    const is_tab = v == splat('\t'); // \t

    // Combine special escapes (these get named sequences like \n instead of \u000A)
    const any_special = maskOr(maskOr(maskOr(maskOr(maskOr(maskOr(is_quot, is_backslash), is_backspace), is_formfeed), is_newline), is_carriage), is_tab);
    const needs_special_escape = maskAnd(is_ascii, any_special);

    // === Surrogate Detection ===
    const is_high_surrogate = maskAnd(v >= splat(0xD800), v <= splat(0xDBFF));
    const is_low_surrogate = maskAnd(v >= splat(0xDC00), v <= splat(0xDFFF));
    const not_surrogate = maskAnd(maskNot(is_high_surrogate), maskNot(is_low_surrogate));

    // === UTF-8 Length Classification ===
    const gt_7f = v > splat(0x7F);
    const le_7ff = v <= splat(0x7FF);
    const is_two_byte = maskAnd(maskAnd(not_surrogate, gt_7f), le_7ff);
    const is_three_byte = maskAnd(maskAnd(not_surrogate, maskNot(is_ascii)), maskNot(is_two_byte));

    return .{
        .is_ascii = is_ascii,
        .is_control = is_control,
        .needs_special_escape = needs_special_escape,
        .is_two_byte = is_two_byte,
        .is_three_byte = is_three_byte,
        .is_high_surrogate = is_high_surrogate,
        .is_low_surrogate = is_low_surrogate,
    };
}

// ============================================================================
// UTF-8 Encoding Helpers
// ============================================================================

/// Encode a BMP codepoint (U+0080-U+07FF) as 2-byte UTF-8.
inline fn encode2Byte(cp: u16) [2]u8 {
    return .{
        0xC0 | @as(u8, @truncate(cp >> 6)),
        0x80 | @as(u8, @truncate(cp & 0x3F)),
    };
}

/// Encode a BMP codepoint (U+0800-U+FFFF) as 3-byte UTF-8.
inline fn encode3Byte(cp: u16) [3]u8 {
    return .{
        0xE0 | @as(u8, @truncate(cp >> 12)),
        0x80 | @as(u8, @truncate((cp >> 6) & 0x3F)),
        0x80 | @as(u8, @truncate(cp & 0x3F)),
    };
}

/// Encode a supplementary codepoint (U+10000+) as 4-byte UTF-8.
inline fn encode4Byte(cp: u21) [4]u8 {
    return .{
        0xF0 | @as(u8, @truncate(cp >> 18)),
        0x80 | @as(u8, @truncate((cp >> 12) & 0x3F)),
        0x80 | @as(u8, @truncate((cp >> 6) & 0x3F)),
        0x80 | @as(u8, @truncate(cp & 0x3F)),
    };
}

/// Decode a surrogate pair into a codepoint.
inline fn decodeSurrogatePair(high: u16, low: u16) u21 {
    const high_ten: u21 = high - 0xD800;
    const low_ten: u21 = low - 0xDC00;
    return 0x10000 + (high_ten << 10) + low_ten;
}

// ============================================================================
// XML Escape Lookup
// ============================================================================

/// Get XML entity for an ASCII character, or null if no escaping needed.
inline fn xmlEntity(c: u8) ?[]const u8 {
    return switch (c) {
        '&' => "&amp;",
        '<' => "&lt;",
        '>' => "&gt;",
        '"' => "&quot;",
        '\'' => "&apos;",
        else => null,
    };
}

/// Get JSON escape sequence for an ASCII character, or null if no escaping needed.
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

/// Write a \uXXXX escape for a control character.
inline fn writeJsonUnicodeEscape(out: *OutputBuffer, c: u8) WriterError!void {
    const hex = "0123456789ABCDEF";
    try out.writeArray(6, .{
        '\\',
        'u',
        '0',
        '0',
        hex[@as(usize, c >> 4)],
        hex[@as(usize, c & 0xF)],
    });
}

// ============================================================================
// Output Buffer Management
// ============================================================================

/// Buffered output writer to reduce syscall overhead.
const OutputBuffer = struct {
    buf: [2048]u8 = undefined,
    len: usize = 0,
    writer: *std.Io.Writer,

    /// Ensure we have room for `needed` bytes, flushing if necessary.
    fn ensureRoom(self: *OutputBuffer, needed: usize) WriterError!void {
        if (self.len + needed > self.buf.len) {
            try self.flush();
        }
    }

    /// Write a single byte.
    fn writeByte(self: *OutputBuffer, b: u8) WriterError!void {
        try self.ensureRoom(1);
        self.buf[self.len] = b;
        self.len += 1;
    }

    /// Write a slice of bytes.
    fn writeSlice(self: *OutputBuffer, bytes: []const u8) WriterError!void {
        try self.ensureRoom(bytes.len);
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    /// Write a fixed-size array.
    fn writeArray(self: *OutputBuffer, comptime N: usize, arr: [N]u8) WriterError!void {
        try self.ensureRoom(N);
        @memcpy(self.buf[self.len..][0..N], &arr);
        self.len += N;
    }

    /// Flush buffered output to the underlying writer.
    fn flush(self: *OutputBuffer) WriterError!void {
        if (self.len > 0) {
            try self.writer.writeAll(self.buf[0..self.len]);
            self.len = 0;
        }
    }
};

// ============================================================================
// Main SIMD Function
// ============================================================================

/// SIMD-accelerated UTF-16LE to XML-escaped UTF-8 conversion.
///
/// Processes 8 UTF-16 code units per iteration. For inputs smaller than
/// 16 code units, the caller should use the scalar version instead.
///
/// ## Parameters
/// - `w`: Output writer
/// - `utf16le`: Input bytes (little-endian UTF-16)
/// - `num_chars`: Number of UTF-16 code units (not bytes!)
pub fn writeUtf16LeXmlEscaped_simd(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    const max_chars: usize = @min(num_chars, utf16le.len / 2);
    if (max_chars == 0) return;

    var out = OutputBuffer{ .writer = w };
    var char_idx: usize = 0; // Current UTF-16 code unit index
    var byte_pos: usize = 0; // Current byte position in utf16le

    // === Main SIMD Loop: Process 8 code units at a time ===
    while (char_idx + 8 <= max_chars) {
        // Load 16 bytes (8 UTF-16 code units) into a vector
        var block: [16]u8 = undefined;
        @memcpy(&block, utf16le[byte_pos..][0..16]);
        const vec: Vec8u16 = @bitCast(block);

        // Classify all 8 code units in parallel
        const class = classifyXml(vec);

        // Track extra consumption for cross-block surrogate pairs
        var extra_bytes: usize = 0;
        var extra_chars: usize = 0;

        // === Emission Loop: Process each lane using classification results ===
        var lane: usize = 0;
        while (lane < 8) : (lane += 1) {
            const code_unit = vec[lane];

            // --- Case 1: ASCII ---
            if (class.is_ascii[lane]) {
                const c: u8 = @truncate(code_unit);
                if (class.needs_escape[lane]) {
                    // XML escape required
                    try out.writeSlice(xmlEntity(c).?);
                } else {
                    // Plain ASCII byte
                    try out.writeByte(c);
                }
                continue;
            }

            // --- Case 2: 2-byte UTF-8 (U+0080 - U+07FF) ---
            if (class.is_two_byte[lane]) {
                try out.writeArray(2, encode2Byte(code_unit));
                continue;
            }

            // --- Case 3: 3-byte UTF-8 (U+0800 - U+FFFF, non-surrogate) ---
            if (class.is_three_byte[lane]) {
                try out.writeArray(3, encode3Byte(code_unit));
                continue;
            }

            // --- Case 4: High Surrogate (start of pair) ---
            if (class.is_high_surrogate[lane]) {
                // Find the low surrogate
                var low_surrogate: ?u16 = null;

                if (lane + 1 < 8) {
                    // Low surrogate is in this block
                    const next_unit = vec[lane + 1];
                    if (next_unit >= 0xDC00 and next_unit <= 0xDFFF) {
                        low_surrogate = next_unit;
                        lane += 1; // Skip the low surrogate in next iteration
                    }
                } else {
                    // Low surrogate is in the NEXT block (cross-block pair)
                    if (char_idx + 9 <= max_chars) {
                        const next_lo = utf16le[byte_pos + 16 + extra_bytes];
                        const next_hi = utf16le[byte_pos + 16 + extra_bytes + 1];
                        const next_unit: u16 = @as(u16, next_lo) | (@as(u16, next_hi) << 8);
                        if (next_unit >= 0xDC00 and next_unit <= 0xDFFF) {
                            low_surrogate = next_unit;
                            extra_bytes += 2;
                            extra_chars += 1;
                        }
                    }
                }

                if (low_surrogate) |low| {
                    // Valid surrogate pair → 4-byte UTF-8
                    const codepoint = decodeSurrogatePair(code_unit, low);
                    try out.writeArray(4, encode4Byte(codepoint));
                }
                // Invalid (lone high surrogate): skip silently
                continue;
            }

            // --- Case 5: Lone Low Surrogate ---
            // Invalid UTF-16: skip silently
        }

        byte_pos += 16 + extra_bytes;
        char_idx += 8 + extra_chars;
    }

    // Flush SIMD output
    try out.flush();

    // === Scalar Tail: Handle remaining < 8 code units ===
    if (char_idx < max_chars) {
        const string = @import("util_string.zig");
        try string.writeUtf16LeXmlEscaped_scalar(w, utf16le[byte_pos..], max_chars - char_idx);
    }
}

// ============================================================================
// JSON SIMD Function
// ============================================================================

/// SIMD-accelerated UTF-16LE to JSON-escaped UTF-8 conversion.
///
/// Similar to XML SIMD but with JSON escaping rules:
/// - " and \ get escaped as \" and \\
/// - Control chars 0x08, 0x0C, 0x0A, 0x0D, 0x09 get \b, \f, \n, \r, \t
/// - Other control chars (0x00-0x1F) get \uXXXX encoding
///
/// ## Parameters
/// - `w`: Output writer
/// - `utf16le`: Input bytes (little-endian UTF-16)
/// - `num_chars`: Number of UTF-16 code units (not bytes!)
pub fn writeUtf16LeJsonEscaped_simd(w: *std.Io.Writer, utf16le: []const u8, num_chars: usize) WriterError!void {
    const max_chars: usize = @min(num_chars, utf16le.len / 2);
    if (max_chars == 0) return;

    var out = OutputBuffer{ .writer = w };
    var char_idx: usize = 0;
    var byte_pos: usize = 0;

    // === Main SIMD Loop: Process 8 code units at a time ===
    while (char_idx + 8 <= max_chars) {
        var block: [16]u8 = undefined;
        @memcpy(&block, utf16le[byte_pos..][0..16]);
        const vec: Vec8u16 = @bitCast(block);

        const class = classifyJson(vec);

        var extra_bytes: usize = 0;
        var extra_chars: usize = 0;

        // === Emission Loop ===
        var lane: usize = 0;
        while (lane < 8) : (lane += 1) {
            const code_unit = vec[lane];

            // --- Case 1: ASCII ---
            if (class.is_ascii[lane]) {
                const c: u8 = @truncate(code_unit);

                if (class.needs_special_escape[lane]) {
                    // Named JSON escape: \", \\, \b, \f, \n, \r, \t
                    try out.writeSlice(jsonEscape(c).?);
                } else if (class.is_control[lane]) {
                    // Control char without named escape → \uXXXX
                    try writeJsonUnicodeEscape(&out, c);
                } else {
                    // Plain ASCII byte
                    try out.writeByte(c);
                }
                continue;
            }

            // --- Case 2: 2-byte UTF-8 ---
            if (class.is_two_byte[lane]) {
                try out.writeArray(2, encode2Byte(code_unit));
                continue;
            }

            // --- Case 3: 3-byte UTF-8 ---
            if (class.is_three_byte[lane]) {
                try out.writeArray(3, encode3Byte(code_unit));
                continue;
            }

            // --- Case 4: High Surrogate ---
            if (class.is_high_surrogate[lane]) {
                var low_surrogate: ?u16 = null;

                if (lane + 1 < 8) {
                    const next_unit = vec[lane + 1];
                    if (next_unit >= 0xDC00 and next_unit <= 0xDFFF) {
                        low_surrogate = next_unit;
                        lane += 1;
                    }
                } else {
                    if (char_idx + 9 <= max_chars) {
                        const next_lo = utf16le[byte_pos + 16 + extra_bytes];
                        const next_hi = utf16le[byte_pos + 16 + extra_bytes + 1];
                        const next_unit: u16 = @as(u16, next_lo) | (@as(u16, next_hi) << 8);
                        if (next_unit >= 0xDC00 and next_unit <= 0xDFFF) {
                            low_surrogate = next_unit;
                            extra_bytes += 2;
                            extra_chars += 1;
                        }
                    }
                }

                if (low_surrogate) |low| {
                    const codepoint = decodeSurrogatePair(code_unit, low);
                    try out.writeArray(4, encode4Byte(codepoint));
                }
                continue;
            }

            // --- Case 5: Lone Low Surrogate - skip ---
        }

        byte_pos += 16 + extra_bytes;
        char_idx += 8 + extra_chars;
    }

    try out.flush();

    // === Scalar Tail ===
    if (char_idx < max_chars) {
        const string = @import("util_string.zig");
        try string.writeUtf16LeJsonEscaped_scalar(w, utf16le[byte_pos..], max_chars - char_idx);
    }
}
