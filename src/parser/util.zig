//! String encoding and datetime utilities for BinXML output rendering.
//!
//! This module re-exports functionality from specialized submodules:
//! - util_string: UTF-16LE/CP-1252 conversion with XML/JSON escaping
//! - util_datetime: FILETIME/SystemTime formatting
//! - util_simd: SIMD-accelerated implementations

const string = @import("util_string.zig");
const datetime = @import("util_datetime.zig");

// ============================================================================
// String Encoding (from util_string.zig)
// ============================================================================

/// Writer error type for output functions.
pub const WriterError = string.WriterError;

/// Write UTF-16LE input as XML-escaped UTF-8.
pub const writeUtf16LeXmlEscaped = string.writeUtf16LeXmlEscaped;

/// Write UTF-16LE input as JSON-escaped UTF-8.
pub const writeUtf16LeJsonEscaped = string.writeUtf16LeJsonEscaped;

/// Write UTF-16LE input as raw UTF-8 (no escaping).
pub const writeUtf16LeRawToUtf8 = string.writeUtf16LeRawToUtf8;

/// Write CP-1252 (ANSI) bytes as XML-escaped UTF-8.
pub const writeAnsiCp1252Escaped = string.writeAnsiCp1252Escaped;

/// Check if UTF-16LE bytes equal an ASCII string.
pub const utf16EqualsAscii = string.utf16EqualsAscii;

/// Convert a CP-1252 byte to Unicode codepoint.
pub const cp1252ToCodepoint = string.cp1252ToCodepoint;

// Scalar versions for benchmarking
pub const writeUtf16LeXmlEscaped_scalar = string.writeUtf16LeXmlEscaped_scalar;
pub const writeUtf16LeJsonEscaped_scalar = string.writeUtf16LeJsonEscaped_scalar;

// SIMD versions for benchmarking
pub const writeUtf16LeXmlEscaped_simd_utf16 = string.writeUtf16LeXmlEscaped_simd_utf16;
pub const writeUtf16LeJsonEscaped_simd = string.writeUtf16LeJsonEscaped_simd;

// ============================================================================
// DateTime Formatting (from util_datetime.zig)
// ============================================================================

/// Format a Windows FILETIME value as ISO8601 UTC string.
pub const formatIso8601UtcFromFiletimeMicros = datetime.formatIso8601UtcFromFiletimeMicros;
