//! Common utilities for BinXML parsing.
//!
//! This module provides offset calculation functions for template parsing.
//! Uses deterministic offset calculations based on format structure rather
//! than heuristic pattern matching.

const std = @import("std");
const types = @import("types.zig");
const tokens = @import("tokens.zig");

/// Calculates where substitution values start within a template instance.
///
/// Template instances have this structure:
/// - TemplateInstanceStart header (10 bytes)
/// - Inline template definitions (if def_data_off == position after header)
/// - Substitution values
///
/// If the template definition is inline, we follow the chain of definitions
/// (via next_offset) to find where substitution values begin.
///
/// Returns the chunk offset where substitution values start.
pub fn calcValuesOffset(chunk: []const u8, after_header: usize, def_data_off: u32) usize {
    // If definition is NOT inline (stored elsewhere in chunk), values start immediately
    if (def_data_off != after_header) return after_header;

    // Definition is inline - skip past it (and any chained definitions)
    var offset = after_header;
    while (offset + @sizeOf(types.TemplateDefinitionHeader) <= chunk.len) {
        const hdr = readTemplateDefHeader(chunk, offset);
        const data_end = offset + 24 + hdr.data_size;

        if (data_end > chunk.len) break;
        offset = data_end;

        // next_offset == 0 means no more chained definitions
        // next_offset pointing elsewhere means we're done with inline defs
        if (hdr.next_offset == 0 or hdr.next_offset != offset) break;
    }

    return offset;
}

/// Reads a TemplateDefinitionHeader from chunk at given offset.
fn readTemplateDefHeader(chunk: []const u8, offset: usize) types.TemplateDefinitionHeader {
    const slice = chunk[offset..][0..@sizeOf(types.TemplateDefinitionHeader)];
    return std.mem.bytesToValue(types.TemplateDefinitionHeader, slice);
}

/// Returns offset after fragment header, or same offset if no fragment header present.
pub fn skipFragmentHeader(chunk: []const u8, offset: usize) usize {
    if (offset + 4 <= chunk.len and chunk[offset] == tokens.TOK_FRAGMENT_HEADER) {
        return offset + @sizeOf(types.FragmentHeader);
    }
    return offset;
}

/// Reads the data_size field from a TemplateDefinitionHeader at the given offset.
pub fn readTemplateDefSize(chunk: []const u8, def_data_off: u32) u32 {
    const off: usize = @intCast(def_data_off);
    // data_size is at offset 20 within the 24-byte header
    const size_slice = chunk[off + 20 .. off + 24];
    return std.mem.readInt(u32, size_slice[0..4], .little);
}
