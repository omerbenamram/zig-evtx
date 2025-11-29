//! XML normalization for snapshot comparison.
//!
//! Handles cosmetic differences that don't affect semantic content:
//! - GUID formatting: braces and case
//! - Empty attributes (Qualifiers, ActivityID, etc.)
//! - Hex value case
//! - Whitespace in empty elements
//! - Blank lines between events

const std = @import("std");
const mvzr = @import("mvzr");

/// Replace callback function type
const ReplaceFn = *const fn (match: []const u8, allocator: std.mem.Allocator) ?[]const u8;

/// Replace all regex matches with the result of a callback function.
fn replaceAll(
    allocator: std.mem.Allocator,
    regex: *const mvzr.Regex,
    haystack: []const u8,
    replaceFn: ReplaceFn,
) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    var iter = regex.iterator(haystack);
    var last_end: usize = 0;

    while (iter.next()) |m| {
        // Append text before match
        try result.appendSlice(allocator, haystack[last_end..m.start]);

        // Append replacement
        if (replaceFn(m.slice, allocator)) |replacement| {
            defer allocator.free(replacement);
            try result.appendSlice(allocator, replacement);
        }

        last_end = m.end;
    }

    // Append remaining text
    try result.appendSlice(allocator, haystack[last_end..]);

    return result.toOwnedSlice(allocator);
}

/// Replace all regex matches with a literal string.
fn replaceAllLiteral(
    allocator: std.mem.Allocator,
    regex: *const mvzr.Regex,
    haystack: []const u8,
    replacement: []const u8,
) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    var iter = regex.iterator(haystack);
    var last_end: usize = 0;

    while (iter.next()) |m| {
        try result.appendSlice(allocator, haystack[last_end..m.start]);
        try result.appendSlice(allocator, replacement);
        last_end = m.end;
    }

    try result.appendSlice(allocator, haystack[last_end..]);
    return result.toOwnedSlice(allocator);
}

// Pre-compiled regex patterns (comptime)
const xml_prolog = mvzr.Regex.compile("<\\?xml[^?]*\\?>\\s*").?;
const empty_qualifiers = mvzr.Regex.compile(" Qualifiers=\"\"").?;
const empty_activity_id = mvzr.Regex.compile(" ActivityID=\"\"").?;
const empty_related_activity_id = mvzr.Regex.compile(" RelatedActivityID=\"\"").?;
const empty_user_id = mvzr.Regex.compile(" UserID=\"\"").?;
const guid_attr = mvzr.Regex.compile("Guid=\"\\{?[^}\"]+\\}?\"").?;
const guid_content = mvzr.Regex.compile(">\\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\}?<").?;
const hex_value = mvzr.Regex.compile("0x[0-9a-fA-F]+").?;
const multiple_newlines = mvzr.Regex.compile("\n\n+").?;
// Note: empty element collapse doesn't use regex (backreferences not supported in mvzr)

/// Normalize XML content for comparison.
/// Caller owns the returned slice and must free it with the provided allocator.
pub fn normalize(allocator: std.mem.Allocator, content: []const u8) ![]u8 {
    var s = try allocator.dupe(u8, content);
    errdefer allocator.free(s);

    // Remove XML prolog
    var next = try replaceAllLiteral(allocator, &xml_prolog, s, "");
    allocator.free(s);
    s = next;

    // Remove empty attributes
    next = try replaceAllLiteral(allocator, &empty_qualifiers, s, "");
    allocator.free(s);
    s = next;

    next = try replaceAllLiteral(allocator, &empty_activity_id, s, "");
    allocator.free(s);
    s = next;

    next = try replaceAllLiteral(allocator, &empty_related_activity_id, s, "");
    allocator.free(s);
    s = next;

    next = try replaceAllLiteral(allocator, &empty_user_id, s, "");
    allocator.free(s);
    s = next;

    // Normalize GUID in attributes
    next = try replaceAll(allocator, &guid_attr, s, normalizeGuidAttr);
    allocator.free(s);
    s = next;

    // Normalize GUID in element content
    next = try replaceAll(allocator, &guid_content, s, normalizeGuidContent);
    allocator.free(s);
    s = next;

    // Normalize hex values
    next = try replaceAll(allocator, &hex_value, s, normalizeHexValue);
    allocator.free(s);
    s = next;

    // Collapse multiple newlines
    next = try replaceAllLiteral(allocator, &multiple_newlines, s, "\n");
    allocator.free(s);
    s = next;

    // Collapse empty elements with whitespace (manual implementation - regex backrefs not supported)
    next = try collapseEmptyElements(allocator, s);
    allocator.free(s);
    s = next;

    // Trim leading/trailing whitespace
    const trimmed = std.mem.trim(u8, s, " \t\n\r");
    if (trimmed.ptr != s.ptr or trimmed.len != s.len) {
        const final = try allocator.dupe(u8, trimmed);
        allocator.free(s);
        return final;
    }

    return s;
}

fn normalizeGuidAttr(match: []const u8, allocator: std.mem.Allocator) ?[]const u8 {
    // Match is: Guid="{...}" or Guid="..."
    // Extract GUID, remove braces, uppercase
    const prefix = "Guid=\"";
    if (!std.mem.startsWith(u8, match, prefix)) return null;

    var start: usize = prefix.len;
    var end: usize = match.len - 1; // before closing quote

    // Skip optional braces
    if (start < end and match[start] == '{') start += 1;
    if (end > start and match[end - 1] == '}') end -= 1;

    const guid = match[start..end];

    // Build result: Guid="UPPERCASE"
    var result = allocator.alloc(u8, prefix.len + guid.len + 1) catch return null;
    @memcpy(result[0..prefix.len], prefix);
    for (guid, 0..) |c, i| {
        result[prefix.len + i] = std.ascii.toUpper(c);
    }
    result[result.len - 1] = '"';

    return result;
}

fn normalizeGuidContent(match: []const u8, allocator: std.mem.Allocator) ?[]const u8 {
    // Match is: >{guid}< or >guid<
    // Keep > and <, uppercase GUID, remove braces
    if (match.len < 3) return null;

    var start: usize = 1; // after >
    var end: usize = match.len - 1; // before <

    // Skip optional braces
    if (start < end and match[start] == '{') start += 1;
    if (end > start and match[end - 1] == '}') end -= 1;

    const guid = match[start..end];

    // Build result: >UPPERCASE<
    var result = allocator.alloc(u8, guid.len + 2) catch return null;
    result[0] = '>';
    for (guid, 0..) |c, i| {
        result[1 + i] = std.ascii.toUpper(c);
    }
    result[result.len - 1] = '<';

    return result;
}

fn normalizeHexValue(match: []const u8, allocator: std.mem.Allocator) ?[]const u8 {
    // Match is: 0x... - uppercase the hex digits
    if (match.len < 3) return null;

    var result = allocator.alloc(u8, match.len) catch return null;
    result[0] = '0';
    result[1] = 'x';
    for (match[2..], 0..) |c, i| {
        result[2 + i] = std.ascii.toUpper(c);
    }

    return result;
}

/// Collapse empty elements with internal whitespace: <tag attrs>\s*</tag> -> <tag attrs></tag>
fn collapseEmptyElements(allocator: std.mem.Allocator, content: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.ensureTotalCapacity(allocator, content.len);

    var i: usize = 0;
    while (i < content.len) {
        // Look for closing tag </tagname>
        if (i + 1 < content.len and content[i] == '<' and content[i + 1] == '/') {
            // Find the end of this closing tag
            const close_start = i;
            var close_end = i + 2;
            while (close_end < content.len and content[close_end] != '>') : (close_end += 1) {}
            if (close_end < content.len) close_end += 1;

            // Extract tag name from </tagname>
            const tag_name = content[close_start + 2 .. close_end - 1];

            // Look back in result for matching opening tag followed by only whitespace
            if (findMatchingOpenTag(result.items, tag_name)) |open_end_pos| {
                // Check if only whitespace between open tag end and current position
                const between = result.items[open_end_pos..];
                var all_ws = true;
                for (between) |c| {
                    if (c != ' ' and c != '\t' and c != '\n' and c != '\r') {
                        all_ws = false;
                        break;
                    }
                }

                if (all_ws) {
                    // Remove the whitespace by truncating
                    result.shrinkRetainingCapacity(open_end_pos);
                }
            }

            // Append closing tag
            try result.appendSlice(allocator, content[close_start..close_end]);
            i = close_end;
        } else {
            try result.append(allocator, content[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice(allocator);
}

fn findMatchingOpenTag(s: []const u8, tag_name: []const u8) ?usize {
    // Search backwards for <tagname> or <tagname ...>
    if (s.len < tag_name.len + 2) return null;

    var i = s.len;
    while (i > 0) {
        i -= 1;
        if (s[i] == '>') {
            // Found a tag end, search backwards for <
            var j = i;
            while (j > 0) {
                j -= 1;
                if (s[j] == '<') {
                    // Skip if it's a closing tag
                    if (j + 1 < i and s[j + 1] == '/') break;

                    // Check if this is <tagname or <tagname ...
                    if (j + 1 + tag_name.len <= i) {
                        const potential = s[j + 1 ..][0..tag_name.len];
                        if (std.mem.eql(u8, potential, tag_name)) {
                            // Check char after tag name is space, >, or end
                            const after_idx = j + 1 + tag_name.len;
                            if (after_idx == i or s[after_idx] == ' ' or s[after_idx] == '>' or
                                s[after_idx] == '\t' or s[after_idx] == '\n')
                            {
                                return i + 1; // Return position after >
                            }
                        }
                    }
                    break; // Found <, stop inner loop
                }
            }
        }
    }
    return null;
}

test "normalize removes xml prolog" {
    const allocator = std.testing.allocator;
    const input = "<?xml version=\"1.0\"?>\n<Event></Event>";
    const result = try normalize(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<Event></Event>", result);
}

test "normalize removes empty attributes" {
    const allocator = std.testing.allocator;
    const input = "<Correlation ActivityID=\"\" RelatedActivityID=\"\"></Correlation>";
    const result = try normalize(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<Correlation></Correlation>", result);
}

test "normalize uppercases GUID in attribute" {
    const allocator = std.testing.allocator;
    const input = "<Provider Guid=\"{abcd1234-5678-90ab-cdef-1234567890ab}\"></Provider>";
    const result = try normalize(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<Provider Guid=\"ABCD1234-5678-90AB-CDEF-1234567890AB\"></Provider>", result);
}

test "normalize uppercases hex values" {
    const allocator = std.testing.allocator;
    const input = "<Data>0x3e7</Data>";
    const result = try normalize(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<Data>0x3E7</Data>", result);
}

test "normalize collapses empty elements with whitespace" {
    const allocator = std.testing.allocator;
    const input = "<Tag attr=\"x\">\n    </Tag>";
    const result = try normalize(allocator, input);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<Tag attr=\"x\"></Tag>", result);
}
