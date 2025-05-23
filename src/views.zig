const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const evtx = @import("evtx.zig");
const Record = evtx.Record;
const template_processor = @import("template_processor.zig");

pub const ViewsError = error{
    OutOfMemory,
    UnexpectedElement,
} || evtx.EvtxError;

pub const XML_HEADER = "<?xml version=\"1.1\" encoding=\"utf-8\" standalone=\"yes\" ?>\n";

// Restricted characters in XML 1.1 (characters that need to be escaped or removed)
const RESTRICTED_CHARS = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x7F };

pub fn isRestrictedChar(c: u8) bool {
    for (RESTRICTED_CHARS) |restricted| {
        if (c == restricted) return true;
    }
    return false;
}

pub fn escapeXmlString(allocator: Allocator, input: []const u8) ViewsError![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    for (input) |c| {
        switch (c) {
            '<' => try result.appendSlice("&lt;"),
            '>' => try result.appendSlice("&gt;"),
            '&' => try result.appendSlice("&amp;"),
            '"' => try result.appendSlice("&quot;"),
            '\'' => try result.appendSlice("&apos;"),
            else => {
                if (isRestrictedChar(c)) {
                    // Replace restricted characters with character reference
                    const ref = try std.fmt.allocPrint(allocator, "&#x{X:0>2};", .{c});
                    defer allocator.free(ref);
                    try result.appendSlice(ref);
                } else {
                    try result.append(c);
                }
            },
        }
    }

    return result.toOwnedSlice() catch return ViewsError.OutOfMemory;
}

pub fn escapeXmlAttr(allocator: Allocator, input: []const u8) ViewsError![]u8 {
    // First escape the string
    const escaped = try escapeXmlString(allocator, input);
    defer allocator.free(escaped);

    // Then wrap in quotes
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    try result.append('"');
    try result.appendSlice(escaped);
    try result.append('"');

    return result.toOwnedSlice() catch return ViewsError.OutOfMemory;
}

pub fn renderRecordAsXml(allocator: Allocator, record: *const Record) ViewsError![]u8 {
    // Simply use the record's xml() method which handles all the template processing
    return record.xml(allocator) catch |err| blk: {
        std.log.warn("Failed to render record as XML: {}", .{err});
        // Fallback to basic XML structure with base64 data
        var result = std.ArrayList(u8).init(allocator);
        defer result.deinit();

        // Start with basic record structure
        try result.appendSlice("<Event>");
        
        // Add record metadata
        const record_num_str = try std.fmt.allocPrint(allocator, "{d}", .{record.recordNum()});
        defer allocator.free(record_num_str);
        
        try result.appendSlice("<System>");
        try result.appendSlice("<RecordID>");
        try result.appendSlice(record_num_str);
        try result.appendSlice("</RecordID>");
        
        // Add timestamp if available
        const timestamp = record.timestamp();
        if (timestamp.toDateTime()) |dt| {
            const timestamp_str = try std.fmt.allocPrint(allocator, "{d}", .{dt.secs});
            defer allocator.free(timestamp_str);
            
            try result.appendSlice("<TimeCreated SystemTime=\"");
            try result.appendSlice(timestamp_str);
            try result.appendSlice("\"/>");
        }
        
        try result.appendSlice("</System>");
        
        // Add raw data as base64 for fallback
        try result.appendSlice("<EventData>");
        
        const raw_data = record.data() catch {
            try result.appendSlice("<Error>Failed to get record data</Error>");
            try result.appendSlice("</EventData>");
            try result.appendSlice("</Event>");
            break :blk try result.toOwnedSlice();
        };
        
        const encoded_size = std.base64.standard.Encoder.calcSize(raw_data.len);
        const encoded = try allocator.alloc(u8, encoded_size);
        defer allocator.free(encoded);
        
        _ = std.base64.standard.Encoder.encode(encoded, raw_data);
        
        try result.appendSlice("<RawData>");
        try result.appendSlice(encoded);
        try result.appendSlice("</RawData>");
        
        try result.appendSlice("</EventData>");
        try result.appendSlice("</Event>");

        break :blk try result.toOwnedSlice();
    };
}

pub fn renderEvtxAsXml(allocator: Allocator, evtx_parser: *evtx.Evtx) ViewsError![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    // Add XML header
    try result.appendSlice(XML_HEADER);
    try result.appendSlice("<Events>\n");

    // Iterate through all records
    var record_iter = evtx_parser.records();
    while (record_iter.next()) |record| {
        const record_xml = try renderRecordAsXml(allocator, &record);
        defer allocator.free(record_xml);
        
        try result.appendSlice(record_xml);
        try result.append('\n');
    }

    try result.appendSlice("</Events>\n");

    return result.toOwnedSlice() catch return ViewsError.OutOfMemory;
}

pub fn renderEvtxAsJson(allocator: Allocator, evtx_parser: *evtx.Evtx) ViewsError![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    try result.appendSlice("[\n");

    var first = true;
    var record_iter = evtx_parser.records();
    while (record_iter.next()) |record| {
        if (!first) {
            try result.appendSlice(",\n");
        }
        first = false;

        try result.appendSlice("  {\n");
        
        // Record number
        const record_num_str = try std.fmt.allocPrint(allocator, "    \"RecordID\": {d}", .{record.recordNum()});
        defer allocator.free(record_num_str);
        try result.appendSlice(record_num_str);
        
        // Timestamp
        const timestamp = record.timestamp();
        if (timestamp.toDateTime()) |dt| {
            const timestamp_str = try std.fmt.allocPrint(allocator, ",\n    \"Timestamp\": {d}", .{dt.secs});
            defer allocator.free(timestamp_str);
            try result.appendSlice(timestamp_str);
        }
        
        // Raw data as base64
        const raw_data = try record.data();
        const encoded_size = std.base64.standard.Encoder.calcSize(raw_data.len);
        const encoded = try allocator.alloc(u8, encoded_size);
        defer allocator.free(encoded);
        
        _ = std.base64.standard.Encoder.encode(encoded, raw_data);
        
        try result.appendSlice(",\n    \"RawData\": \"");
        try result.appendSlice(encoded);
        try result.appendSlice("\"");
        
        try result.appendSlice("\n  }");
    }

    try result.appendSlice("\n]\n");

    return result.toOwnedSlice() catch return ViewsError.OutOfMemory;
}

// Parse template ID from record's binary XML data
fn parseTemplateIdFromRecord(data: []const u8) ?u32 {
    if (data.len < 8) return null;
    
    // EVTX records typically start with binary XML tokens
    // Look for TemplateInstance token (0x0C) which contains the template ID
    var i: usize = 0;
    while (i + 8 <= data.len) {
        const token = data[i] & 0x0F; // Lower 4 bits are the token
        
        if (token == 0x0C) { // TemplateInstance token
            // Template instance structure:
            // 0x00: token (1 byte)
            // 0x01: unknown (1 byte) 
            // 0x02: template_id (4 bytes)
            // 0x06: guid (16 bytes) - optional
            
            if (i + 6 <= data.len) {
                // Read template ID (little endian)
                const template_id = std.mem.readInt(u32, data[i+2..i+6][0..4], .little);
                return template_id;
            }
        }
        
        i += 1;
    }
    
    return null;
}

// Tests
test "XML string escaping" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_input = "Hello <world> & \"test\"";
    const escaped = try escapeXmlString(allocator, test_input);
    defer allocator.free(escaped);

    const expected = "Hello &lt;world&gt; &amp; &quot;test&quot;";
    try testing.expectEqualStrings(expected, escaped);
}

test "Restricted character escaping" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_input = [_]u8{ 'H', 'i', 0x01, 0x02, 'x' };
    const escaped = try escapeXmlString(allocator, &test_input);
    defer allocator.free(escaped);

    try testing.expect(std.mem.indexOf(u8, escaped, "&#x01;") != null);
    try testing.expect(std.mem.indexOf(u8, escaped, "&#x02;") != null);
}

test "XML attribute escaping" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_input = "value";
    const escaped = try escapeXmlAttr(allocator, test_input);
    defer allocator.free(escaped);

    const expected = "\"value\"";
    try testing.expectEqualStrings(expected, escaped);
}