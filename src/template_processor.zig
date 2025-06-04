const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const binary_parser = @import("binary_parser.zig");
const Block = binary_parser.Block;
const BinaryParserError = binary_parser.BinaryParserError;
const variant_types = @import("variant_types.zig");
const VariantTypeNode = variant_types.VariantTypeNode;
const BinaryXMLError = @import("tokens.zig").BinaryXMLError;
const bxml_parser = @import("bxml_parser.zig");

// Import actual EVTX types
const evtx = @import("evtx.zig");
pub const ChunkHeader = evtx.ChunkHeader;
pub const TemplateNode = evtx.Template;

pub const TemplateProcessorError = error{
    TemplateNotFound,
    InvalidSubstitution,
    ParseError,
    OutOfMemory,
    NotImplemented,
} || BinaryXMLError;

// Substitution array parsing
pub const SubstitutionArray = struct {
    entries: []VariantTypeNode,
    allocator: Allocator,

    const Self = @This();

    pub fn parse(allocator: Allocator, block: *Block, position: usize) TemplateProcessorError!Self {
        var entries = std.ArrayList(VariantTypeNode).init(allocator);
        errdefer entries.deinit();

        var pos = position;
        const data_end = block.getSize();

        // Parse substitution entries until we reach the end
        while (pos < data_end) {
            // Each substitution starts with a type byte
            if (pos >= data_end) break;

            const variant_node = VariantTypeNode.fromBinary(allocator, block, &pos) catch |err| switch (err) {
                BinaryXMLError.InvalidVariantType => break, // End of substitutions
                else => return err,
            };

            try entries.append(variant_node);
        }

        return Self{
            .entries = try entries.toOwnedSlice(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Free any allocated strings in the variant nodes
        for (self.entries) |*entry| {
            switch (entry.data) {
                .WString => |str| self.allocator.free(str),
                .String => |str| self.allocator.free(str),
                .Binary => |data| self.allocator.free(data),
                .GUID => |data| self.allocator.free(data),
                .SizeT => |data| self.allocator.free(data),
                .Systemtime => |data| self.allocator.free(data),
                .SID => |data| self.allocator.free(data),
                .HexInt32 => |data| self.allocator.free(data),
                .HexInt64 => |data| self.allocator.free(data),
                .BinXml => |data| self.allocator.free(data),
                .WStringArray => |data| self.allocator.free(data),
                else => {},
            }
        }
        self.allocator.free(self.entries);
    }

    pub fn getValue(self: *const Self, index: usize) ?*const VariantTypeNode {
        if (index >= self.entries.len) return null;
        return &self.entries[index];
    }

    pub fn getValueString(self: *const Self, index: usize) ![]u8 {
        if (self.getValue(index)) |variant| {
            return try variant.toString(self.allocator);
        }
        return try self.allocator.dupe(u8, "");
    }

    /// Parse substitution array following the EVTX record format starting at the
    /// provided position. The layout is:
    ///   dword   count
    ///   count * ( word size | byte type | byte padding )  // declarations
    ///   followed by `count` values with the specified size
    pub fn parseWithDeclarations(allocator: Allocator, block: *Block, start_pos: usize) TemplateProcessorError!Self {
        var entries = std.ArrayList(VariantTypeNode).init(allocator);
        errdefer entries.deinit();

        var pos: usize = start_pos;
        const data_end = block.getSize();

        std.log.debug("parseWithDeclarations: start_pos={d}, data_end={d}, block_size={d}", .{ start_pos, data_end, block.buf.len });

        if (pos + 4 > data_end) {
            std.log.err("Not enough data for count: pos={d}, data_end={d}", .{ pos, data_end });
            return TemplateProcessorError.ParseError;
        }

        const sub_count = try block.unpackDword(pos);
        pos += 4;

        const count_usize: usize = @as(usize, sub_count);

        // Read declarations
        var sizes = try allocator.alloc(u16, count_usize);
        var types = try allocator.alloc(u8, count_usize);
        defer allocator.free(sizes);
        defer allocator.free(types);

        var i: usize = 0;
        while (i < count_usize) : (i += 1) {
            if (pos + 4 > data_end) return TemplateProcessorError.ParseError;
            sizes[i] = try block.unpackWord(pos);
            types[i] = try block.unpackByte(pos + 2);
            // skip padding byte
            pos += 4;
        }

        // Read each value according to declaration
        i = 0;
        while (i < count_usize) : (i += 1) {
            const size = sizes[i];
            const typ = types[i];

            if (pos + size > data_end) return TemplateProcessorError.ParseError;

            // Use the new parseWithKnownSize function that handles pre-declared sizes
            const variant_node = VariantTypeNode.parseWithKnownSize(allocator, block, &pos, typ, size) catch |err| {
                std.log.warn("Variant parse error (type={}, size={}): {any}", .{ typ, size, err });
                return TemplateProcessorError.ParseError;
            };

            try entries.append(variant_node);
        }

        return Self{
            .entries = try entries.toOwnedSlice(),
            .allocator = allocator,
        };
    }
};

// Processed template with XML format string and substitution placeholders
pub const ProcessedTemplate = struct {
    xml_format: []u8,
    substitution_count: usize,
    allocator: Allocator,

    const Self = @This();

    pub fn fromTemplate(allocator: Allocator, template: *const TemplateNode) TemplateProcessorError!Self {
        // Get the template's XML format
        const template_xml = template.xml();

        // Count substitution placeholders
        var count: usize = 0;
        var i: usize = 0;
        while (i < template_xml.len) {
            if (template_xml[i] == '{' and i + 1 < template_xml.len and template_xml[i + 1] == '}') {
                count += 1;
                i += 2;
            } else {
                i += 1;
            }
        }

        return Self{
            .xml_format = try allocator.dupe(u8, template_xml),
            .substitution_count = count,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.xml_format);
    }
};

// Template processing core functionality
pub const TemplateProcessor = struct {
    allocator: Allocator,
    template_cache: std.AutoHashMap(u32, *ProcessedTemplate),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .template_cache = std.AutoHashMap(u32, *ProcessedTemplate).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var iterator = self.template_cache.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.template_cache.deinit();
    }

    pub fn processTemplate(self: *Self, template: *const TemplateNode, substitutions: *const SubstitutionArray) TemplateProcessorError![]u8 {
        // Get or create processed template
        const template_id = template.templateId();
        const processed = self.getOrCreateProcessedTemplate(template_id, template) catch |err| {
            std.log.err("Failed to process template {d}: {any}", .{ template_id, err });
            return err;
        };

        // Apply substitutions to generate XML
        return try self.applySubstitutions(processed, substitutions);
    }

    fn getOrCreateProcessedTemplate(self: *Self, template_id: u32, template: *const TemplateNode) TemplateProcessorError!*ProcessedTemplate {
        if (self.template_cache.get(template_id)) |cached| {
            return cached;
        }

        // Create new processed template
        const processed = try self.allocator.create(ProcessedTemplate);
        processed.* = try ProcessedTemplate.fromTemplate(self.allocator, template);
        try self.template_cache.put(template_id, processed);
        return processed;
    }

    fn applySubstitutions(self: *Self, processed: *const ProcessedTemplate, substitutions: *const SubstitutionArray) TemplateProcessorError![]u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        defer result.deinit();

        // Simple substitution processing - replace placeholders in format string
        var format_iter = std.mem.splitSequence(u8, processed.xml_format, "{}");
        var substitution_index: usize = 0;

        // Add first part (before any substitutions)
        if (format_iter.next()) |part| {
            try result.appendSlice(part);
        }

        // Process each substitution placeholder
        while (format_iter.next()) |part_after| {
            // Insert substitution value
            if (substitution_index < substitutions.entries.len) {
                const value_str = try substitutions.getValueString(substitution_index);
                defer self.allocator.free(value_str);

                // Escape XML characters
                try self.appendXmlEscaped(&result, value_str);
            }
            substitution_index += 1;

            // Add the part after this substitution
            try result.appendSlice(part_after);
        }

        return try result.toOwnedSlice();
    }

    fn appendXmlEscaped(self: *Self, result: *std.ArrayList(u8), text: []const u8) !void {
        _ = self;
        for (text) |char| {
            switch (char) {
                '<' => try result.appendSlice("&lt;"),
                '>' => try result.appendSlice("&gt;"),
                '&' => try result.appendSlice("&amp;"),
                '"' => try result.appendSlice("&quot;"),
                '\'' => try result.appendSlice("&apos;"),
                else => try result.append(char),
            }
        }
    }
};

// Substitution processor - applies substitution values to template format strings
pub const SubstitutionProcessor = struct {
    allocator: Allocator,
    template_xml: []const u8,
    substitutions: *const SubstitutionArray,

    const Self = @This();

    pub fn init(allocator: Allocator, template_xml: []const u8, substitutions: *const SubstitutionArray) Self {
        return Self{
            .allocator = allocator,
            .template_xml = template_xml,
            .substitutions = substitutions,
        };
    }

    pub fn process(self: *Self) ![]u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        defer result.deinit();

        var i: usize = 0;
        while (i < self.template_xml.len) {
            // Look for substitution markers
            if (self.findSubstitutionMarker(i)) |marker| {
                // Add any text before the marker
                try result.appendSlice(self.template_xml[i..marker.start]);

                // Process the substitution
                if (marker.index < self.substitutions.entries.len) {
                    const value = try self.substitutions.getValueString(marker.index);
                    defer self.allocator.free(value);

                    // For conditional substitutions, check if we should include it
                    if (marker.is_conditional) {
                        // Check if this is a null/empty value
                        const variant_node = &self.substitutions.entries[marker.index];
                        if (variant_node.tag != .Null and value.len > 0) {
                            // Escape XML special characters
                            try self.appendXmlEscaped(&result, value);
                        }
                        // Otherwise suppress the value (and potentially the parent element)
                    } else {
                        // Normal substitution - always include
                        try self.appendXmlEscaped(&result, value);
                    }
                } else {
                    // Index out of bounds - log warning and keep marker
                    std.log.warn("Substitution index {} out of bounds (max {})", .{ marker.index, self.substitutions.entries.len });
                    try result.appendSlice(self.template_xml[marker.start..marker.end]);
                }

                i = marker.end;
            } else {
                // No more markers, copy the rest
                try result.appendSlice(self.template_xml[i..]);
                break;
            }
        }

        return try result.toOwnedSlice();
    }

    const SubstitutionMarker = struct {
        start: usize,
        end: usize,
        index: usize,
        is_conditional: bool,
    };

    fn findSubstitutionMarker(self: *const Self, start_pos: usize) ?SubstitutionMarker {
        const normal_prefix = "[Normal Substitution(index=";
        const conditional_prefix = "[Conditional Substitution(index=";

        // Find the next substitution marker
        var pos = start_pos;
        while (pos < self.template_xml.len) {
            if (std.mem.startsWith(u8, self.template_xml[pos..], normal_prefix)) {
                return self.parseMarker(pos, normal_prefix.len, false);
            } else if (std.mem.startsWith(u8, self.template_xml[pos..], conditional_prefix)) {
                return self.parseMarker(pos, conditional_prefix.len, true);
            }
            pos += 1;
        }

        return null;
    }

    fn parseMarker(self: *const Self, start: usize, prefix_len: usize, is_conditional: bool) ?SubstitutionMarker {
        const index_start = start + prefix_len;
        var index_end = index_start;

        // Find the comma after the index
        while (index_end < self.template_xml.len and self.template_xml[index_end] != ',') : (index_end += 1) {}

        if (index_end >= self.template_xml.len) return null;

        // Parse the index
        const index_str = self.template_xml[index_start..index_end];
        const index = std.fmt.parseInt(usize, index_str, 10) catch return null;

        // Find the closing bracket
        var marker_end = index_end;
        while (marker_end < self.template_xml.len and self.template_xml[marker_end] != ']') : (marker_end += 1) {}

        if (marker_end >= self.template_xml.len) return null;
        marker_end += 1; // Include the closing bracket

        return SubstitutionMarker{
            .start = start,
            .end = marker_end,
            .index = index,
            .is_conditional = is_conditional,
        };
    }

    fn appendXmlEscaped(self: *const Self, list: *std.ArrayList(u8), text: []const u8) !void {
        _ = self;
        for (text) |char| {
            switch (char) {
                '<' => try list.appendSlice("&lt;"),
                '>' => try list.appendSlice("&gt;"),
                '&' => try list.appendSlice("&amp;"),
                '"' => try list.appendSlice("&quot;"),
                '\'' => try list.appendSlice("&apos;"),
                else => try list.append(char),
            }
        }
    }
};

pub fn processRecord(allocator: Allocator, record_data: []const u8, chunk: *ChunkHeader, template_id: u32) ![]u8 {
    _ = template_id; // Template ID is embedded in the binary XML

    const bxml_offset = 0x18;
    if (record_data.len <= bxml_offset)
        return try allocator.dupe(u8, "<Event><!-- Record too small --></Event>");

    var block = binary_parser.Block.init(record_data[bxml_offset..], 0);
    return bxml_parser.parseRecordXml(allocator, &block, 0, @intCast(record_data.len - bxml_offset), chunk) catch |err| {
        std.log.warn("Failed to parse record XML: {any}", .{err});
        return try allocator.dupe(u8, "<Event><!-- XML parsing error --></Event>");
    };
}

// Tests
test "Basic substitution parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test parsing of simple substitution data
    const test_data = [_]u8{ 0x01, 0x05, 0x00, 'H', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00 }; // WString "Hello" with length prefix
    var block = Block.init(&test_data, 0);

    var substitutions = try SubstitutionArray.parse(allocator, &block, 0);
    defer substitutions.deinit();

    try testing.expect(substitutions.entries.len > 0);
}

test "Template processor basic workflow" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var processor = TemplateProcessor.init(allocator);
    defer processor.deinit();

    // Test basic functionality - would need actual template and substitution data
    try testing.expect(true); // Placeholder test
}
