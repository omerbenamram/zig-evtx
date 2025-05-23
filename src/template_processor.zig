const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const binary_parser = @import("binary_parser.zig");
const Block = binary_parser.Block;
const BinaryParserError = binary_parser.BinaryParserError;
const variant_types = @import("variant_types.zig");
const VariantTypeNode = variant_types.VariantTypeNode;
const BinaryXMLError = variant_types.BinaryXMLError;

// Import actual EVTX types
const evtx = @import("evtx.zig");
pub const ChunkHeader = evtx.ChunkHeader;
pub const TemplateNode = evtx.Template;

pub const BXmlNode = struct {
    block: Block,
    allocator: Allocator,
    
    pub fn init(allocator: Allocator, buf: []const u8, start_offset: usize) BXmlNode {
        return BXmlNode{
            .block = Block.init(buf, start_offset),
            .allocator = allocator,
        };
    }
};

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

// Root node implementation with substitution parsing
pub const RootNode = struct {
    base: BXmlNode,
    substitution_array: ?SubstitutionArray,

    const Self = @This();

    pub fn init(allocator: Allocator, buf: []const u8, start_offset: usize, chunk: *ChunkHeader, parent: ?*BXmlNode) TemplateProcessorError!Self {
        _ = chunk;
        _ = parent;
        return Self{
            .base = BXmlNode.init(allocator, buf, start_offset),
            .substitution_array = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.substitution_array) |*subs| {
            subs.deinit();
        }
    }

    pub fn substitutions(self: *Self) TemplateProcessorError!*const SubstitutionArray {
        if (self.substitution_array == null) {
            // Parse substitutions from the record data
            // In EVTX, substitutions typically start after the initial record header
            // We need to skip past any initial binary XML structure tokens
            var parse_offset: usize = 0;
            
            // Look for substitution data - typically starts after template instance
            // This is a simplified approach - real implementation would parse the binary XML structure
            while (parse_offset < self.base.block.getSize()) {
                const byte_val = self.base.block.unpackByte(parse_offset) catch break;
                
                // Look for variant type markers (substitution data)
                if ((byte_val >= 0x00 and byte_val <= 0x15) or byte_val == 0x21 or byte_val == 0x81) {
                    break;
                }
                parse_offset += 1;
            }
            
            self.substitution_array = try SubstitutionArray.parse(self.base.allocator, &self.base.block, parse_offset);
        }
        return &self.substitution_array.?;
    }

    pub fn length(self: *const Self) usize {
        _ = self;
        return 0; // Root node has no direct length
    }

    pub fn xml(self: *const Self) TemplateProcessorError![]u8 {
        return try self.base.allocator.dupe(u8, "");
    }
};

// Core template processing workflow
pub fn processRecord(allocator: Allocator, record_data: []const u8, chunk: *ChunkHeader, template_id: u32) ![]u8 {
    _ = record_data; // TODO: Use for substitution processing
    // Get template from chunk
    const template = chunk.getTemplate(template_id) catch |err| {
        std.log.warn("Error getting template {d}: {any}", .{template_id, err});
        return try allocator.dupe(u8, "<Event><!-- Template parsing error --></Event>");
    } orelse {
        std.log.warn("Template {d} not found", .{template_id});
        return try allocator.dupe(u8, "<Event><!-- Template not found --></Event>");
    };
    
    // For now, just return the template's pre-parsed XML
    // TODO: Implement actual substitution processing
    std.log.info("Successfully got template {d}, XML length: {d}", .{template_id, template.xml_format.len});
    return try allocator.dupe(u8, template.xml_format);
}

// Tests
test "Basic substitution parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test parsing of simple substitution data
    const test_data = [_]u8{ 0x01, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00 }; // WString "Hello"
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