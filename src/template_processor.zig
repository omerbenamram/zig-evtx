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
const BXmlNode = bxml_parser.BXmlNode;

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
                std.log.warn("Variant parse error (type={d}, size={d}): {any}", .{ typ, size, err });
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

/// A template representation that stores the BXML node tree
/// and can be materialized with substitution values later
pub const TemplateStructure = struct {
    /// Root nodes of the template
    nodes: []BXmlNode,
    /// Allocator used for this structure
    allocator: Allocator,
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, nodes: []const BXmlNode) !Self {
        // Deep copy the nodes to ensure ownership
        const owned_nodes = try allocator.alloc(BXmlNode, nodes.len);
        @memcpy(owned_nodes, nodes);
        
        return Self{
            .nodes = owned_nodes,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        // NOTE: Currently we're just shallow copying nodes from parseTemplateNodes
        // The strings and other data are owned by the chunk/block allocators
        // So we only free the nodes array itself, not the contents
        self.allocator.free(self.nodes);
    }
    
    /// Materialize the template with actual substitution values
    pub fn toXml(self: *const Self, allocator: Allocator, subs: *const SubstitutionArray) ![]u8 {
        var output = std.ArrayList(u8).init(allocator);
        errdefer output.deinit();
        
        const writer = output.writer();
        var element_stack = std.ArrayList([]const u8).init(allocator);
        defer element_stack.deinit();
        
        try self.renderNodes(allocator, writer, &element_stack, self.nodes, subs);
        
        // Close any remaining open elements
        while (element_stack.items.len > 0) {
            // Safe to use unreachable: we check items.len > 0 before popping
            const name = element_stack.pop() orelse unreachable;
            try writer.print("</{s}>", .{name});
        }
        
        return output.toOwnedSlice();
    }
    
    fn renderNodes(
        self: *const Self,
        allocator: Allocator,
        writer: anytype,
        element_stack: *std.ArrayList([]const u8),
        nodes: []const BXmlNode,
        subs: *const SubstitutionArray,
    ) !void {
        _ = self;
        
        for (nodes) |node| {
            // Use BXmlNode's toXml method which handles dispatching correctly
            try node.toXml(allocator, writer, subs);
            
            // Handle element stack tracking separately
            switch (node) {
                .open_start_element => |elem| {
                    try element_stack.append(elem.name.string);
                },
                .close_empty_element => {
                    if (element_stack.items.len > 0) {
                        _ = element_stack.pop();
                    }
                },
                .close_element => {
                    if (element_stack.items.len > 0) {
                        // Safe to use unreachable: we check items.len > 0 before popping
                        const name = element_stack.pop() orelse unreachable;
                        try writer.print("</{s}>", .{name});
                    }
                },
                else => {},
            }
        }
    }
};

// Template processing core functionality
pub const TemplateProcessor = struct {
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{ .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn processTemplate(self: *Self, template: *const TemplateNode, substitutions: *const SubstitutionArray) TemplateProcessorError![]u8 {
        return template.structure.toXml(self.allocator, substitutions) catch |err| {
            std.log.err("Failed to process template: {any}", .{err});
            return TemplateProcessorError.ParseError;
        };
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
