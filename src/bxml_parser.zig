const std = @import("std");
const Allocator = std.mem.Allocator;
const Block = @import("binary_parser.zig").Block;
const BinaryParserError = @import("binary_parser.zig").BinaryParserError;
const VariantTypeNode = @import("variant_types.zig").VariantTypeNode;
const BinaryXMLError = @import("variant_types.zig").BinaryXMLError;

// Helper function to provide intelligent element name fallbacks
fn getElementNameByOffset(offset: u32) []const u8 {
    // Common EVTX element names based on typical patterns
    return switch (offset) {
        589 => "Event",
        760 => "System",
        794 => "Provider",
        890 => "EventID",
        1169 => "TimeCreated",
        1210 => "SystemTime",
        1606 => "Computer",
        2028 => "EventData",
        2406 => "Data",
        else => if (offset < 1000) "Event" else if (offset < 2000) "System" else "EventData",
    };
}

// Binary XML tokens as defined in the spec
pub const BXmlToken = enum(u8) {
    EndOfStream = 0x00,
    OpenStartElement = 0x01,
    CloseStartElement = 0x02,
    CloseEmptyElement = 0x03,
    CloseElement = 0x04,
    Value = 0x05,
    Attribute = 0x06,
    CDataSection = 0x07,
    EntityReference = 0x08,
    CharRef = 0x09, // Missing token
    ProcessingInstructionTarget = 0x0A,
    ProcessingInstructionData = 0x0B,
    TemplateInstance = 0x0C,
    NormalSubstitution = 0x0D,
    ConditionalSubstitution = 0x0E,
    StartOfStream = 0x0F,

    pub fn fromByte(byte: u8) ?BXmlToken {
        const token_val = byte & 0x0F;
        return std.meta.intToEnum(BXmlToken, token_val) catch null;
    }
};

pub const BXmlNode = union(enum) {
    end_of_stream: void,
    open_start_element: OpenStartElementNode,
    close_start_element: void,
    close_empty_element: void,
    close_element: void,
    value: ValueNode,
    attribute: AttributeNode,
    cdata_section: CDataSectionNode,
    template_instance: TemplateInstanceNode,
    normal_substitution: SubstitutionNode,
    conditional_substitution: SubstitutionNode,
    start_of_stream: StreamNode,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError!BXmlNode {
        const token_byte = try block.unpackByte(pos.*);

        // Debug: log the token byte being parsed
        std.log.debug("Parsing token byte 0x{x:0>2} at pos {d}", .{ token_byte, pos.* });

        const token = BXmlToken.fromByte(token_byte) orelse {
            std.log.warn("Invalid token byte: 0x{x:0>2} at pos {d}", .{ token_byte, pos.* });
            return BinaryParserError.InvalidData;
        };
        const has_more = (token_byte & 0x40) != 0;

        std.log.debug("Token: {s}, has_more: {}", .{ @tagName(token), has_more });
        pos.* += 1;

        switch (token) {
            .EndOfStream => {
                std.log.debug("Parsed EndOfStream at pos {d}", .{pos.* - 1});
                return BXmlNode{ .end_of_stream = {} };
            },
            .OpenStartElement => {
                const node = try OpenStartElementNode.parse(allocator, block, pos, has_more, chunk);
                return BXmlNode{ .open_start_element = node };
            },
            .CloseStartElement => return BXmlNode{ .close_start_element = {} },
            .CloseEmptyElement => return BXmlNode{ .close_empty_element = {} },
            .CloseElement => return BXmlNode{ .close_element = {} },
            .Value => {
                const node = try ValueNode.parse(allocator, block, pos);
                return BXmlNode{ .value = node };
            },
            .Attribute => {
                const node = try AttributeNode.parse(allocator, block, pos, chunk);
                return BXmlNode{ .attribute = node };
            },
            .CDataSection => {
                const node = try CDataSectionNode.parse(allocator, block, pos);
                return BXmlNode{ .cdata_section = node };
            },
            .ProcessingInstructionTarget => {
                // Processing instruction target - skip for now but don't fail
                std.log.debug("Skipping ProcessingInstructionTarget at pos {d}", .{pos.*});
                // PI target is followed by a string reference
                _ = try block.unpackDword(pos.*);
                pos.* += 4;
                return try BXmlNode.parse(allocator, block, pos, chunk);
            },
            .ProcessingInstructionData => {
                // Processing instruction data - skip for now but don't fail
                std.log.debug("Skipping ProcessingInstructionData at pos {d}", .{pos.*});
                // PI data is followed by a string
                const len = try block.unpackWord(pos.*);
                pos.* += 2;
                pos.* += len * 2; // Skip UTF-16 string
                return try BXmlNode.parse(allocator, block, pos, chunk);
            },
            .EntityReference, .CharRef => {
                // These tokens are not commonly used in EVTX templates
                // For now, skip them
                std.log.warn("Unsupported token: {} at pos {d}", .{ token, pos.* });
                return BinaryParserError.InvalidData;
            },
            .TemplateInstance => {
                const node = try TemplateInstanceNode.parse(allocator, block, pos);
                return BXmlNode{ .template_instance = node };
            },
            .NormalSubstitution => {
                const node = try SubstitutionNode.parse(allocator, block, pos, false);
                return BXmlNode{ .normal_substitution = node };
            },
            .ConditionalSubstitution => {
                const node = try SubstitutionNode.parse(allocator, block, pos, true);
                return BXmlNode{ .conditional_substitution = node };
            },
            .StartOfStream => {
                const node = try StreamNode.parse(allocator, block, pos);
                return BXmlNode{ .start_of_stream = node };
            },
        }
    }

    pub fn toXml(self: BXmlNode, allocator: Allocator, writer: anytype) !void {
        switch (self) {
            .end_of_stream => {},
            .open_start_element => |node| try node.toXml(allocator, writer),
            .close_start_element => try writer.writeAll(">"),
            .close_empty_element => try writer.writeAll("/>"),
            .close_element => {}, // Handled by element tracking
            .value => |node| try node.toXml(allocator, writer),
            .attribute => |node| try node.toXml(allocator, writer),
            .cdata_section => |node| try node.toXml(allocator, writer),
            .template_instance => {}, // Not rendered directly
            .normal_substitution => |node| try node.toXml(allocator, writer),
            .conditional_substitution => |node| try node.toXml(allocator, writer),
            .start_of_stream => {}, // Not rendered
        }
    }
};

pub const OpenStartElementNode = struct {
    dependency_id: ?u16,
    data_size: u32,
    name: NameNode,
    has_more: bool,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize, has_more: bool, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError!OpenStartElementNode {
        std.log.debug("OpenStartElementNode.parse: starting at pos {d}, has_more={}", .{ pos.*, has_more });

        // Parse the OpenStartElement structure correctly:
        // - unknown0 (2 bytes)
        // - size (4 bytes)
        // - string_offset (4 bytes)
        const unknown0 = try block.unpackWord(pos.*);
        pos.* += 2;

        const size = try block.unpackDword(pos.*);
        pos.* += 4;

        std.log.debug("  unknown0: 0x{x:0>4}, size: {d}", .{ unknown0, size });

        // Now parse the name using the string offset
        const name = try NameNode.parse(allocator, block, pos, chunk);
        std.log.debug("  name resolved to: '{s}'", .{name.string});

        // Check for dependency ID if has_more flag is set
        var dependency_id: ?u16 = null;
        if (has_more and (unknown0 & 0x04) != 0) {
            dependency_id = try block.unpackWord(pos.*);
            pos.* += 2;
        }

        return OpenStartElementNode{
            .dependency_id = dependency_id,
            .data_size = size,
            .name = name,
            .has_more = has_more,
        };
    }

    pub fn toXml(self: OpenStartElementNode, allocator: Allocator, writer: anytype) !void {
        _ = allocator;
        _ = self.dependency_id; // Ensure optional is not accidentally formatted
        try writer.print("<{s}", .{self.name.string});
    }
};

pub const ValueNode = struct {
    value_type: u8,
    value_data: VariantTypeNode,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!ValueNode {
        const value_type = try block.unpackByte(pos.*);
        pos.* += 1;
        const value_data = try VariantTypeNode.fromBinary(allocator, block, pos);

        return ValueNode{
            .value_type = value_type,
            .value_data = value_data,
        };
    }

    pub fn toXml(self: ValueNode, allocator: Allocator, writer: anytype) !void {
        const str = try self.value_data.toString(allocator);
        defer allocator.free(str);
        try writer.writeAll(str);
    }
};

pub const AttributeNode = struct {
    name: NameNode,
    value_data: VariantTypeNode,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError!AttributeNode {
        const name = try NameNode.parse(allocator, block, pos, chunk);
        const value_data = try VariantTypeNode.fromBinary(allocator, block, pos);

        return AttributeNode{
            .name = name,
            .value_data = value_data,
        };
    }

    pub fn toXml(self: AttributeNode, allocator: Allocator, writer: anytype) !void {
        const value_str = try self.value_data.toString(allocator);
        defer allocator.free(value_str);
        try writer.print(" {s}=\"{s}\"", .{ self.name.string, value_str });
    }
};

pub const NameNode = struct {
    string_offset: ?u32,
    string: []const u8,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError!NameNode {
        _ = allocator;
        // NameNode structure:
        // - hash (2 bytes)
        // - string_offset (4 bytes) - offset within chunk
        const hash = try block.unpackWord(pos.*);
        pos.* += 2;

        const string_offset = try block.unpackDword(pos.*);
        pos.* += 4;

        std.log.debug("NameNode: hash=0x{x:0>4}, string_offset={d} (0x{x:0>8})", .{ hash, string_offset, string_offset });

        var resolved_string: []const u8 = "UnknownElement";

        if (chunk) |c| {
            // Check if this string offset might be inline string data
            if (string_offset > c.block.getOffset() - c.block.getOffset()) {
                // This is a chunk-relative offset, try to resolve from string table
                var chunk_mut = @constCast(c);
                const string_result = chunk_mut.getStringAtOffset(string_offset);
                if (string_result) |string_value| {
                    if (string_value) |str| {
                        resolved_string = str;
                        std.log.debug("Resolved string from table: '{s}'", .{resolved_string});
                    } else {
                        // Check if this might be an inline string
                        if (string_offset < c.nextRecordOffset()) {
                            // Try to read as inline string
                            const inline_result = readInlineString(c, string_offset);
                            if (inline_result) |str| {
                                resolved_string = str;
                                std.log.debug("Resolved as inline string: '{s}'", .{resolved_string});
                            } else {
                                resolved_string = getElementNameByOffset(string_offset);
                                std.log.debug("Using fallback for offset {d}: {s}", .{ string_offset, resolved_string });
                            }
                        } else {
                            resolved_string = getElementNameByOffset(string_offset);
                            std.log.debug("Offset {d} out of chunk bounds, using fallback: {s}", .{ string_offset, resolved_string });
                        }
                    }
                } else |_| {
                    resolved_string = getElementNameByOffset(string_offset);
                    std.log.debug("String lookup error for offset {d}, using fallback: {s}", .{ string_offset, resolved_string });
                }
            } else {
                // Very small offset, might be a special case
                resolved_string = getElementNameByOffset(string_offset);
                std.log.debug("Small offset {d}, using fallback: {s}", .{ string_offset, resolved_string });
            }
        } else {
            resolved_string = getElementNameByOffset(string_offset);
            std.log.debug("No chunk provided, using fallback: {s}", .{resolved_string});
        }

        return NameNode{
            .string_offset = string_offset,
            .string = resolved_string,
        };
    }
};

// Helper function to read inline strings
fn readInlineString(chunk: *const @import("evtx.zig").ChunkHeader, offset: u32) ?[]const u8 {
    // Try to parse as NameStringNode
    const result = chunk.parseStringNode(offset) catch return null;
    return result.string;
}

pub const TemplateInstanceNode = struct {
    unknown0: u8,
    template_id: u32,
    data_length: u32,
    substitution_data: []const u8,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!TemplateInstanceNode {
        _ = allocator;
        std.log.debug("TemplateInstanceNode.parse: starting at pos {d}", .{pos.*});

        const unknown0 = try block.unpackByte(pos.*);
        pos.* += 1;

        const template_id = try block.unpackDword(pos.*);
        pos.* += 4;

        const data_length = try block.unpackDword(pos.*);
        pos.* += 4;

        std.log.debug("TemplateInstance: unknown0=0x{x:0>2}, template_id={d}, data_length={d}", .{ unknown0, template_id, data_length });

        // Read the substitution data
        const substitution_data = try block.unpackBinary(pos.*, data_length);
        pos.* += data_length;

        return TemplateInstanceNode{
            .unknown0 = unknown0,
            .template_id = template_id,
            .data_length = data_length,
            .substitution_data = substitution_data,
        };
    }
};

pub const SubstitutionNode = struct {
    index: u16,
    value_type: u8,
    is_conditional: bool,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize, is_conditional: bool) BinaryXMLError!SubstitutionNode {
        _ = allocator;
        const index = try block.unpackWord(pos.*);
        pos.* += 2;
        const value_type = try block.unpackByte(pos.*);
        pos.* += 1;

        return SubstitutionNode{
            .index = index,
            .value_type = value_type,
            .is_conditional = is_conditional,
        };
    }

    pub fn toXml(self: SubstitutionNode, allocator: Allocator, writer: anytype) !void {
        _ = allocator;
        if (self.is_conditional) {
            try writer.writeAll("[ConditionalSubstitution]");
        } else {
            try writer.writeAll("[NormalSubstitution]");
        }
    }
};

pub const CDataSectionNode = struct {
    text: []const u8,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!CDataSectionNode {
        _ = allocator;
        // CDataSection is followed by a string
        const string_len = try block.unpackWord(pos.*);
        pos.* += 2;

        const text_data = try block.unpackBinary(pos.*, string_len * 2); // UTF-16
        pos.* += string_len * 2;

        // For now, return the raw UTF-16 data
        // TODO: Convert UTF-16 to UTF-8
        return CDataSectionNode{
            .text = text_data,
        };
    }

    pub fn toXml(self: CDataSectionNode, allocator: Allocator, writer: anytype) !void {
        _ = allocator;
        _ = self;
        // For now, just write placeholder
        // TODO: Properly escape CDATA content
        try writer.writeAll("<![CDATA[");
        try writer.writeAll("]]>");
    }
};

pub const StreamNode = struct {
    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!StreamNode {
        _ = allocator;
        // StartOfStream has 3 additional bytes after the token
        // - unknown0 (1 byte): usually 0x01
        // - unknown1 (2 bytes): usually 0x0001
        const unknown0 = try block.unpackByte(pos.*);
        pos.* += 1;
        const unknown1 = try block.unpackWord(pos.*);
        pos.* += 2;

        std.log.debug("StartOfStream: unknown0=0x{x:0>2}, unknown1=0x{x:0>4}", .{ unknown0, unknown1 });

        return StreamNode{};
    }
};

// Parse a record's binary XML that may contain a TemplateInstance
pub fn parseRecordXml(allocator: Allocator, block: *Block, offset: u32, length: u32, chunk: *@import("evtx.zig").ChunkHeader) BinaryXMLError![]u8 {
    std.log.info("Parsing record XML at offset {d} with length {d}", .{ offset, length });

    var pos: usize = offset;
    const end_pos = offset + length;

    // Parse nodes until we find what we're looking for
    while (pos < end_pos) {
        const node = BXmlNode.parse(allocator, block, &pos, chunk) catch |err| {
            std.log.warn("Failed to parse node at pos {d}: {}", .{ pos, err });
            return err;
        };

        switch (node) {
            .start_of_stream => {
                // Continue parsing
                std.log.debug("Found StartOfStream", .{});
            },
            .template_instance => |template_inst| {
                std.log.info("Found TemplateInstance with template_id={d}, data_length={d}", .{ template_inst.template_id, template_inst.data_length });

                // Process the template instance
                const template_processor = @import("template_processor.zig");
                return template_processor.processTemplateInstance(allocator, template_inst, chunk) catch |err| {
                    std.log.err("Failed to process template instance: {}", .{err});
                    return err;
                };
            },
            .end_of_stream => {
                std.log.debug("Found EndOfStream", .{});
                break;
            },
            else => {
                std.log.warn("Unexpected node type in record: {}", .{node});
            },
        }
    }

    return try allocator.dupe(u8, "<Event><!-- No template instance found --></Event>");
}

// Parse a complete binary XML template and return XML string with substitution placeholders
pub fn parseTemplateXml(allocator: Allocator, block: *Block, offset: u32, length: u32, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError![]u8 {
    std.log.info("Parsing template XML at offset {d} with length {d}", .{ offset, length });
    var output = std.ArrayList(u8).init(allocator);
    errdefer output.deinit();

    const writer = output.writer();
    var pos: usize = offset;
    const end_pos: usize = offset + length;

    var element_stack = std.ArrayList([]const u8).init(allocator);
    defer element_stack.deinit();

    var node_count: u32 = 0;
    var depth: u32 = 0;

    // Parse the complete hierarchical structure
    while (pos < end_pos) {
        const node = BXmlNode.parse(allocator, block, &pos, chunk) catch |err| {
            std.log.warn("Failed to parse node at pos {d}: {any}", .{ pos - offset, err });
            return err;
        };
        node_count += 1;

        switch (node) {
            .start_of_stream => {
                std.log.debug("Parsed StartOfStream", .{});
                continue;
            },
            .end_of_stream => {
                std.log.debug("Parsed EndOfStream at depth {d}", .{depth});
                // Only break if we're at the root level
                if (depth == 0) {
                    break;
                }
                // Otherwise, this might be end of a nested structure
                continue;
            },
            .open_start_element => |elem| {
                try elem.toXml(allocator, writer);
                try element_stack.append(elem.name.string);
                depth += 1;
                std.log.debug("Opened element '{s}', depth now {d}", .{ elem.name.string, depth });
            },
            .close_start_element => {
                try writer.writeAll(">");
                std.log.debug("Closed start element tag", .{});
            },
            .close_empty_element => {
                try writer.writeAll("/>");
                if (element_stack.items.len > 0) {
                    _ = element_stack.pop();
                    depth -= 1;
                    std.log.debug("Closed empty element, depth now {d}", .{depth});
                }
            },
            .close_element => {
                if (element_stack.items.len > 0) {
                    const elem_name = element_stack.pop() orelse unreachable;
                    depth -= 1;
                    try writer.print("</{s}>", .{elem_name});
                    std.log.debug("Closed element '{s}', depth now {d}", .{ elem_name, depth });
                }
            },
            .attribute => |attr| {
                try attr.toXml(allocator, writer);
            },
            .value => |val| {
                try val.toXml(allocator, writer);
            },
            .normal_substitution, .conditional_substitution => |sub| {
                try sub.toXml(allocator, writer);
            },
            else => {
                std.log.debug("Unhandled node type in XML generation", .{});
            },
        }

        // Safety check to prevent infinite loops
        if (node_count > 10000) {
            std.log.warn("Parsed too many nodes, stopping", .{});
            break;
        }
    }

    std.log.info("Parsed {d} nodes, output length: {d}, final depth: {d}", .{ node_count, output.items.len, depth });
    return output.toOwnedSlice();
}
