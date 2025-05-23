const std = @import("std");
const Allocator = std.mem.Allocator;
const Block = @import("binary_parser.zig").Block;
const BinaryParserError = @import("binary_parser.zig").BinaryParserError;
const VariantTypeNode = @import("variant_types.zig").VariantTypeNode;
const BinaryXMLError = @import("variant_types.zig").BinaryXMLError;

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
    ProcessingInstructionTarget = 0x0A,
    ProcessingInstructionData = 0x0B,
    TemplateInstance = 0x0C,
    NormalSubstitution = 0x0D,
    ConditionalSubstitution = 0x0E,
    StartOfStream = 0x0F,
    
    pub fn fromByte(byte: u8) BXmlToken {
        return @enumFromInt(byte & 0x0F);
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
    template_instance: TemplateInstanceNode,
    normal_substitution: SubstitutionNode,
    conditional_substitution: SubstitutionNode,
    start_of_stream: StreamNode,
    
    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!BXmlNode {
        const token_byte = try block.unpackByte(pos.*);
        const token = BXmlToken.fromByte(token_byte);
        const has_more = (token_byte & 0x40) != 0;
        
        pos.* += 1;
        
        switch (token) {
            .EndOfStream => return BXmlNode{ .end_of_stream = {} },
            .OpenStartElement => {
                const node = try OpenStartElementNode.parse(allocator, block, pos, has_more);
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
                const node = try AttributeNode.parse(allocator, block, pos);
                return BXmlNode{ .attribute = node };
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
            else => return BinaryParserError.InvalidData,
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
    
    pub fn parse(allocator: Allocator, block: *Block, pos: *usize, has_more: bool) BinaryXMLError!OpenStartElementNode {
        const dependency_id = if (has_more) blk: {
            const val = try block.unpackWord(pos.*);
            pos.* += 2;
            break :blk val;
        } else null;
        const data_size = try block.unpackDword(pos.*);
        pos.* += 4;
        const name = try NameNode.parse(allocator, block, pos);
        
        return OpenStartElementNode{
            .dependency_id = dependency_id,
            .data_size = data_size,
            .name = name,
        };
    }
    
    pub fn toXml(self: OpenStartElementNode, allocator: Allocator, writer: anytype) !void {
        _ = allocator;
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
    
    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!AttributeNode {
        const name = try NameNode.parse(allocator, block, pos);
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
    
    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!NameNode {
        _ = allocator;
        const hash = try block.unpackWord(pos.*);
        _ = hash; // TODO: Use for string table lookup
        pos.* += 2;
        
        const string_offset = try block.unpackDword(pos.*);
        pos.* += 4;
        
        // For now, return placeholder names
        // TODO: Implement proper string table lookup
        return NameNode{
            .string_offset = string_offset,
            .string = "UnknownElement",
        };
    }
};

pub const TemplateInstanceNode = struct {
    unknown0: u8,
    template_id: u32,
    template_offset: u32,
    
    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!TemplateInstanceNode {
        _ = allocator;
        const unknown0 = try block.unpackByte(pos.*);
        pos.* += 1;
        const template_id = try block.unpackDword(pos.*);
        pos.* += 4;
        const template_offset = try block.unpackDword(pos.*);
        pos.* += 4;
        
        return TemplateInstanceNode{
            .unknown0 = unknown0,
            .template_id = template_id,
            .template_offset = template_offset,
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

pub const StreamNode = struct {
    dependency_id: ?u16,
    data_size: u32,
    
    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!StreamNode {
        _ = allocator;
        // StartOfStream has additional fields
        const unknown = try block.unpackByte(pos.*);
        pos.* += 1;
        
        const has_more = (unknown & 0x40) != 0;
        const dependency_id = if (has_more) blk: {
            const val = try block.unpackWord(pos.*);
            pos.* += 2;
            break :blk val;
        } else null;
        const data_size = try block.unpackDword(pos.*);
        pos.* += 4;
        
        return StreamNode{
            .dependency_id = dependency_id,
            .data_size = data_size,
        };
    }
};

// Parse a complete binary XML template and return XML string with substitution placeholders
pub fn parseTemplateXml(allocator: Allocator, block: *Block, offset: u32, length: u32) BinaryXMLError![]u8 {
    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();
    
    const writer = output.writer();
    var pos: usize = offset;
    const end_pos: usize = offset + length;
    
    var element_stack = std.ArrayList([]const u8).init(allocator);
    defer element_stack.deinit();
    
    while (pos < end_pos) {
        const node = try BXmlNode.parse(allocator, block, &pos);
        
        switch (node) {
            .start_of_stream => continue,
            .end_of_stream => break,
            .open_start_element => |elem| {
                try elem.toXml(allocator, writer);
                try element_stack.append(elem.name.string);
            },
            .close_start_element => try writer.writeAll(">"),
            .close_empty_element => {
                try writer.writeAll("/>");
                _ = element_stack.pop();
            },
            .close_element => {
                if (element_stack.items.len > 0) {
                    const elem_name = element_stack.pop();
                    try writer.print("</{s}>", .{elem_name});
                }
            },
            else => try node.toXml(allocator, writer),
        }
    }
    
    return output.toOwnedSlice();
}