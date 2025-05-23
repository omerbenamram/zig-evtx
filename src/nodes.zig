const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const binary_parser = @import("binary_parser.zig");
const Block = binary_parser.Block;
const BinaryParserError = binary_parser.BinaryParserError;

pub const SystemTokens = enum(u8) {
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
};

pub const NodeTypes = enum(u8) {
    Null = 0x00,
    WString = 0x01,
    String = 0x02,
    SignedByte = 0x03,
    UnsignedByte = 0x04,
    SignedWord = 0x05,
    UnsignedWord = 0x06,
    SignedDword = 0x07,
    UnsignedDword = 0x08,
    SignedQword = 0x09,
    UnsignedQword = 0x0A,
    Float = 0x0B,
    Double = 0x0C,
    Boolean = 0x0D,
    Binary = 0x0E,
    Guid = 0x0F,
    Size = 0x10,
    Filetime = 0x11,
    Systemtime = 0x12,
    Sid = 0x13,
    Hex32 = 0x14,
    Hex64 = 0x15,
    Bxml = 0x21,
    WStringArray = 0x81,
};

pub const NodesError = error{
    UnexpectedState,
    SuppressConditionalSubstitution,
    OutOfMemory,
    InvalidData,
} || BinaryParserError;

// Forward declarations
pub const BXmlNode = struct {
    block: Block,
    chunk: ?*anyopaque, // Pointer to chunk
    parent: ?*BXmlNode,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, buf: []const u8, start_offset: usize, chunk: ?*anyopaque, parent: ?*BXmlNode) Self {
        return Self{
            .block = Block.init(buf, start_offset),
            .chunk = chunk,
            .parent = parent,
            .allocator = allocator,
        };
    }

    pub fn tagLength(self: *const Self) NodesError!usize {
        _ = self; // Suppress unused parameter warning
        // Must be implemented by derived types
        return NodesError.UnexpectedState;
    }

    pub fn length(self: *const Self) NodesError!usize {
        const tag_len = try self.tagLength();
        // Add children lengths - simplified for now
        return tag_len;
    }

    pub fn offset(self: *const Self) usize {
        return self.block.getOffset();
    }

    pub fn absoluteOffset(self: *const Self, relative_offset: usize) usize {
        return self.block.absoluteOffset(relative_offset);
    }

    pub fn unpackByte(self: *const Self, relative_offset: usize) BinaryParserError!u8 {
        return self.block.unpackByte(relative_offset);
    }

    pub fn unpackWord(self: *const Self, relative_offset: usize) BinaryParserError!u16 {
        return self.block.unpackWord(relative_offset);
    }

    pub fn unpackDword(self: *const Self, relative_offset: usize) BinaryParserError!u32 {
        return self.block.unpackDword(relative_offset);
    }

    pub fn unpackQword(self: *const Self, relative_offset: usize) BinaryParserError!u64 {
        return self.block.unpackQword(relative_offset);
    }
};

pub const NameStringNode = struct {
    base: BXmlNode,
    next_offset_val: u32,
    hash_val: u16,
    string_length_val: u16,
    string_val: ?[]u8,

    const Self = @This();

    pub fn init(allocator: Allocator, buf: []const u8, start_offset: usize, chunk: ?*anyopaque, parent: ?*BXmlNode) NodesError!Self {
        var node = Self{
            .base = BXmlNode.init(allocator, buf, start_offset, chunk, parent),
            .next_offset_val = 0,
            .hash_val = 0,
            .string_length_val = 0,
            .string_val = null,
        };

        // Parse fields
        node.next_offset_val = try node.base.unpackDword(0x0);
        node.hash_val = try node.base.unpackWord(0x4);
        node.string_length_val = try node.base.unpackWord(0x6);

        // Parse string
        if (node.string_length_val > 0) {
            node.string_val = try node.base.block.unpackWstring(allocator, 0x8, node.string_length_val);
        }

        return node;
    }

    pub fn deinit(self: *Self) void {
        if (self.string_val) |str| {
            self.base.allocator.free(str);
        }
    }

    pub fn nextOffset(self: *const Self) u32 {
        return self.next_offset_val;
    }

    pub fn hash(self: *const Self) u16 {
        return self.hash_val;
    }

    pub fn stringLength(self: *const Self) u16 {
        return self.string_length_val;
    }

    pub fn string(self: *const Self) ?[]const u8 {
        return self.string_val;
    }

    pub fn tagLength(self: *const Self) usize {
        return (@as(usize, self.string_length_val) * 2) + 8;
    }

    pub fn length(self: *const Self) usize {
        // Two bytes unaccounted for in original code
        return self.tagLength() + 2;
    }
};

pub const TemplateNode = struct {
    base: BXmlNode,
    next_offset_val: u32,
    template_id_val: u32,
    guid_val: ?[]u8,
    data_length_val: u32,

    const Self = @This();

    pub fn init(allocator: Allocator, buf: []const u8, start_offset: usize, chunk: ?*anyopaque, parent: ?*BXmlNode) NodesError!Self {
        var node = Self{
            .base = BXmlNode.init(allocator, buf, start_offset, chunk, parent),
            .next_offset_val = 0,
            .template_id_val = 0,
            .guid_val = null,
            .data_length_val = 0,
        };

        // Parse fields
        node.next_offset_val = try node.base.unpackDword(0x0);
        node.template_id_val = try node.base.unpackDword(0x4);
        node.guid_val = try node.base.block.unpackGuid(allocator, 0x4); // Overlaps with template_id in original
        node.data_length_val = try node.base.unpackDword(0x14);

        return node;
    }

    pub fn deinit(self: *Self) void {
        if (self.guid_val) |guid_data| {
            self.base.allocator.free(guid_data);
        }
    }

    pub fn nextOffset(self: *const Self) u32 {
        return self.next_offset_val;
    }

    pub fn templateId(self: *const Self) u32 {
        return self.template_id_val;
    }

    pub fn guid(self: *const Self) ?[]const u8 {
        return self.guid_val;
    }

    pub fn dataLength(self: *const Self) u32 {
        return self.data_length_val;
    }

    pub fn tagLength(self: *const Self) usize {
        _ = self; // Suppress unused parameter warning
        return 0x18;
    }

    pub fn length(self: *const Self) usize {
        return self.tagLength() + self.data_length_val;
    }
};

pub const EndOfStreamNode = struct {
    base: BXmlNode,

    const Self = @This();

    pub fn init(allocator: Allocator, buf: []const u8, start_offset: usize, chunk: ?*anyopaque, parent: ?*BXmlNode) Self {
        return Self{
            .base = BXmlNode.init(allocator, buf, start_offset, chunk, parent),
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self; // No cleanup needed
    }

    pub fn flags(self: *const Self) BinaryParserError!u8 {
        const token = try self.base.unpackByte(0);
        return token >> 4;
    }

    pub fn tagLength(self: *const Self) usize {
        _ = self;
        return 1;
    }

    pub fn length(self: *const Self) usize {
        _ = self;
        return 1;
    }
};

pub const OpenStartElementNode = struct {
    base: BXmlNode,
    token_val: u8,
    unknown0_val: u16,
    size_val: u32,
    string_offset_val: u32,
    tag_length_val: usize,

    const Self = @This();

    pub fn init(allocator: Allocator, buf: []const u8, start_offset: usize, chunk: ?*anyopaque, parent: ?*BXmlNode) NodesError!Self {
        var node = Self{
            .base = BXmlNode.init(allocator, buf, start_offset, chunk, parent),
            .token_val = 0,
            .unknown0_val = 0,
            .size_val = 0,
            .string_offset_val = 0,
            .tag_length_val = 11,
        };

        // Parse fields
        node.token_val = try node.base.unpackByte(0x0);
        node.unknown0_val = try node.base.unpackWord(0x1);
        node.size_val = try node.base.unpackDword(0x3);
        node.string_offset_val = try node.base.unpackDword(0x7);

        // Adjust tag length based on flags
        if (node.flags() & 0x04 != 0) {
            node.tag_length_val += 4;
        }

        return node;
    }

    pub fn deinit(self: *Self) void {
        _ = self; // No cleanup needed for now
    }

    pub fn token(self: *const Self) u8 {
        return self.token_val;
    }

    pub fn flags(self: *const Self) u8 {
        return self.token_val >> 4;
    }

    pub fn size(self: *const Self) u32 {
        return self.size_val;
    }

    pub fn stringOffset(self: *const Self) u32 {
        return self.string_offset_val;
    }

    pub fn tagLength(self: *const Self) usize {
        return self.tag_length_val;
    }

    pub fn length(self: *const Self) usize {
        // Simplified for now - need to add children length calculation
        return self.tag_length_val;
    }
};

// Node dispatch function type
pub const NodeInitFn = *const fn (allocator: Allocator, buf: []const u8, offset: usize, chunk: ?*anyopaque, parent: ?*BXmlNode) anyerror!*anyopaque;

// Node dispatch table - maps token values to node types
pub const node_dispatch_table = [_]?NodeInitFn{
    null, // 0x00 - EndOfStreamNode
    null, // 0x01 - OpenStartElementNode  
    null, // 0x02 - CloseStartElementNode
    null, // 0x03 - CloseEmptyElementNode
    null, // 0x04 - CloseElementNode
    null, // 0x05 - ValueNode
    null, // 0x06 - AttributeNode
    null, // 0x07 - CDataSectionNode
    null, // 0x08 - EntityReferenceNode
    null, // 0x09 - (unused)
    null, // 0x0A - ProcessingInstructionTargetNode
    null, // 0x0B - ProcessingInstructionDataNode
    null, // 0x0C - TemplateInstanceNode
    null, // 0x0D - NormalSubstitutionNode
    null, // 0x0E - ConditionalSubstitutionNode
    null, // 0x0F - StartOfStreamNode
};

// Tests
test "NameStringNode initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create test data for a name string node
    var test_data = [_]u8{
        0x10, 0x00, 0x00, 0x00, // next_offset = 0x10
        0x34, 0x12,             // hash = 0x1234
        0x05, 0x00,             // string_length = 5
        'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0, // "Hello" in UTF-16
        0x00, 0x00, // padding
    };

    var node = try NameStringNode.init(allocator, &test_data, 0, null, null);
    defer node.deinit();

    try testing.expect(node.nextOffset() == 0x10);
    try testing.expect(node.hash() == 0x1234);
    try testing.expect(node.stringLength() == 5);
    
    if (node.string()) |str| {
        try testing.expect(std.mem.eql(u8, str, "Hello"));
    } else {
        try testing.expect(false);
    }
}

test "EndOfStreamNode" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_data = [_]u8{0x00}; // EndOfStream token
    const node = EndOfStreamNode.init(allocator, &test_data, 0, null, null);

    try testing.expect(node.tagLength() == 1);
    try testing.expect(node.length() == 1);
}

test "SystemTokens enum values" {
    try testing.expect(@intFromEnum(SystemTokens.EndOfStream) == 0x00);
    try testing.expect(@intFromEnum(SystemTokens.OpenStartElement) == 0x01);
    try testing.expect(@intFromEnum(SystemTokens.TemplateInstance) == 0x0C);
}