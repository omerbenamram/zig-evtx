const std = @import("std");
const Allocator = std.mem.Allocator;
const Block = @import("binary_parser.zig").Block;
const BinaryParserError = @import("binary_parser.zig").BinaryParserError;
const VariantTypeNode = @import("variant_types.zig").VariantTypeNode;
const tokens = @import("tokens.zig");
const BXmlToken = tokens.BXmlToken;
const BinaryXMLError = tokens.BinaryXMLError;

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

pub const BXmlNode = union(enum) {
    end_of_stream: void,
    open_start_element: OpenStartElementNode,
    close_start_element: void,
    close_empty_element: void,
    close_element: void,
    value: ValueNode,
    attribute: AttributeNode,
    cdata_section: CDataSectionNode,
    entity_reference: EntityReferenceNode,
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
            return BinaryXMLError.InvalidToken;
        };
        const has_more = BXmlToken.hasMoreFlag(token_byte);

        std.log.debug("Token: {s}, has_more: {}", .{ tokens.getTokenName(token_byte), has_more });
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
            .EntityReference => {
                const node = try EntityReferenceNode.parse(allocator, block, pos, chunk);
                return BXmlNode{ .entity_reference = node };
            },
            .CharRef => {
                // Character references are less common, skip for now
                std.log.warn("Unsupported token: {} at pos {d}", .{ token, pos.* });
                return BinaryXMLError.InvalidData;
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
        _ = allocator;

        // Remember start of this node relative to the block
        const start_pos = pos.*;
        std.log.debug("OpenStartElementNode.parse: starting at pos {d}, has_more={}", .{ start_pos, has_more });

        // Read unknown0 (2 bytes)
        const unknown0 = try block.unpackWord(pos.*);
        pos.* += 2;

        // Check if this is a ROOT OpenStartElement marker
        if (!has_more and unknown0 == 1) {
            if (block.offset + pos.* < block.buf.len) {
                const next_byte = block.buf[block.offset + pos.*];
                const next_token = BXmlToken.fromByte(next_byte);

                if (next_token != null and (next_byte == 0x41 or next_byte == 0x01)) {
                    std.log.debug("  Detected ROOT OpenStartElement marker (unknown0=1, next byte=0x{x:02})", .{next_byte});

                    return OpenStartElementNode{
                        .dependency_id = null,
                        .data_size = 0,
                        .name = NameNode{
                            .string_offset = 0,
                            .string = "ROOT",
                        },
                        .has_more = false,
                    };
                }
            }
        }

        // Read size (4 bytes)
        const size = try block.unpackDword(pos.*);
        pos.* += 4;

        // Read string_offset (4 bytes)
        const string_offset = try block.unpackDword(pos.*);
        pos.* += 4;

        std.log.debug("  unknown0: 0x{x:0>4}, size: {d}, string_offset: {d} (0x{x:0>8})", .{ unknown0, size, string_offset, string_offset });

        // Resolve the element name from string table
        const resolved_string = NameNode.resolveString(string_offset, chunk);
        const name = NameNode{
            .string_offset = string_offset,
            .string = resolved_string,
        };
        std.log.debug("  name resolved to: '{s}'", .{name.string});

        // According to EVTX documentation and our analysis:
        // When has_more flag is set, there's an attribute list structure:
        // - 4 bytes: Data size (not including these 4 bytes)
        // - Variable: Array of attributes
        if (has_more) {
            // Read the attribute list size
            const attr_list_size = try block.unpackDword(pos.*);
            pos.* += 4;

            std.log.debug("  Attribute list size: {d} bytes", .{attr_list_size});

            // Skip over the attribute data to position the parser at the
            // first child element.  Attribute data size is specified by the
            // attribute list size field.
            if (pos.* + attr_list_size <= block.buf.len - block.offset) {
                pos.* += attr_list_size;
            } else {
                std.log.warn("  Attribute list would exceed buffer, adjusting", .{});
                pos.* = block.buf.len - block.offset;
            }
        }

        // If the name string is stored inline after this node, skip it
        if (chunk != null) {
            if (string_offset > start_pos and string_offset < block.getSize()) {
                const str_len = block.unpackWord(string_offset + 0x06) catch 0;
                const inline_size = @as(usize, str_len) * 2 + 10;

                if (pos.* <= string_offset) {
                    pos.* = string_offset + inline_size;
                } else if (pos.* < string_offset + inline_size) {
                    pos.* = string_offset + inline_size;
                }
            }
        }

        return OpenStartElementNode{
            .dependency_id = null, // Simplified for now
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
        std.log.debug("ValueNode: parsing variant type 0x{x:0>2} at pos {d}", .{ value_type, pos.* });

        // Don't call fromBinary which reads the type again, use parseWithType
        const value_data = try VariantTypeNode.parseWithType(allocator, block, pos, value_type);

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

    // For OpenStartElement - just parse string offset (4 bytes)
    pub fn parseForElement(allocator: Allocator, block: *Block, pos: *usize, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError!NameNode {
        _ = allocator;

        const string_offset = try block.unpackDword(pos.*);
        pos.* += 4;

        std.log.debug("NameNode (element): string_offset={d} (0x{x:0>8})", .{ string_offset, string_offset });

        const resolved_string = resolveString(string_offset, chunk);

        return NameNode{
            .string_offset = string_offset,
            .string = resolved_string,
        };
    }

    // For attributes - parse hash (2 bytes) + string offset (4 bytes)
    pub fn parse(allocator: Allocator, block: *Block, pos: *usize, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError!NameNode {
        _ = allocator;
        // NameNode structure for attributes:
        // - hash (2 bytes)
        // - string_offset (4 bytes) - offset within chunk
        const hash = try block.unpackWord(pos.*);
        pos.* += 2;

        const string_offset = try block.unpackDword(pos.*);
        pos.* += 4;

        std.log.debug("NameNode (attribute): hash=0x{x:0>4}, string_offset={d} (0x{x:0>8})", .{ hash, string_offset, string_offset });

        const resolved_string = resolveString(string_offset, chunk);

        return NameNode{
            .string_offset = string_offset,
            .string = resolved_string,
        };
    }

    // Helper function to resolve strings from chunk string table
    fn resolveString(string_offset: u32, chunk: ?*const @import("evtx.zig").ChunkHeader) []const u8 {
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

        return resolved_string;
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
    template_offset: u32,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!TemplateInstanceNode {
        _ = allocator;
        std.log.debug("TemplateInstanceNode.parse: starting at pos {d}", .{pos.*});

        const unknown0 = try block.unpackByte(pos.*);
        pos.* += 1;

        const template_id = try block.unpackDword(pos.*);
        pos.* += 4;

        const template_offset = try block.unpackDword(pos.*);
        pos.* += 4;

        std.log.debug("TemplateInstance: unknown0=0x{x:0>2}, template_id={d}, template_offset={d}", .{ unknown0, template_id, template_offset });

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
        // Skip padding byte present in substitution tokens
        if (pos.* < block.getSize()) {
            pos.* += 1;
        }

        return SubstitutionNode{
            .index = index,
            .value_type = value_type,
            .is_conditional = is_conditional,
        };
    }

    pub fn toXml(self: SubstitutionNode, allocator: Allocator, writer: anytype) !void {
        _ = allocator;
        if (self.is_conditional) {
            try writer.print("[Conditional Substitution(index={}, type={})]", .{ self.index, self.value_type });
        } else {
            try writer.print("[Normal Substitution(index={}, type={})]", .{ self.index, self.value_type });
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

        // Align to 4-byte boundary (padding after CDATA)
        const consumed = 2 + string_len * 2;
        const padding = @as(usize, (4 - (consumed % 4)) % 4);
        if (pos.* + padding <= block.getSize()) {
            pos.* += padding;
        }

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

pub const EntityReferenceNode = struct {
    name: []const u8,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError!EntityReferenceNode {
        _ = allocator;
        // EntityReference has a 4-byte string offset
        const string_offset = try block.unpackDword(pos.*);
        pos.* += 4;

        var entity_name: []const u8 = "unknown";

        if (chunk) |c| {
            var chunk_mut = @constCast(c);
            const string_result = chunk_mut.getStringAtOffset(string_offset) catch null;
            if (string_result) |str| {
                entity_name = str;
            }
        }

        return EntityReferenceNode{
            .name = entity_name,
        };
    }

    pub fn toXml(self: EntityReferenceNode, allocator: Allocator, writer: anytype) !void {
        _ = allocator;
        try writer.print("&{s};", .{self.name});
    }
};

pub const StreamNode = struct {
    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!StreamNode {
        _ = allocator;

        // The StartOfStream token is followed by three bytes of
        // additional data: a single byte and a 16-bit value.
        // These values are typically 0x01, 0x0001.
        const unknown0 = try block.unpackByte(pos.*);
        pos.* += 1;
        const unknown1 = try block.unpackWord(pos.*);
        pos.* += 2;

        std.log.debug(
            "StartOfStream token: unknown0=0x{x:0>2}, unknown1=0x{x:0>4}",
            .{ unknown0, unknown1 },
        );

        return StreamNode{};
    }
};

// Parse a record's binary XML that may contain a TemplateInstance
pub fn parseRecordXml(allocator: Allocator, block: *Block, offset: u32, length: u32, chunk: *@import("evtx.zig").ChunkHeader) BinaryXMLError![]u8 {
    std.log.info("Parsing record XML at offset {d} with length {d}", .{ offset, length });

    var pos: usize = offset;
    const end_pos = offset + length;

    // Parse StartOfStream (token + 3 bytes of data)
    const start_token = try block.unpackByte(pos);
    if (start_token != 0x0f) {
        std.log.warn("Expected StartOfStream (0x0f), got 0x{x:0>2}", .{start_token});
        return BinaryXMLError.InvalidToken;
    }
    // Skip the 3 bytes of StartOfStream data
    pos += 4;

    // Parse TemplateInstance
    const template_token = try block.unpackByte(pos);
    if (template_token != 0x0c) {
        std.log.warn("Expected TemplateInstance (0x0c), got 0x{x:0>2}", .{template_token});
        return BinaryXMLError.InvalidToken;
    }
    pos += 1;

    // Parse template instance data
    const ti_unknown = try block.unpackByte(pos);
    pos += 1;
    const template_id = try block.unpackDword(pos);
    pos += 4;
    const template_offset = try block.unpackDword(pos);
    pos += 4;

    std.log.info("TemplateInstance: unknown=0x{x:0>2}, id={d}, offset={d}", .{ ti_unknown, template_id, template_offset });

    // Check what comes next
    const next_byte = try block.unpackByte(pos);

    if (next_byte == 0x00) {
        // EndOfStream - this record contains the resident template
        std.log.debug("Found EndOfStream at pos {d}, resident template follows", .{pos - offset});
        pos += 1;

        // Parse through the resident template to find where substitutions start
        // For now, use a simple heuristic: look for valid substitution count
        var found_subs = false;
        var subs_pos = pos;

        while (subs_pos + 4 <= end_pos and !found_subs) {
            const potential_count = try block.unpackDword(subs_pos);

            // Check if this could be a valid substitution count
            if (potential_count > 0 and potential_count < 100) {
                // Verify it looks like valid declarations
                var looks_valid = true;
                if (subs_pos + 4 + (potential_count * 4) <= end_pos) {
                    var i: u32 = 0;
                    while (i < potential_count and i < 5) : (i += 1) {
                        const decl_pos = subs_pos + 4 + (i * 4);
                        const size = try block.unpackWord(decl_pos);
                        const typ = try block.unpackByte(decl_pos + 2);

                        // Basic validation
                        if (size > 1000 or typ > 0x30) {
                            looks_valid = false;
                            break;
                        }
                    }

                    if (looks_valid) {
                        std.log.info("Found likely substitution count {d} at pos {d}", .{ potential_count, subs_pos - offset });
                        pos = subs_pos;
                        found_subs = true;
                    }
                }
            }

            subs_pos += 1;
        }

        if (!found_subs) {
            std.log.err("Could not find substitution array in resident template", .{});
            return try allocator.dupe(u8, "<Event><!-- Could not find substitutions --></Event>");
        }
    } else {
        // No EndOfStream - substitutions start immediately
        std.log.debug("No EndOfStream, substitutions start at pos {d}", .{pos - offset});
        // pos is already at the right place
    }

    // Parse substitution array
    const template_processor = @import("template_processor.zig");

    // Log what's at the substitution position
    std.log.debug("Parsing substitutions at pos {d} (0x{x})", .{ pos - offset, pos });
    if (pos + 16 <= block.getSize()) {
        var preview: [16]u8 = undefined;
        for (0..16) |i| {
            preview[i] = try block.unpackByte(pos + i);
        }
        std.log.debug("First 16 bytes: {x}", .{preview});
    }

    var subs = template_processor.SubstitutionArray.parseWithDeclarations(allocator, block, pos) catch |err| {
        std.log.err("Failed to parse substitution array at pos {d}: {any}", .{ pos - offset, err });

        // Log more details about the failure
        if (pos + 4 <= block.getSize()) {
            const count = try block.unpackDword(pos);
            std.log.err("Count at position would be: {d} (0x{x})", .{ count, count });
        }

        return try allocator.dupe(u8, "<Event><!-- Failed to parse substitutions --></Event>");
    };
    defer subs.deinit();

    std.log.info("Parsed {d} substitutions successfully", .{subs.entries.len});

    // Fetch template
    const template_opt = chunk.getTemplate(template_id) catch null;
    if (template_opt == null) {
        std.log.warn("Template {d} not found", .{template_id});
        return try allocator.dupe(u8, "<Event><!-- Template not found --></Event>");
    }

    const template = template_opt.?;

    std.log.info("Template XML format length: {d}", .{template.xml_format.len});
    std.log.debug("Template XML: {s}", .{template.xml_format});

    // Apply substitutions
    var processor = template_processor.SubstitutionProcessor.init(allocator, template.xml_format, &subs);
    const result = try processor.process();

    std.log.info("Result after substitution: {s}", .{result});
    return result;
}

// Parse a complete binary XML template and return XML string with substitution placeholders
pub fn parseTemplateXml(allocator: Allocator, block: *Block, offset: u32, length: u32, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError![]u8 {
    // Note: offset is block-relative (e.g., 574 for template data at chunk offset 0x1000 + 574)
    std.log.info("Parsing template XML at block-relative offset {d} with length {d}", .{ offset, length });
    var output = std.ArrayList(u8).init(allocator);
    errdefer output.deinit();

    // Use a temporary arena for node allocations so they don't leak
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temp_allocator = arena.allocator();

    const writer = output.writer();
    var pos: usize = offset; // pos is block-relative throughout parsing
    const end_pos: usize = offset + length;

    var element_stack = std.ArrayList([]const u8).init(allocator);
    defer element_stack.deinit();

    var node_count: u32 = 0;
    var depth: u32 = 0;

    // Parse the complete hierarchical structure
    while (pos < end_pos) {
        const node = BXmlNode.parse(temp_allocator, block, &pos, chunk) catch |err| {
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
            .entity_reference => |entity| {
                try entity.toXml(allocator, writer);
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
