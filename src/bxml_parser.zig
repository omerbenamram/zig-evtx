const std = @import("std");
const Allocator = std.mem.Allocator;
const Block = @import("binary_parser.zig").Block;
const BinaryParserError = @import("binary_parser.zig").BinaryParserError;
const VariantTypeNode = @import("variant_types.zig").VariantTypeNode;
const views = @import("views.zig");
const tokens = @import("tokens.zig");
const BXmlToken = tokens.BXmlToken;
const BinaryXMLError = tokens.BinaryXMLError;

pub const BXmlNode = union(enum) {
    end_of_stream: void,
    open_start_element: OpenStartElementNode,
    close_start_element: void,
    close_empty_element: void,
    close_element: void,
    value: ValueNode,
    attribute: AttributeNode,
    cdata_section: CDataSectionNode,
    char_reference: CharRefNode,
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
                const flags = BXmlToken.getFlags(token_byte);
                const node = try OpenStartElementNode.parse(allocator, block, pos, has_more, flags, chunk);
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
                const node = try CharRefNode.parse(allocator, block, pos);
                return BXmlNode{ .char_reference = node };
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

    pub fn toXml(self: BXmlNode, allocator: Allocator, writer: anytype) anyerror!void {
        switch (self) {
            .end_of_stream => {},
            .open_start_element => |node| try node.toXml(allocator, writer),
            .close_start_element => try writer.writeAll(">"),
            .close_empty_element => try writer.writeAll("/>"),
            .close_element => {}, // Handled by element tracking
            .value => |node| try node.toXml(allocator, writer),
            .attribute => |node| try node.toXml(allocator, writer),
            .cdata_section => |node| try node.toXml(allocator, writer),
            .entity_reference => |node| try node.toXml(allocator, writer),
            .char_reference => |node| try node.toXml(allocator, writer),
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

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize, has_more: bool, flags: u8, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError!OpenStartElementNode {

        // Remember start of this node relative to the block
        const start_pos = pos.*;
        std.log.debug("OpenStartElementNode.parse: starting at pos {d}, has_more={}", .{ start_pos, has_more });

        // Read unknown0 (2 bytes)
        const unknown0 = try block.unpackWord(pos.*);
        pos.* += 2;

        // Older revisions attempted to detect a special ROOT marker here and
        // hard-code the element name. This caused subtle misalignment issues
        // when additional attributes were present. The real EVTX format simply
        // encodes the element name in the normal string table, so parse it
        // generically instead of injecting a placeholder.

        // Read size (4 bytes)
        const size = try block.unpackDword(pos.*);
        pos.* += 4;

        // Read string_offset (4 bytes)
        const string_offset = try block.unpackDword(pos.*);
        pos.* += 4;

        // Optional dependency ID if flag 0x04 is set
        if (flags & 0x04 != 0) {
            _ = try block.unpackDword(pos.*);
            pos.* += 4;
        }

        // Skip inline name string if the string offset points inside the template
        if (chunk) |_| {
            const start_relative = start_pos;
            if (string_offset > start_relative) {
                // Inline NameString node
                const str_len = try block.unpackWord(string_offset + 6);
                const inline_len = 10 + (@as(usize, str_len) * 2);
                if (string_offset + inline_len > pos.*) {
                    pos.* = string_offset + inline_len;
                }
            }
        }

        std.log.debug("  unknown0: 0x{x:0>4}, size: {d}, string_offset: {d} (0x{x:0>8})", .{ unknown0, size, string_offset, string_offset });

        // Resolve the element name from string table
        const resolved_string = NameNode.resolveString(allocator, string_offset, chunk);
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
            // When "has_more" is set, an attribute list follows this element
            // header.  Some producers insert a 4-byte size for that list, while
            // others omit it and immediately start with an Attribute token. To
            // detect which form we're dealing with, peek at the next byte and
            // decode it as a token. If it represents an Attribute, no size field
            // is present and we continue parsing attributes directly. Otherwise
            // treat those bytes as the attribute list size.
            const peek = try block.unpackByte(pos.*);
            const peek_token = BXmlToken.fromByte(peek);
            if (peek_token != null and peek_token.? == .Attribute) {
                std.log.debug("  Attribute list size not present", .{});
            } else {
                const attr_list_size = try block.unpackDword(pos.*);
                pos.* += 4;
                std.log.debug("  Attribute list size: {d} bytes", .{attr_list_size});
            }
        }

        // Previous implementations attempted to skip inline name strings here,
        // but that caused misalignment when attribute lists were present.
        // Allow the parser to naturally consume any inline string tokens.

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
        const raw = try self.value_data.toString(allocator);
        defer allocator.free(raw);
        const escaped = try views.escapeXmlString(allocator, raw);
        defer allocator.free(escaped);
        try writer.writeAll(escaped);
    }
};

pub const AttributeNode = struct {
    name: NameNode,
    value_node: *BXmlNode,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError!AttributeNode {
        const name = try NameNode.parse(allocator, block, pos, chunk);
        // Attribute values are encoded as their own BXML node
        // (typically a Value node or substitution). Parse the next
        // node to obtain the attribute's value.
        const node_ptr = try allocator.create(BXmlNode);
        node_ptr.* = try BXmlNode.parse(allocator, block, pos, chunk);

        return AttributeNode{
            .name = name,
            .value_node = node_ptr,
        };
    }

    pub fn toXml(self: AttributeNode, allocator: Allocator, writer: anytype) !void {
        try writer.print(" {s}=\"", .{self.name.string});
        try self.value_node.toXml(allocator, writer);
        try writer.writeAll("\"");
    }
};

pub const NameNode = struct {
    string_offset: ?u32,
    string: []const u8,

    // For OpenStartElement - just parse string offset (4 bytes)
    pub fn parseForElement(allocator: Allocator, block: *Block, pos: *usize, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError!NameNode {
        const string_offset = try block.unpackDword(pos.*);
        pos.* += 4;

        std.log.debug("NameNode (element): string_offset={d} (0x{x:0>8})", .{ string_offset, string_offset });

        const resolved_string = resolveString(allocator, string_offset, chunk);

        return NameNode{
            .string_offset = string_offset,
            .string = resolved_string,
        };
    }

    // For attributes - parse string offset (4 bytes)
    pub fn parse(allocator: Allocator, block: *Block, pos: *usize, chunk: ?*const @import("evtx.zig").ChunkHeader) BinaryXMLError!NameNode {
        // NameNode structure for attributes simply stores a dword string offset
        const string_offset = try block.unpackDword(pos.*);
        pos.* += 4;

        std.log.debug("NameNode (attribute): string_offset={d} (0x{x:0>8})", .{ string_offset, string_offset });

        const resolved_string = resolveString(allocator, string_offset, chunk);

        return NameNode{
            .string_offset = string_offset,
            .string = resolved_string,
        };
    }

    // Helper function to resolve strings from chunk string table
    fn resolveString(allocator: Allocator, string_offset: u32, chunk: ?*const @import("evtx.zig").ChunkHeader) []const u8 {
        if (chunk) |c| {
            var c_mut = @constCast(c);
            if (string_offset < c.nextRecordOffset()) {
                const lookup = c_mut.getStringAtOffset(string_offset);
                if (lookup) |maybe| {
                    if (maybe) |str| return str;
                } else |err| {
                    std.log.debug("String lookup error: {any}", .{err});
                }
                if (readInlineString(allocator, c, string_offset)) |str| {
                    return str;
                }
                std.log.debug("String offset {d} unresolved in chunk", .{string_offset});
            } else {
                std.log.debug("String offset {d} out of bounds", .{string_offset});
            }
        } else {
            std.log.debug("resolveString called with null chunk for offset {d}", .{string_offset});
        }
        return "UnknownElement";
    }
};

// Helper function to read inline strings
fn readInlineString(allocator: Allocator, chunk: *const @import("evtx.zig").ChunkHeader, offset: u32) ?[]const u8 {
    const block = chunk.block;
    const length = block.unpackWord(offset + 0x06) catch return null;
    const utf8_string = block.unpackWstring(allocator, offset + 0x08, length) catch return null;
    return utf8_string;
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
        // CDataSection is followed by a string
        const string_len = try block.unpackWord(pos.*);
        pos.* += 2;

        const utf8_text = try block.unpackWstring(allocator, pos.*, string_len);
        pos.* += string_len * 2;

        // Align to 4-byte boundary (padding after CDATA)
        const consumed = 2 + string_len * 2;
        const padding = @as(usize, (4 - (consumed % 4)) % 4);
        if (pos.* + padding <= block.getSize()) {
            pos.* += padding;
        }

        return CDataSectionNode{
            .text = utf8_text,
        };
    }

    pub fn toXml(self: CDataSectionNode, allocator: Allocator, writer: anytype) !void {
        _ = allocator;
        try writer.writeAll("<![CDATA[");
        try writer.writeAll(self.text);
        try writer.writeAll("]]>");
    }
};

pub const CharRefNode = struct {
    /// Unicode code point referenced by the char ref. According to the
    /// EVTX specification this is stored as a 32-bit value.
    value: u32,

    pub fn parse(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!CharRefNode {
        _ = allocator;
        // CharRef uses a 4-byte little endian code point. The previous
        // implementation only consumed a 16-bit value which caused
        // misalignment and truncated templates.
        const val = try block.unpackDword(pos.*);
        pos.* += 4;
        return CharRefNode{ .value = val };
    }

    pub fn toXml(self: CharRefNode, allocator: Allocator, writer: anytype) BinaryXMLError!void {
        _ = allocator;
        var buf: [12]u8 = undefined;
        const slice = std.fmt.bufPrint(&buf, "&#x{X};", .{self.value}) catch {
            return BinaryXMLError.OutOfMemory;
        };
        try writer.writeAll(slice);
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
pub fn parseTemplateXml(allocator: Allocator, block: *Block, offset: u32, length: u32, chunk: ?*const @import("evtx.zig").ChunkHeader) anyerror![]u8 {
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

    try parseStream(allocator, temp_allocator, block, &pos, end_pos, chunk, writer, &element_stack, &depth, &node_count);

    // Some templates omit explicit close element tokens. Close any
    // remaining open elements to keep the XML well-formed so further
    // processing matches the Python output.
    while (true) {
        const maybe = element_stack.pop();
        if (maybe) |name| {
            try writer.print("</{s}>", .{name});
        } else break;
    }

    std.log.info("Parsed {d} nodes, output length: {d}, final depth: {d}", .{ node_count, output.items.len, depth });
    return output.toOwnedSlice();
}

fn parseStream(
    allocator: Allocator,
    temp_allocator: Allocator,
    block: *Block,
    pos: *usize,
    end_pos: usize,
    chunk: ?*const @import("evtx.zig").ChunkHeader,
    writer: anytype,
    element_stack: *std.ArrayList([]const u8),
    depth: *u32,
    node_count: *u32,
) anyerror!void {
    while (pos.* < end_pos) {
        const node = BXmlNode.parse(temp_allocator, block, pos, chunk) catch |err| {
            std.log.warn("Failed to parse node at pos {d}: {any}", .{ pos.*, err });
            return err;
        };
        node_count.* += 1;

        switch (node) {
            .start_of_stream => {
                std.log.debug("Parsed StartOfStream", .{});
                depth.* += 1;
                try parseStream(allocator, temp_allocator, block, pos, end_pos, chunk, writer, element_stack, depth, node_count);
                depth.* -= 1;
            },
            .end_of_stream => {
                std.log.debug("Parsed EndOfStream at depth {d}", .{depth.*});
                return;
            },
            .open_start_element => |elem| {
                try elem.toXml(allocator, writer);
                try element_stack.append(elem.name.string);
                depth.* += 1;
                std.log.debug("Opened element '{s}', depth now {d}", .{ elem.name.string, depth.* });
            },
            .close_start_element => {
                try writer.writeAll(">");
                std.log.debug("Closed start element tag", .{});
            },
            .close_empty_element => {
                try writer.writeAll("/>");
                if (element_stack.items.len > 0) {
                    _ = element_stack.pop();
                    depth.* -= 1;
                    std.log.debug("Closed empty element, depth now {d}", .{depth.*});
                }
            },
            .close_element => {
                if (element_stack.items.len > 0) {
                    const elem_name = element_stack.pop() orelse unreachable;
                    depth.* -= 1;
                    try writer.print("</{s}>", .{elem_name});
                    std.log.debug("Closed element '{s}', depth now {d}", .{ elem_name, depth.* });
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
            .char_reference => |charref| {
                try charref.toXml(allocator, writer);
            },
            else => {
                std.log.debug("Unhandled node type in XML generation", .{});
            },
        }

        if (node_count.* > 10000) {
            std.log.warn("Parsed too many nodes, stopping", .{});
            return;
        }
    }
}
