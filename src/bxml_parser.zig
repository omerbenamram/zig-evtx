const std = @import("std");
const Allocator = std.mem.Allocator;
const Block = @import("binary_parser.zig").Block;
const BinaryParserError = @import("binary_parser.zig").BinaryParserError;
const VariantTypeNode = @import("variant_types.zig").VariantTypeNode;
const views = @import("views.zig");
const tokens = @import("tokens.zig");
const BXmlToken = tokens.BXmlToken;
pub const BinaryXMLError = tokens.BinaryXMLError;

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

        std.log.debug("Token: {s}, has_more: {any}", .{ tokens.getTokenName(token_byte), has_more });
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

    pub fn toXml(
        self: BXmlNode,
        allocator: Allocator,
        writer: anytype,
        subs: ?*const @import("template_processor.zig").SubstitutionArray,
    ) anyerror!void {
        switch (self) {
            .end_of_stream => {},
            .open_start_element => |node| try node.toXml(allocator, writer),
            .close_start_element => try writer.writeAll(">"),
            .close_empty_element => try writer.writeAll("/>"),
            .close_element => {}, // Handled by element tracking
            .value => |node| try node.toXml(allocator, writer),
            .attribute => |node| try node.toXml(allocator, writer, subs),
            .cdata_section => |node| try node.toXml(allocator, writer),
            .entity_reference => |node| try node.toXml(allocator, writer),
            .char_reference => |node| try node.toXml(allocator, writer),
            .template_instance => {}, // Not rendered directly
            .normal_substitution, .conditional_substitution => |node| {
                const s = subs orelse return error.SubstitutionWithoutValues;
                node.toXml(allocator, writer, s) catch |err| switch (err) {
                    BinaryXMLError.SuppressConditionalSubstitution => {},
                    else => return err,
                };
            },
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
        std.log.debug("OpenStartElementNode.parse: starting at pos {d}, has_more={any}", .{ start_pos, has_more });

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

        // Some producers store the element name as an inline NameString node
        // immediately after the header. When the string_offset points inside
        // the current template, skip over the inline string to keep parsing
        // aligned with the Python implementation.
        if (chunk) |_| {
            const start_relative = start_pos;
            if (string_offset > start_relative and string_offset < start_relative + size and string_offset + 8 <= block.getSize()) {
                const str_len = block.unpackWord(string_offset + 6) catch 0;
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

        // According to the EVTX spec (see lines 418–432 of
        // `Windows XML Event Log (EVTX).asciidoc`), a start element
        // with the "has more" flag set is followed by an attribute list
        // structure.  The documentation states this list begins with a
        // 4‑byte size field, then an array of Attribute tokens.  The
        // reference Python parser (see `Evtx/Nodes.py` in
        // `OpenStartElementNode.__init__`) does **not** read such a
        // size; it simply starts parsing the next tokens and relies on
        // them to delineate the attributes.  Real-world logs show both
        // behaviours, so we peek at the next dword and only treat it as
        // a size when it doesn't look like an Attribute token.
        if (has_more) {
            // Some logs include a 4-byte attribute list size while others omit it.
            // Read the next dword but only consume it when the high three bytes
            // are non-zero (indicating a real size rather than the start of an
            // Attribute token).
            const maybe_size = try block.unpackDword(pos.*);
            const first_byte: u8 = @as(u8, @truncate(maybe_size));
            const as_token = BXmlToken.fromByte(first_byte);
            if ((maybe_size & 0xFFFFFF00) == 0 and as_token != null and as_token.? == .Attribute) {
                std.log.debug("  Attribute list size not present", .{});
            } else {
                pos.* += 4;
                std.log.debug("  Attribute list size: {d} bytes", .{maybe_size});
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

        // The attribute value may either be encoded as a standard BXML node
        // (Value/Substitution/etc) or directly as a variant type without a
        // preceding token. Peek at the next byte to determine how to decode it.
        const start_byte = try block.unpackByte(pos.*);
        var value_node: BXmlNode = undefined;

        if (BXmlToken.fromByte(start_byte)) |tok| {
            switch (tok) {
                .Value => {
                    pos.* += 1;
                    const val = try ValueNode.parse(allocator, block, pos);
                    value_node = .{ .value = val };
                },
                .NormalSubstitution => {
                    pos.* += 1;
                    const sub = try SubstitutionNode.parse(allocator, block, pos, false);
                    value_node = .{ .normal_substitution = sub };
                },
                .ConditionalSubstitution => {
                    pos.* += 1;
                    const sub = try SubstitutionNode.parse(allocator, block, pos, true);
                    value_node = .{ .conditional_substitution = sub };
                },
                .CharRef => {
                    pos.* += 1;
                    const cref = try CharRefNode.parse(allocator, block, pos);
                    value_node = .{ .char_reference = cref };
                },
                .EntityReference => {
                    pos.* += 1;
                    const eref = try EntityReferenceNode.parse(allocator, block, pos, chunk);
                    value_node = .{ .entity_reference = eref };
                },
                else => {
                    // Not a recognised attribute value token - treat the byte as
                    // a variant type.
                    const variant_type = start_byte;
                    pos.* += 1;
                    const variant = try VariantTypeNode.parseWithType(allocator, block, pos, variant_type);
                    value_node = .{ .value = .{ .value_type = variant_type, .value_data = variant } };
                },
            }
        } else {
            // Direct variant type without a token
            const variant_type = start_byte;
            pos.* += 1;
            const variant = try VariantTypeNode.parseWithType(allocator, block, pos, variant_type);
            value_node = .{ .value = .{ .value_type = variant_type, .value_data = variant } };
        }

        const node_ptr = try allocator.create(BXmlNode);
        node_ptr.* = value_node;

        return AttributeNode{
            .name = name,
            .value_node = node_ptr,
        };
    }

    pub fn toXml(
        self: AttributeNode,
        allocator: Allocator,
        writer: anytype,
        subs: ?*const @import("template_processor.zig").SubstitutionArray,
    ) !void {
        try writer.print(" {s}=\"", .{self.name.string});
        try self.value_node.toXml(allocator, writer, subs);
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

    pub fn toXml(
        self: SubstitutionNode,
        allocator: Allocator,
        writer: anytype,
        subs: *const @import("template_processor.zig").SubstitutionArray,
    ) anyerror!void {
        if (self.index >= subs.entries.len) return BinaryXMLError.InvalidData;
        const variant = &subs.entries[self.index];
        if (self.is_conditional and variant.tag == .Null) {
            return BinaryXMLError.SuppressConditionalSubstitution;
        }
        const raw = try variant.toString(allocator);
        defer allocator.free(raw);
        const escaped = try @import("views.zig").escapeXmlString(allocator, raw);
        defer allocator.free(escaped);
        try writer.writeAll(escaped);
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
        const slice = std.fmt.bufPrint(&buf, "&#x{X:0>4};", .{self.value}) catch {
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

    // Ensure the referenced template is available. If it's missing, attempt to
    // parse it from the provided offset (used for resident templates).
    if (chunk.templates == null) {
        chunk.loadTemplates() catch |err| {
            std.log.warn("Failed to load templates: {any}", .{err});
        };
    }
    if (chunk.templates) |*map| {
        const tmpl = chunk.parseTemplate(template_offset) catch |err| {
            std.log.warn("Failed to parse resident template {d}: {any}", .{ template_id, err });
            return BinaryXMLError.InvalidToken;
        };
        std.log.info("Parsed resident template {d} at offset {d}", .{ template_id, template_offset });

        if (try map.fetchPut(tmpl.template_id, tmpl)) |kv| {
            // Replace existing template and free old resources to avoid leaks
            var old_template = kv.value;
            old_template.deinit(chunk.allocator);
        }
    }

    // Check what comes next to determine if the record embeds an updated template
    const next_byte = try block.unpackByte(pos);

    if ((next_byte & 0x0f) == 0x00) {
        // EndOfStream token indicates a resident template immediately follows
        std.log.debug(
            "Found EndOfStream token 0x{x} at pos {d}, resident template follows",
            .{ next_byte, pos - offset },
        );
        pos += 4; // skip token and padding

        // Resident template header layout:
        //   dword template_id
        //   guid  template_guid
        //   dword data_length
        _ = try block.unpackDword(pos); // next_offset (unused)
        pos += 4;
        const res_template_id = try block.unpackDword(pos);
        pos += 4;
        // The GUID overlaps with the template_id. We've already read the first
        // 4 bytes as the ID, so skip the remaining 12 bytes here.
        _ = try block.unpackBinary(pos, 12);
        pos += 12;
        const data_length = try block.unpackDword(pos);
        pos += 4;

        std.log.debug("Resident template id={d} data_length={d}", .{ res_template_id, data_length });

        // Skip over the resident template data
        pos += data_length;
    } else {
        // No resident template - substitutions start immediately
        std.log.debug("No EndOfStream, substitutions start at pos {d}", .{pos - offset});
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
        std.log.debug("First 16 bytes: {any}", .{preview});
    }

    var subs = template_processor.SubstitutionArray.parseWithDeclarations(allocator, block, pos) catch |err| {
        std.log.err("Failed to parse substitution array at pos {d}: {any}", .{ pos - offset, err });

        // Log more details about the failure
        if (pos + 4 <= block.getSize()) {
            const count = try block.unpackDword(pos);
            std.log.err("Count at position would be: {d} (0x{x})", .{ count, count });
        }

        return BinaryXMLError.InvalidData;
    };
    defer subs.deinit();

    std.log.info("Parsed {d} substitutions successfully", .{subs.entries.len});

    // Fetch template
    const template_opt = chunk.getTemplate(template_id) catch null;
    if (template_opt == null) {
        std.log.warn("Template {d} not found", .{template_id});
        return BinaryXMLError.InvalidData;
    }

    const template = template_opt.?;

    // Apply substitutions using the template structure
    const result = template.structure.toXml(allocator, &subs) catch |err| {
        std.log.err("Failed to apply substitutions: {any}", .{err});
        return BinaryXMLError.InvalidData;
    };
    std.log.info("Result after substitution: {s}", .{result});
    return result;
}

// Import template processor types
const TemplateStructure = @import("template_processor.zig").TemplateStructure;

// Parse a complete binary XML template and return a structured representation
pub fn parseTemplateStructure(allocator: Allocator, block: *Block, offset: u32, length: u32, chunk: ?*const @import("evtx.zig").ChunkHeader) anyerror!TemplateStructure {
    // Note: offset is block-relative (e.g., 574 for template data at chunk offset 0x1000 + 574)
    std.log.info("Parsing template structure at block-relative offset {d} with length {d}", .{ offset, length });

    var nodes = std.ArrayList(BXmlNode).init(allocator);
    errdefer nodes.deinit();

    var pos: usize = offset;
    const end_pos: usize = offset + length;

    // Parse all nodes into the array
    try parseTemplateNodes(allocator, block, &pos, end_pos, chunk, &nodes, false);

    std.log.info("Parsed {d} nodes into template structure", .{nodes.items.len});

    // Create the template structure
    return TemplateStructure.init(allocator, nodes.items);
}

// Helper function to parse nodes into an array
fn parseTemplateNodes(
    allocator: Allocator,
    block: *Block,
    pos: *usize,
    end_pos: usize,
    chunk: ?*const @import("evtx.zig").ChunkHeader,
    nodes: *std.ArrayList(BXmlNode),
    in_stream: bool,
) anyerror!void {
    while (pos.* < end_pos) {
        const node = BXmlNode.parse(allocator, block, pos, chunk) catch |err| {
            std.log.warn("Failed to parse node at pos {d}: {any}", .{ pos.*, err });
            return err;
        };

        switch (node) {
            .start_of_stream => {
                try nodes.append(node);
                // Continue parsing the stream
                try parseTemplateNodes(allocator, block, pos, end_pos, chunk, nodes, true);
            },
            .end_of_stream => {
                try nodes.append(node);
                if (in_stream) {
                    return;
                } else {
                    continue;
                }
            },
            .template_instance => |inst| {
                // For nested templates, we need to handle them specially
                // For now, just add the node
                _ = inst;
                try nodes.append(node);
            },
            else => {
                try nodes.append(node);
            },
        }

        if (nodes.items.len > 10000) {
            std.log.warn("Parsed too many nodes, stopping", .{});
            return;
        }
    }
}

// Parse template XML - this now returns an error since we don't support placeholder rendering
pub fn parseTemplateXml(allocator: Allocator, block: *Block, offset: u32, length: u32, chunk: ?*const @import("evtx.zig").ChunkHeader) anyerror![]u8 {
    _ = allocator;
    _ = block;
    _ = offset;
    _ = length;
    _ = chunk;
    return error.NotImplemented; // Use parseTemplateStructure instead
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
    subs: ?*const @import("template_processor.zig").SubstitutionArray,
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
                try parseStream(allocator, temp_allocator, block, pos, end_pos, chunk, writer, element_stack, depth, node_count, subs);
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
                try attr.toXml(allocator, writer, subs);
            },
            .value => |val| {
                try val.toXml(allocator, writer);
            },
            .normal_substitution, .conditional_substitution => |sub| {
                const s = subs orelse return error.SubstitutionWithoutValues;
                sub.toXml(allocator, writer, s) catch |err| switch (err) {
                    BinaryXMLError.SuppressConditionalSubstitution => {},
                    else => return err,
                };
            },
            .entity_reference => |entity| {
                try entity.toXml(allocator, writer);
            },
            .char_reference => |charref| {
                try charref.toXml(allocator, writer);
            },
            .template_instance => |inst| {
                if (chunk) |c| {
                    var c_mut = @constCast(c);
                    var tmpl_opt = c_mut.getTemplate(inst.template_id) catch null;
                    if (tmpl_opt == null) {
                        if (c_mut.templates) |*map| {
                            // try parsing template at provided offset
                            const tmpl = c_mut.parseTemplate(inst.template_offset) catch null;
                            if (tmpl) |t| {
                                try map.put(t.template_id, t);
                                tmpl_opt = map.getPtr(t.template_id);
                            }
                        }
                    }
                    if (tmpl_opt) |tmpl| {
                        // We can't render templates without substitutions
                        if (subs) |s| {
                            // Apply the template structure with current substitutions
                            const result = tmpl.structure.toXml(allocator, s) catch |err| {
                                std.log.warn("Failed to render template {d}: {any}", .{ inst.template_id, err });
                                return;
                            };
                            defer allocator.free(result);
                            try writer.writeAll(result);
                        } else {
                            std.log.warn("Cannot render template {d} without substitutions", .{inst.template_id});
                        }
                    } else {
                        std.log.warn("Referenced template {d} not available", .{inst.template_id});
                    }
                }
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
