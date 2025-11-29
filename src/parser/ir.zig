const std = @import("std");

/// Intermediate Representation for parsed BinXML.
///
/// The IR represents XML element trees. Template definitions (cached as `Template`)
/// may contain `Placeholder` nodes marking substitution sites. When instantiated,
/// these become `ElementTree` which is guaranteed to have no placeholders.
///
/// Memory: All IR nodes reference slices into the chunk buffer where possible
/// (names, value bytes). Element nodes are allocated in a per-chunk arena.
pub const IR = struct {
    /// Pre-converted UTF-8 name, ready for direct output without escaping.
    ///
    /// ## Why No Escaping?
    ///
    /// Element and attribute names in XML follow the NCName (non-colonized name)
    /// production, which restricts them to: `[a-zA-Z_][a-zA-Z0-9_.-]*`
    ///
    /// This means names **cannot contain** characters that require escaping:
    /// - No `&`, `<`, `>`, `"`, `'` (XML special chars)
    /// - No `\` (JSON escape char)
    /// - No control characters
    /// - No spaces
    ///
    /// Therefore, pre-converted UTF-8 names can be written directly to output
    /// without any escaping pass - they are safe by definition.
    ///
    /// ## Performance
    ///
    /// Names are converted once at parse time in `Context.getOrReadName()`,
    /// then shared across all IR nodes that reference the same name via
    /// template cloning. This eliminates repeated UTF-16→UTF-8 conversion
    /// during rendering.
    pub const Name = struct { utf8: []const u8 };

    pub const NodeTag = enum { Element, Text, Value, Placeholder, CharRef, EntityRef, CData, PITarget, PIData };

    /// Payload types for each node variant
    pub const TextPayload = struct { utf16: []const u8, num_chars: usize };
    pub const ValuePayload = struct { vtype: u8, bytes: []const u8 };

    /// Placeholder for template substitution sites.
    /// Only exists in cached Template structures, never in final ElementTree output.
    pub const PlaceholderPayload = struct {
        id: u16,
        vtype: u8,
        optional: bool,
    };

    /// Tagged union for IR nodes.
    /// Placeholder variant only appears in cached templates, not in final output.
    pub const Node = union(NodeTag) {
        Element: *Element,
        Text: TextPayload,
        Value: ValuePayload,
        Placeholder: PlaceholderPayload,
        CharRef: u16,
        EntityRef: Name,
        CData: TextPayload,
        PITarget: Name,
        PIData: TextPayload,
    };

    pub const Attr = struct {
        name: Name,
        // Flat token list allowed in attribute contexts
        value: std.ArrayList(Node),
    };

    pub const Element = struct {
        name: Name,
        attrs: std.ArrayList(Attr),
        children: std.ArrayList(Node),
        has_element_child: bool = false,
    };
};

pub fn irNewElement(allocator: std.mem.Allocator, name: IR.Name) !*IR.Element {
    const el = try allocator.create(IR.Element);
    el.* = .{ .name = name, .attrs = .empty, .children = .empty };
    return el;
}
