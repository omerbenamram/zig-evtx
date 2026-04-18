const std = @import("std");

// Shared BinXML types and helpers. Keep renderer-free to avoid cycles.

/// Returns binary size of T. Uses T.binary_size if defined, else @sizeOf.
/// This handles types with alignment padding (like TemplateDefinitionHeader)
/// where @sizeOf doesn't match the binary layout.
pub fn binarySize(comptime T: type) usize {
    return if (@hasDecl(T, "binary_size")) T.binary_size else @sizeOf(T);
}

pub const ValueType = enum(u8) {
    null = 0x00,
    string = 0x01,
    ansi_string = 0x02,
    int8 = 0x03,
    uint8 = 0x04,
    int16 = 0x05,
    uint16 = 0x06,
    int32 = 0x07,
    uint32 = 0x08,
    int64 = 0x09,
    uint64 = 0x0a,
    real32 = 0x0b,
    real64 = 0x0c,
    bool = 0x0d,
    binary = 0x0e,
    guid = 0x0f,
    size_t = 0x10,
    filetime = 0x11,
    systime = 0x12,
    sid = 0x13,
    hex_int32 = 0x14,
    hex_int64 = 0x15,
    evt_handle = 0x20,
    bin_xml = 0x21,
    evt_xml = 0x23,

    // Array types use ARRAY_FLAG (0x80) | base_type - no explicit enum variants needed
    pub const ARRAY_FLAG: u8 = 0x80;

    /// Extracts the base type by masking off the array flag.
    pub fn baseType(raw: u8) u8 {
        return raw & ~ARRAY_FLAG;
    }

    /// Check if a raw type byte has the array flag set.
    pub fn isArray(raw: u8) bool {
        return (raw & ARRAY_FLAG) != 0;
    }

    /// True if the raw type byte (after stripping the array flag) matches
    /// `expected`. Replaces 24 individual comptime-generated checker
    /// functions; only `isBinXml`/`isNull` are kept as named aliases for
    /// readability at the call sites that actually use them.
    pub fn is(comptime expected: ValueType, raw: u8) bool {
        return baseType(raw) == @intFromEnum(expected);
    }

    pub fn isNull(raw: u8) bool {
        return is(.null, raw);
    }

    pub fn isBinXml(raw: u8) bool {
        return is(.bin_xml, raw);
    }

    /// Returns the fixed byte size for this value type, or null if variable-length.
    pub fn fixedSize(self: ValueType) ?usize {
        return switch (self) {
            .int8, .uint8 => 1,
            .int16, .uint16 => 2,
            .int32, .uint32, .bool, .hex_int32 => 4,
            .int64, .uint64, .real32, .real64, .filetime, .hex_int64 => 8,
            .guid, .systime => 16,
            // Variable-length types
            .null, .string, .ansi_string, .binary, .sid, .size_t, .evt_handle, .bin_xml, .evt_xml => null,
        };
    }

    /// Returns the fixed byte size for a raw type byte, or null if
    /// variable-length / unknown. Uses `std.enums.fromInt` to validate
    /// the byte falls within `ValueType`, then defers to `fixedSize`.
    pub fn fixedSizeFromRaw(vtype: u8) ?usize {
        const base = baseType(vtype);
        const tag = std.enums.fromInt(ValueType, base) orelse return null;
        return tag.fixedSize();
    }
};

pub const FragmentHeader = packed struct {
    token: u8,
    major_version: u8,
    minor_version: u8,
    flags: u8,
};

pub const ValueDescriptor = packed struct {
    size: u16,
    value_type: ValueType,
    unknown: u8,
};

pub const TemplateValue = struct {
    t: u8,
    data: []const u8,
};

pub const NameHeader = packed struct {
    next_offset: u32,
    hash: u16,
    num_chars: u16,
};

pub const AttributeListHeader = packed struct {
    data_size: u32,
};

/// Template definition header in BinXML format.
/// Binary layout: next_offset(4) + guid(16) + data_size(4) = 24 bytes
/// Note: @sizeOf returns 32 due to alignment padding - always use binary_size.
pub const TemplateDefinitionHeader = struct {
    next_offset: u32,
    guid: [16]u8,
    data_size: u32,

    pub const binary_size: usize = 24;
};

pub const ValueTokenHeader = struct {
    token: u8,
    vtype: u8,

    pub const binary_size: usize = 2;

    pub fn isBinXml(self: ValueTokenHeader) bool {
        return ValueType.isBinXml(self.vtype);
    }
    pub fn isNull(self: ValueTokenHeader) bool {
        return ValueType.isNull(self.vtype);
    }
    pub fn isArray(self: ValueTokenHeader) bool {
        return ValueType.isArray(self.vtype);
    }
    pub fn baseType(self: ValueTokenHeader) u8 {
        return ValueType.baseType(self.vtype);
    }
    pub fn valueType(self: ValueTokenHeader) ?ValueType {
        return std.enums.fromInt(ValueType, ValueType.baseType(self.vtype));
    }
};

pub const SubstitutionHeader = struct {
    token: u8,
    id: u16,
    vtype: u8,

    pub const binary_size: usize = 4;

    pub fn isBinXml(self: SubstitutionHeader) bool {
        return ValueType.isBinXml(self.vtype);
    }
    pub fn isNull(self: SubstitutionHeader) bool {
        return ValueType.isNull(self.vtype);
    }
    pub fn isArray(self: SubstitutionHeader) bool {
        return ValueType.isArray(self.vtype);
    }
    pub fn baseType(self: SubstitutionHeader) u8 {
        return ValueType.baseType(self.vtype);
    }
    pub fn valueType(self: SubstitutionHeader) ?ValueType {
        return std.enums.fromInt(ValueType, ValueType.baseType(self.vtype));
    }
};

pub const CharRefHeader = packed struct {
    token: u8,
    value: u16,
};

pub const TokenHeader = packed struct {
    token: u8,
};

pub const NameOffsetHeader = packed struct {
    offset: u32,
};

pub const TemplateInstanceStart = packed struct {
    token: u8,
    version: u8,
    template_id: u32,
    def_data_off: u32,
};
