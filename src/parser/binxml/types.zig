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

    /// Comptime helper to generate type checker functions.
    fn makeChecker(comptime expected: ValueType) fn (u8) bool {
        return struct {
            pub fn check(raw: u8) bool {
                return baseType(raw) == @intFromEnum(expected);
            }
        }.check;
    }

    // Comptime-generated type checkers for each variant
    pub const isNull = makeChecker(.null);
    pub const isString = makeChecker(.string);
    pub const isAnsiString = makeChecker(.ansi_string);
    pub const isInt8 = makeChecker(.int8);
    pub const isUint8 = makeChecker(.uint8);
    pub const isInt16 = makeChecker(.int16);
    pub const isUint16 = makeChecker(.uint16);
    pub const isInt32 = makeChecker(.int32);
    pub const isUint32 = makeChecker(.uint32);
    pub const isInt64 = makeChecker(.int64);
    pub const isUint64 = makeChecker(.uint64);
    pub const isReal32 = makeChecker(.real32);
    pub const isReal64 = makeChecker(.real64);
    pub const isBool = makeChecker(.bool);
    pub const isBinary = makeChecker(.binary);
    pub const isGuid = makeChecker(.guid);
    pub const isSizeT = makeChecker(.size_t);
    pub const isFiletime = makeChecker(.filetime);
    pub const isSystime = makeChecker(.systime);
    pub const isSid = makeChecker(.sid);
    pub const isHexInt32 = makeChecker(.hex_int32);
    pub const isHexInt64 = makeChecker(.hex_int64);
    pub const isEvtHandle = makeChecker(.evt_handle);
    pub const isBinXml = makeChecker(.bin_xml);
    pub const isEvtXml = makeChecker(.evt_xml);

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

    /// Returns the fixed byte size for a raw type byte, or null if variable-length.
    /// Use this when working with raw u8 type codes from binary data.
    pub fn fixedSizeFromRaw(vtype: u8) ?usize {
        const vt = std.meta.intToEnum(ValueType, baseType(vtype)) catch return null;
        return vt.fixedSize();
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

    /// Reads a TemplateDefinitionHeader from bytes at the given offset.
    pub fn read(chunk: []const u8, offset: usize) TemplateDefinitionHeader {
        return .{
            .next_offset = std.mem.readInt(u32, chunk[offset..][0..4], .little),
            .guid = chunk[offset + 4 ..][0..16].*,
            .data_size = std.mem.readInt(u32, chunk[offset + 20 ..][0..4], .little),
        };
    }
};

/// Zero-bit mixin for vtype proxy methods.
/// Access via the `vt` field: `header.vt.isBinXml()`
pub fn VTypeMixin(comptime T: type) type {
    return struct {
        pub fn isBinXml(self: *const @This()) bool {
            const parent: *const T = @fieldParentPtr("vt", self);
            return ValueType.isBinXml(parent.vtype);
        }
        pub fn isNull(self: *const @This()) bool {
            const parent: *const T = @fieldParentPtr("vt", self);
            return ValueType.isNull(parent.vtype);
        }
        pub fn isArray(self: *const @This()) bool {
            const parent: *const T = @fieldParentPtr("vt", self);
            return ValueType.isArray(parent.vtype);
        }
        pub fn baseType(self: *const @This()) u8 {
            const parent: *const T = @fieldParentPtr("vt", self);
            return ValueType.baseType(parent.vtype);
        }
        pub fn valueType(self: *const @This()) ?ValueType {
            const parent: *const T = @fieldParentPtr("vt", self);
            return std.meta.intToEnum(ValueType, ValueType.baseType(parent.vtype)) catch null;
        }
    };
}

pub const ValueTokenHeader = struct {
    token: u8,
    vtype: u8,
    vt: VTypeMixin(ValueTokenHeader) = .{},

    pub const binary_size: usize = 2;
};

pub const SubstitutionHeader = struct {
    token: u8,
    id: u16,
    vtype: u8,
    vt: VTypeMixin(SubstitutionHeader) = .{},

    pub const binary_size: usize = 4;
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
