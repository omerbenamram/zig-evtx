const std = @import("std");

// Shared BinXML types and helpers. Keep renderer-free to avoid cycles.

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

    // Array types (0x80 | base_type)
    string_array = 0x81,
    ansi_string_array = 0x82,
    int8_array = 0x83,
    uint8_array = 0x84,
    int16_array = 0x85,
    uint16_array = 0x86,
    int32_array = 0x87,
    uint32_array = 0x88,
    int64_array = 0x89,
    uint64_array = 0x8a,
    real32_array = 0x8b,
    real64_array = 0x8c,
    bool_array = 0x8d,
    binary_array = 0x8e,
    guid_array = 0x8f,
    size_t_array = 0x90,
    filetime_array = 0x91,
    systime_array = 0x92,
    sid_array = 0x93,
    hex_int32_array = 0x94,
    hex_int64_array = 0x95,
    evt_handle_array = 0xa0,
    bin_xml_array = 0xa1,
    evt_xml_array = 0xa3,

    pub const ARRAY_FLAG = 0x80;

    pub fn isArray(self: ValueType) bool {
        return @intFromEnum(self) & ARRAY_FLAG != 0;
    }

    pub fn baseType(self: ValueType) ValueType {
        const val = @intFromEnum(self) & 0x7F;
        return std.meta.intToEnum(ValueType, val) catch self;
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

pub fn valueTypeFixedSize(vtype: u8) ?usize {
    return switch (vtype) {
        0x03, // Int8
        0x04, // UInt8
        => 1,
        0x05, // Int16
        0x06, // UInt16
        => 2,
        0x07, // Int32
        0x08, // UInt32
        0x0d, // Bool (DWORD)
        0x14, // HexInt32
        => 4,
        0x09, // Int64
        0x0a, // UInt64
        0x0b, // Real32
        0x0c, // Real64
        0x11, // FILETIME
        0x15, // HexInt64
        => 8,
        0x0f, // GUID
        0x12, // SYSTEMTIME
        => 16,
        else => null,
    };
}

pub const ElementStartHeader = packed struct {
    dep_id: u16,
    data_size: u32,
};

pub const ElementStartHeaderNoDep = packed struct {
    data_size: u32,
};

pub const NameHeader = packed struct {
    next_offset: u32,
    hash: u16,
    num_chars: u16,
};

pub const SubstitutionToken = packed struct {
    id: u16,
    vtype: u8,
};

pub const CharRefToken = packed struct {
    value: u16,
};

pub const AttributeListHeader = packed struct {
    data_size: u32,
};

pub const TemplateDefinitionHeader = packed struct {
    next_offset: u32,
    guid_1: u64,
    guid_2: u64,
    data_size: u32,
};

// Plain struct: GUIDs are read as raw bytes via std.mem.readInt in callers.
pub const GuidBytes = struct {
    bytes: [16]u8,
};

pub const NameLengthHeader = packed struct {
    len: u16,
};

pub const ValueTokenHeader = packed struct {
    token: u8,
    vtype: u8,
};

pub const SubstitutionHeader = packed struct {
    token: u8,
    id: u16,
    vtype: u8,
};

pub const CharRefHeader = packed struct {
    token: u8,
    value: u16,
};

pub const TokenHeader = packed struct {
    token: u8,
};

pub const TemplateValuesCountHeader = packed struct {
    count: u32,
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
