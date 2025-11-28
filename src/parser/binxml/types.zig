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

    /// Returns the fixed byte size for a raw type byte, or null if variable-length.
    /// Use this when working with raw u8 type codes from binary data.
    pub fn fixedSizeFromRaw(vtype: u8) ?usize {
        return switch (vtype & 0x7f) {
            0x03, 0x04 => 1,
            0x05, 0x06 => 2,
            0x07, 0x08, 0x0d, 0x14 => 4,
            0x09, 0x0a, 0x0b, 0x0c, 0x11, 0x15 => 8,
            0x0f, 0x12 => 16,
            else => null,
        };
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

pub const NameOffsetHeader = packed struct {
    offset: u32,
};

pub const TemplateInstanceStart = packed struct {
    token: u8,
    version: u8,
    template_id: u32,
    def_data_off: u32,
};
