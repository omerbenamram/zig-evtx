const std = @import("std");

/// Binary XML system tokens as defined in the EVTX specification
pub const BXmlToken = enum(u8) {
    EndOfStream = 0x00,
    OpenStartElement = 0x01,
    CloseStartElement = 0x02,
    CloseEmptyElement = 0x03,
    CloseElement = 0x04,
    Value = 0x05,
    Attribute = 0x06,
    CDataSection = 0x07,
    CharRef = 0x08,
    EntityReference = 0x09,
    ProcessingInstructionTarget = 0x0A,
    ProcessingInstructionData = 0x0B,
    TemplateInstance = 0x0C,
    NormalSubstitution = 0x0D,
    ConditionalSubstitution = 0x0E,
    StartOfStream = 0x0F,

    /// Extract token value from a byte, masking out flags
    pub fn fromByte(byte: u8) ?BXmlToken {
        const token_val = byte & 0x0F;
        return std.meta.intToEnum(BXmlToken, token_val) catch null;
    }

    /// Check if token byte has the "has more" flag set
    pub fn hasMoreFlag(byte: u8) bool {
        return (byte & 0x40) != 0;
    }

    /// Extract flags from token byte
    pub fn getFlags(byte: u8) u8 {
        return byte >> 4;
    }
};

/// Variant data types for EVTX values
pub const VariantType = enum(u8) {
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

/// Common error types for binary XML parsing
pub const BinaryXMLError = error{
    InvalidToken,
    InvalidData,
    UnexpectedEndOfStream,
    OutOfMemory,
    SuppressConditionalSubstitution,
    InvalidVariantType,
    UnexpectedEndOfFile,
    InvalidGuid,
    InvalidFiletime,
    InvalidSID,
    SubstitutionWithoutValues,
} || @import("binary_parser.zig").BinaryParserError;

/// Token names for debugging and logging
pub const token_names = [_][]const u8{
    "EndOfStream", // 0x00
    "OpenStartElement", // 0x01
    "CloseStartElement", // 0x02
    "CloseEmptyElement", // 0x03
    "CloseElement", // 0x04
    "Value", // 0x05
    "Attribute", // 0x06
    "CDataSection", // 0x07
    "CharRef", // 0x08
    "EntityReference", // 0x09
    "ProcessingInstructionTarget", // 0x0A
    "ProcessingInstructionData", // 0x0B
    "TemplateInstance", // 0x0C
    "NormalSubstitution", // 0x0D
    "ConditionalSubstitution", // 0x0E
    "StartOfStream", // 0x0F
};

/// Get human-readable name for a token
pub fn getTokenName(token: u8) []const u8 {
    const token_val = token & 0x0F;
    return if (token_val < token_names.len) token_names[token_val] else "Unknown";
}

test "BXmlToken from byte parsing" {
    const testing = std.testing;

    // Test basic token extraction
    try testing.expect(BXmlToken.fromByte(0x01).? == BXmlToken.OpenStartElement);
    try testing.expect(BXmlToken.fromByte(0x41).? == BXmlToken.OpenStartElement); // with flags
    try testing.expect(BXmlToken.fromByte(0x0F).? == BXmlToken.StartOfStream);

    // Test flags
    try testing.expect(BXmlToken.hasMoreFlag(0x41) == true);
    try testing.expect(BXmlToken.hasMoreFlag(0x01) == false);
    try testing.expect(BXmlToken.getFlags(0x41) == 0x04);
}
