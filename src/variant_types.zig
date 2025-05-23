const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const binary_parser = @import("binary_parser.zig");
const Block = binary_parser.Block;
const BinaryParserError = binary_parser.BinaryParserError;

pub const BinaryXMLError = error{
    InvalidVariantType,
    OutOfMemory,
    UnexpectedEndOfFile,
    InvalidGuid,
    InvalidFiletime,
    InvalidSID,
} || BinaryParserError;

// Unified variant data union for all data types
pub const VariantData = union(enum) {
    Null: void,
    WString: []const u8,
    String: []const u8,
    SignedByte: i8,
    UnsignedByte: u8,
    SignedWord: i16,
    UnsignedWord: u16,
    SignedDword: i32,
    UnsignedDword: u32,
    SignedQword: i64,
    UnsignedQword: u64,
    Real32: f32,
    Real64: f64,
    Boolean: bool,
    Binary: []const u8,
    GUID: []const u8,
    SizeT: []const u8,
    Filetime: u64,
    Systemtime: []const u8,
    SID: []const u8,
    HexInt32: []const u8,
    HexInt64: []const u8,
    BinXml: []const u8,
    WStringArray: []const u8,
};

// Unified variant type node
pub const VariantTypeNode = struct {
    tag: std.meta.Tag(VariantData),
    data: VariantData,

    const Self = @This();

    pub fn fromBinary(allocator: Allocator, block: *Block, pos: *usize) BinaryXMLError!Self {
        const variant_type = try block.unpackByte(pos.*);
        pos.* += 1;

        switch (variant_type) {
            0x00 => return VariantTypeNode{ .tag = .Null, .data = VariantData{ .Null = {} } },
            0x01 => {
                // WString - null terminated UTF-16
                const wstring = try block.unpackWstringNullTerminated(allocator, pos.*);
                // Calculate actual bytes consumed: UTF-16 chars * 2 + 2 for null terminator
                var bytes_consumed: usize = 0;
                var check_pos = pos.*;
                while (check_pos + 1 < block.buf.len) : (check_pos += 2) {
                    const word = std.mem.readInt(u16, block.buf[check_pos..check_pos + 2][0..2], .little);
                    bytes_consumed += 2;
                    if (word == 0) break;
                }
                pos.* += bytes_consumed;
                return VariantTypeNode{ .tag = .WString, .data = VariantData{ .WString = wstring } };
            },
            0x02 => {
                // String - null terminated ASCII
                const string = try block.unpackStringNullTerminated(allocator, pos.*);
                // Calculate bytes consumed
                const bytes_consumed: usize = string.len + 1; // string + null terminator
                pos.* += bytes_consumed;
                return VariantTypeNode{ .tag = .String, .data = VariantData{ .String = string } };
            },
            0x03 => {
                const value = try block.unpackInt8(pos.*);
                pos.* += 1;
                return VariantTypeNode{ .tag = .SignedByte, .data = VariantData{ .SignedByte = value } };
            },
            0x04 => {
                const value = try block.unpackByte(pos.*);
                pos.* += 1;
                return VariantTypeNode{ .tag = .UnsignedByte, .data = VariantData{ .UnsignedByte = value } };
            },
            0x05 => {
                const value = try block.unpackInt16(pos.*);
                pos.* += 2;
                return VariantTypeNode{ .tag = .SignedWord, .data = VariantData{ .SignedWord = value } };
            },
            0x06 => {
                const value = try block.unpackWord(pos.*);
                pos.* += 2;
                return VariantTypeNode{ .tag = .UnsignedWord, .data = VariantData{ .UnsignedWord = value } };
            },
            0x07 => {
                const value = try block.unpackInt32(pos.*);
                pos.* += 4;
                return VariantTypeNode{ .tag = .SignedDword, .data = VariantData{ .SignedDword = value } };
            },
            0x08 => {
                const value = try block.unpackDword(pos.*);
                pos.* += 4;
                return VariantTypeNode{ .tag = .UnsignedDword, .data = VariantData{ .UnsignedDword = value } };
            },
            0x09 => {
                const value = try block.unpackInt64(pos.*);
                pos.* += 8;
                return VariantTypeNode{ .tag = .SignedQword, .data = VariantData{ .SignedQword = value } };
            },
            0x0A => {
                const value = try block.unpackQword(pos.*);
                pos.* += 8;
                return VariantTypeNode{ .tag = .UnsignedQword, .data = VariantData{ .UnsignedQword = value } };
            },
            0x0B => {
                const value = try block.unpackFloat(pos.*);
                pos.* += 4;
                return VariantTypeNode{ .tag = .Real32, .data = VariantData{ .Real32 = value } };
            },
            0x0C => {
                const value = try block.unpackDouble(pos.*);
                pos.* += 8;
                return VariantTypeNode{ .tag = .Real64, .data = VariantData{ .Real64 = value } };
            },
            0x0D => {
                const value = try block.unpackByte(pos.*);
                pos.* += 1;
                return VariantTypeNode{ .tag = .Boolean, .data = VariantData{ .Boolean = value != 0 } };
            },
            0x0E => {
                const bytes = try block.unpackBinary(pos.*, 16);
                pos.* += 16;
                return VariantTypeNode{ .tag = .Binary, .data = VariantData{ .Binary = bytes } };
            },
            0x0F => {
                const guid_bytes = try block.unpackBinary(pos.*, 16);
                pos.* += 16;
                return VariantTypeNode{ .tag = .GUID, .data = VariantData{ .GUID = guid_bytes } };
            },
            0x10 => {
                const size = try block.unpackWord(pos.*);
                pos.* += 2;
                const bytes = try block.unpackBinary(pos.*, size);
                pos.* += size;
                return VariantTypeNode{ .tag = .SizeT, .data = VariantData{ .SizeT = bytes } };
            },
            0x11 => {
                const filetime = try block.unpackQword(pos.*);
                pos.* += 8;
                return VariantTypeNode{ .tag = .Filetime, .data = VariantData{ .Filetime = filetime } };
            },
            0x12 => {
                const systime_bytes = try block.unpackBinary(pos.*, 16);
                pos.* += 16;
                return VariantTypeNode{ .tag = .Systemtime, .data = VariantData{ .Systemtime = systime_bytes } };
            },
            0x13 => {
                const size = try block.unpackByte(pos.*);
                pos.* += 1;
                const sid_bytes = try block.unpackBinary(pos.*, size);
                pos.* += size;
                return VariantTypeNode{ .tag = .SID, .data = VariantData{ .SID = sid_bytes } };
            },
            0x14 => {
                const size = try block.unpackDword(pos.*);
                pos.* += 4;
                const hex_bytes = try block.unpackBinary(pos.*, size);
                pos.* += size;
                return VariantTypeNode{ .tag = .HexInt32, .data = VariantData{ .HexInt32 = hex_bytes } };
            },
            0x15 => {
                const size = try block.unpackDword(pos.*);
                pos.* += 4;
                const hex_bytes = try block.unpackBinary(pos.*, size);
                pos.* += size;
                return VariantTypeNode{ .tag = .HexInt64, .data = VariantData{ .HexInt64 = hex_bytes } };
            },
            0x21 => {
                const size = try block.unpackWord(pos.*);
                pos.* += 2;
                const bytes = try block.unpackBinary(pos.*, size);
                pos.* += size;
                return VariantTypeNode{ .tag = .BinXml, .data = VariantData{ .BinXml = bytes } };
            },
            0x81 => {
                const size = try block.unpackWord(pos.*);
                pos.* += 2;
                const string_data = try block.unpackBinary(pos.*, size * 2);
                pos.* += size * 2;
                return VariantTypeNode{ .tag = .WStringArray, .data = VariantData{ .WStringArray = string_data } };
            },
            else => return BinaryXMLError.InvalidVariantType,
        }
    }

    pub fn toString(self: *const VariantTypeNode, allocator: std.mem.Allocator) ![]u8 {
        switch (self.tag) {
            .Null => return try allocator.dupe(u8, ""),
            .WString => return try allocator.dupe(u8, self.data.WString),
            .String => return try allocator.dupe(u8, self.data.String),
            .SignedByte => return try std.fmt.allocPrint(allocator, "{d}", .{self.data.SignedByte}),
            .UnsignedByte => return try std.fmt.allocPrint(allocator, "{d}", .{self.data.UnsignedByte}),
            .SignedWord => return try std.fmt.allocPrint(allocator, "{d}", .{self.data.SignedWord}),
            .UnsignedWord => return try std.fmt.allocPrint(allocator, "{d}", .{self.data.UnsignedWord}),
            .SignedDword => return try std.fmt.allocPrint(allocator, "{d}", .{self.data.SignedDword}),
            .UnsignedDword => return try std.fmt.allocPrint(allocator, "{d}", .{self.data.UnsignedDword}),
            .SignedQword => return try std.fmt.allocPrint(allocator, "{d}", .{self.data.SignedQword}),
            .UnsignedQword => return try std.fmt.allocPrint(allocator, "{d}", .{self.data.UnsignedQword}),
            .Real32 => return try std.fmt.allocPrint(allocator, "{d}", .{self.data.Real32}),
            .Real64 => return try std.fmt.allocPrint(allocator, "{d}", .{self.data.Real64}),
            .Boolean => return try allocator.dupe(u8, if (self.data.Boolean) "true" else "false"),
            .Binary => {
                var result = std.ArrayList(u8).init(allocator);
                for (self.data.Binary) |byte| {
                    try result.writer().print("{x:0>2}", .{byte});
                }
                return result.toOwnedSlice();
            },
            .GUID => {
                const bytes = self.data.GUID;
                return try std.fmt.allocPrint(allocator, 
                    "{{{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}}}",
                    .{ @as(u32, @bitCast(bytes[0..4].*)), @as(u16, @bitCast(bytes[4..6].*)), @as(u16, @bitCast(bytes[6..8].*)),
                       bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15] });
            },
            .SizeT => {
                var result = std.ArrayList(u8).init(allocator);
                for (self.data.SizeT) |byte| {
                    try result.writer().print("{x:0>2}", .{byte});
                }
                return result.toOwnedSlice();
            },
            .Filetime => {
                const filetime = self.data.Filetime;
                const unix_epoch: u64 = 116444736000000000;
                if (filetime >= unix_epoch) {
                    const unix_time = (filetime - unix_epoch) / 10000000;
                    return try std.fmt.allocPrint(allocator, "{d}", .{unix_time});
                } else {
                    return try std.fmt.allocPrint(allocator, "{d}", .{filetime});
                }
            },
            .Systemtime => {
                var result = std.ArrayList(u8).init(allocator);
                for (self.data.Systemtime) |byte| {
                    try result.writer().print("{x:0>2}", .{byte});
                }
                return result.toOwnedSlice();
            },
            .SID => {
                var result = std.ArrayList(u8).init(allocator);
                try result.appendSlice("S-");
                const bytes = self.data.SID;
                if (bytes.len < 2) return try allocator.dupe(u8, "S-INVALID");
                
                const revision = bytes[0];
                const authority_count = bytes[1];
                try result.writer().print("{d}-{d}", .{ revision, authority_count });
                
                var i: usize = 2;
                while (i + 4 <= bytes.len) : (i += 4) {
                    const subauth_bytes = bytes[i..i+4];
                    const subauth = std.mem.readInt(u32, subauth_bytes[0..4], .little);
                    try result.writer().print("-{d}", .{subauth});
                }
                return result.toOwnedSlice();
            },
            .HexInt32 => {
                const bytes = self.data.HexInt32;
                if (bytes.len >= 4) {
                    const value = @as(u32, @bitCast(bytes[0..4].*));
                    return try std.fmt.allocPrint(allocator, "0x{x:0>8}", .{value});
                }
                return try allocator.dupe(u8, "0x00000000");
            },
            .HexInt64 => {
                const bytes = self.data.HexInt64;
                if (bytes.len >= 8) {
                    const value = @as(u64, @bitCast(bytes[0..8].*));
                    return try std.fmt.allocPrint(allocator, "0x{x:0>16}", .{value});
                }
                return try allocator.dupe(u8, "0x0000000000000000");
            },
            .BinXml => {
                var result = std.ArrayList(u8).init(allocator);
                for (self.data.BinXml) |byte| {
                    try result.writer().print("{x:0>2}", .{byte});
                }
                return result.toOwnedSlice();
            },
            .WStringArray => {
                return try allocator.dupe(u8, "[WStringArray]");
            },
        }
    }
};