const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub const BinaryParserError = error{
    BufferOverrun,
    InvalidData,
    UnicodeDecodeError,
    OutOfMemory,
};

pub const FileTime = struct {
    value: u64,

    pub fn toDateTime(self: FileTime) ?std.time.epoch.EpochSeconds {
        if (self.value == 0) return null;
        
        // Windows FILETIME is 100-nanosecond intervals since January 1, 1601
        // Unix epoch is since January 1, 1970
        // Difference is 11644473600 seconds
        const unix_timestamp = @as(f64, @floatFromInt(self.value)) * 1e-7 - 11644473600.0;
        if (unix_timestamp < 0) return null;
        
        return std.time.epoch.EpochSeconds{ .secs = @as(u64, @intFromFloat(unix_timestamp)) };
    }
};

pub const Block = struct {
    buf: []const u8,
    offset: usize,
    implicit_offset: usize,

    pub fn init(buf: []const u8, offset: usize) Block {
        return Block{
            .buf = buf,
            .offset = offset,
            .implicit_offset = 0,
        };
    }

    fn checkBounds(self: Block, relative_offset: usize, size: usize) BinaryParserError!void {
        const absolute_offset = self.offset + relative_offset;
        if (absolute_offset + size > self.buf.len) {
            return BinaryParserError.BufferOverrun;
        }
    }

    pub fn unpackByte(self: Block, relative_offset: usize) BinaryParserError!u8 {
        try self.checkBounds(relative_offset, 1);
        return self.buf[self.offset + relative_offset];
    }

    pub fn unpackInt8(self: Block, relative_offset: usize) BinaryParserError!i8 {
        try self.checkBounds(relative_offset, 1);
        return @as(i8, @bitCast(self.buf[self.offset + relative_offset]));
    }

    pub fn unpackWord(self: Block, relative_offset: usize) BinaryParserError!u16 {
        try self.checkBounds(relative_offset, 2);
        const bytes = self.buf[self.offset + relative_offset..self.offset + relative_offset + 2];
        return std.mem.readInt(u16, bytes[0..2], .little);
    }

    pub fn unpackWordBe(self: Block, relative_offset: usize) BinaryParserError!u16 {
        try self.checkBounds(relative_offset, 2);
        const bytes = self.buf[self.offset + relative_offset..self.offset + relative_offset + 2];
        return std.mem.readInt(u16, bytes[0..2], .big);
    }

    pub fn unpackInt16(self: Block, relative_offset: usize) BinaryParserError!i16 {
        try self.checkBounds(relative_offset, 2);
        const bytes = self.buf[self.offset + relative_offset..self.offset + relative_offset + 2];
        return std.mem.readInt(i16, bytes[0..2], .little);
    }

    pub fn unpackDword(self: Block, relative_offset: usize) BinaryParserError!u32 {
        try self.checkBounds(relative_offset, 4);
        const bytes = self.buf[self.offset + relative_offset..self.offset + relative_offset + 4];
        return std.mem.readInt(u32, bytes[0..4], .little);
    }

    pub fn unpackDwordBe(self: Block, relative_offset: usize) BinaryParserError!u32 {
        try self.checkBounds(relative_offset, 4);
        const bytes = self.buf[self.offset + relative_offset..self.offset + relative_offset + 4];
        return std.mem.readInt(u32, bytes[0..4], .big);
    }

    pub fn unpackInt32(self: Block, relative_offset: usize) BinaryParserError!i32 {
        try self.checkBounds(relative_offset, 4);
        const bytes = self.buf[self.offset + relative_offset..self.offset + relative_offset + 4];
        return std.mem.readInt(i32, bytes[0..4], .little);
    }

    pub fn unpackQword(self: Block, relative_offset: usize) BinaryParserError!u64 {
        try self.checkBounds(relative_offset, 8);
        const bytes = self.buf[self.offset + relative_offset..self.offset + relative_offset + 8];
        return std.mem.readInt(u64, bytes[0..8], .little);
    }

    pub fn unpackInt64(self: Block, relative_offset: usize) BinaryParserError!i64 {
        try self.checkBounds(relative_offset, 8);
        const bytes = self.buf[self.offset + relative_offset..self.offset + relative_offset + 8];
        return std.mem.readInt(i64, bytes[0..8], .little);
    }

    pub fn unpackFloat(self: Block, relative_offset: usize) BinaryParserError!f32 {
        try self.checkBounds(relative_offset, 4);
        const bytes = self.buf[self.offset + relative_offset..self.offset + relative_offset + 4];
        const int_val = std.mem.readInt(u32, bytes[0..4], .little);
        return @as(f32, @bitCast(int_val));
    }

    pub fn unpackDouble(self: Block, relative_offset: usize) BinaryParserError!f64 {
        try self.checkBounds(relative_offset, 8);
        const bytes = self.buf[self.offset + relative_offset..self.offset + relative_offset + 8];
        const int_val = std.mem.readInt(u64, bytes[0..8], .little);
        return @as(f64, @bitCast(int_val));
    }

    pub fn unpackBinary(self: Block, relative_offset: usize, length: usize) BinaryParserError![]const u8 {
        if (length == 0) return &[_]u8{};
        try self.checkBounds(relative_offset, length);
        return self.buf[self.offset + relative_offset..self.offset + relative_offset + length];
    }

    pub fn unpackString(self: Block, allocator: Allocator, relative_offset: usize, length: usize) BinaryParserError![]u8 {
        const data = try self.unpackBinary(relative_offset, length);
        const result = allocator.alloc(u8, length) catch return BinaryParserError.OutOfMemory;
        @memcpy(result, data);
        return result;
    }

    pub fn unpackStringNullTerminated(self: Block, allocator: Allocator, relative_offset: usize) BinaryParserError![]u8 {
        // Find null terminator first
        var length: usize = 0;
        var pos = relative_offset;
        while (pos < self.buf.len - self.offset) : (pos += 1) {
            const byte = self.buf[self.offset + pos];
            if (byte == 0) break;
            length += 1;
        }
        
        return self.unpackString(allocator, relative_offset, length);
    }

    pub fn unpackWstringNullTerminated(self: Block, allocator: Allocator, relative_offset: usize) BinaryParserError![]u8 {
        // Find null terminator first
        var length: usize = 0;
        var pos = relative_offset;
        while (pos + 1 < self.buf.len - self.offset) : (pos += 2) {
            const word = std.mem.readInt(u16, self.buf[self.offset + pos..self.offset + pos + 2][0..2], .little);
            if (word == 0) break;
            length += 1;
        }
        
        return self.unpackWstring(allocator, relative_offset, length);
    }

    pub fn unpackWstring(self: Block, allocator: Allocator, relative_offset: usize, length: usize) BinaryParserError![]u8 {
        try self.checkBounds(relative_offset, length * 2);
        const utf16_data = self.buf[self.offset + relative_offset..self.offset + relative_offset + length * 2];
        
        // Convert UTF-16 to UTF-8
        var utf8_list = std.ArrayList(u8).init(allocator);
        defer utf8_list.deinit();
        
        var i: usize = 0;
        while (i < utf16_data.len) : (i += 2) {
            if (i + 1 >= utf16_data.len) break;
            const codepoint = std.mem.readInt(u16, utf16_data[i..i+2][0..2], .little);
            
            if (codepoint == 0) break; // Null terminator
            
            // Basic ASCII range
            if (codepoint < 0x80) {
                utf8_list.append(@as(u8, @truncate(codepoint))) catch return BinaryParserError.OutOfMemory;
            } else if (codepoint < 0x800) {
                // 2-byte UTF-8
                utf8_list.append(0xC0 | @as(u8, @truncate(codepoint >> 6))) catch return BinaryParserError.OutOfMemory;
                utf8_list.append(0x80 | @as(u8, @truncate(codepoint & 0x3F))) catch return BinaryParserError.OutOfMemory;
            } else {
                // 3-byte UTF-8 (basic case, not handling surrogates)
                utf8_list.append(0xE0 | @as(u8, @truncate(codepoint >> 12))) catch return BinaryParserError.OutOfMemory;
                utf8_list.append(0x80 | @as(u8, @truncate((codepoint >> 6) & 0x3F))) catch return BinaryParserError.OutOfMemory;
                utf8_list.append(0x80 | @as(u8, @truncate(codepoint & 0x3F))) catch return BinaryParserError.OutOfMemory;
            }
        }
        
        return utf8_list.toOwnedSlice() catch return BinaryParserError.OutOfMemory;
    }

    pub fn unpackFiletime(self: Block, relative_offset: usize) BinaryParserError!FileTime {
        const qword_val = try self.unpackQword(relative_offset);
        return FileTime{ .value = qword_val };
    }

    pub fn unpackGuid(self: Block, allocator: Allocator, relative_offset: usize) BinaryParserError![]u8 {
        try self.checkBounds(relative_offset, 16);
        const guid_bytes = self.buf[self.offset + relative_offset..self.offset + relative_offset + 16];
        
        // Format GUID as string: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
        var result = std.ArrayList(u8).init(allocator);
        defer result.deinit();
        
        const fmt_str = "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}";
        const formatted = std.fmt.allocPrint(allocator, fmt_str, .{
            guid_bytes[3], guid_bytes[2], guid_bytes[1], guid_bytes[0],
            guid_bytes[5], guid_bytes[4], guid_bytes[7], guid_bytes[6],
            guid_bytes[8], guid_bytes[9], guid_bytes[10], guid_bytes[11],
            guid_bytes[12], guid_bytes[13], guid_bytes[14], guid_bytes[15]
        }) catch return BinaryParserError.OutOfMemory;
        
        return formatted;
    }

    pub fn absoluteOffset(self: Block, relative_offset: usize) usize {
        return self.offset + relative_offset;
    }

    pub fn getOffset(self: Block) usize {
        return self.offset;
    }
    
    pub fn getSize(self: Block) usize {
        return self.buf.len;
    }
};

pub fn alignOffset(offset: usize, alignment: usize) usize {
    if (offset % alignment == 0) {
        return offset;
    }
    return offset + (alignment - (offset % alignment));
}

pub fn calculateCrc32(data: []const u8) u32 {
    return std.hash.Crc32.hash(data);
}

// Tests
test "Block basic operations" {
    const test_data = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    const block = Block.init(&test_data, 0);
    
    try testing.expect(try block.unpackByte(0) == 0x12);
    try testing.expect(try block.unpackWord(0) == 0x3412); // Little endian
    try testing.expect(try block.unpackDword(0) == 0x78563412);
}

test "Block with offset" {
    const test_data = [_]u8{ 0x00, 0x00, 0x12, 0x34, 0x56, 0x78 };
    const block = Block.init(&test_data, 2);
    
    try testing.expect(try block.unpackByte(0) == 0x12);
    try testing.expect(try block.unpackWord(0) == 0x3412);
}

test "Buffer overrun detection" {
    const test_data = [_]u8{ 0x12, 0x34 };
    const block = Block.init(&test_data, 0);
    
    try testing.expectError(BinaryParserError.BufferOverrun, block.unpackDword(0));
    try testing.expectError(BinaryParserError.BufferOverrun, block.unpackWord(1));
}

test "FileTime conversion" {
    const ft = FileTime{ .value = 132472608000000000 }; // Example timestamp
    const dt = ft.toDateTime();
    try testing.expect(dt != null);
}