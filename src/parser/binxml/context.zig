const std = @import("std");
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const util = @import("../util.zig");
const types = @import("types.zig");
const BinXmlError = @import("../err.zig").BinXmlError;
const Reader = @import("../reader.zig").Reader;

// --- Context and template cache (IR) ---
// Keep this file renderer-free to avoid cycles. Lifetime: per parser/run, with resetPerChunk().

pub const NameCacheEntry = struct { bytes: []u8, num_chars: usize };

pub const Context = struct {
    pub const DefKey = struct {
        def_data_off: u32,
        guid: [16]u8,
    };

    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    cache: std.AutoHashMap(DefKey, *IR.Element),
    verbose: bool = false,
    name_cache: std.AutoHashMap(u32, NameCacheEntry),
    // Cached UTF-16 separators for joining arrays (arena-owned)
    sep_space_utf16: ?[]u8 = null,
    sep_comma_utf16: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator) !Context {
        return .{
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .cache = std.AutoHashMap(DefKey, *IR.Element).init(allocator),
            .verbose = false,
            .name_cache = std.AutoHashMap(u32, NameCacheEntry).init(allocator),
        };
    }

    pub fn deinit(self: *Context) void {
        self.cache.deinit();
        self.name_cache.deinit();
        self.arena.deinit();
    }

    pub fn resetPerChunk(self: *Context) void {
        // EVTX template definitions are chunk-local. Reset arena and clear cache buckets.
        self.cache.clearRetainingCapacity();
        self.name_cache.clearRetainingCapacity();
        // Invalidate any arena-backed cached slices
        self.sep_space_utf16 = null;
        self.sep_comma_utf16 = null;
        _ = self.arena.reset(.retain_capacity);
    }

    pub fn getSepUtf16(self: *Context, ascii: []const u8) !struct { bytes: []u8, num_chars: usize } {
        if (ascii.len == 0) return .{ .bytes = &[_]u8{}, .num_chars = 0 };
        if (ascii.len == 1 and ascii[0] == ' ') {
            if (self.sep_space_utf16 == null) {
                self.sep_space_utf16 = try util.utf16FromAscii(self.arena.allocator(), ascii);
            }
            return .{ .bytes = self.sep_space_utf16.?, .num_chars = 1 };
        }
        if (ascii.len == 1 and ascii[0] == ',') {
            if (self.sep_comma_utf16 == null) {
                self.sep_comma_utf16 = try util.utf16FromAscii(self.arena.allocator(), ascii);
            }
            return .{ .bytes = self.sep_comma_utf16.?, .num_chars = 1 };
        }
        // Fallback (should not happen with current joiner policy)
        const dyn = try util.utf16FromAscii(self.arena.allocator(), ascii);
        return .{ .bytes = dyn, .num_chars = ascii.len };
    }

    pub fn getOrReadName(self: *Context, chunk: []const u8, off_u32: u32) !IR.Name {
        // Check cache first
        if (self.name_cache.get(off_u32)) |entry| {
            return IR.Name{ .bytes = entry.bytes, .num_chars = entry.num_chars };
        }

        if (off_u32 >= chunk.len) return BinXmlError.UnexpectedEof;

        var r = Reader.init(chunk);
        r.pos = off_u32;

        const h = try r.readStruct(types.NameHeader);
        const num_chars = h.num_chars;
        const byte_len = @as(usize, num_chars) * 2;

        if (r.rem() < byte_len) return BinXmlError.UnexpectedEof;
        const str_start = r.pos;

        // Adjust length for trailing nulls if necessary
        var take_chars = num_chars;
        if (byte_len >= 2) {
            const last = std.mem.readInt(u16, chunk[str_start + byte_len - 2 .. str_start + byte_len][0..2], .little);
            if (last == 0 and take_chars > 0) take_chars -= 1;
        }

        // Allocate and cache new name
        const buf = try self.arena.allocator().alloc(u8, take_chars * 2);
        @memcpy(buf, chunk[str_start .. str_start + take_chars * 2]);
        try self.name_cache.put(off_u32, NameCacheEntry{ .bytes = buf, .num_chars = take_chars });

        return IR.Name{ .bytes = buf, .num_chars = take_chars };
    }
};
