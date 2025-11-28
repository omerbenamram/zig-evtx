//! Context and template cache for BinXML parsing.
//!
//! This module provides the shared state used during parsing, including:
//! - Template definition cache (per-chunk)
//! - Name cache for string deduplication
//! - Arena allocator for chunk-scoped allocations
//!
//! Keep this file renderer-free to avoid cycles.

const std = @import("std");
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const types = @import("types.zig");
const BinXmlError = @import("../err.zig").BinXmlError;
const Reader = @import("../reader.zig").Reader;

/// Cached name entry with UTF-16 bytes and character count.
pub const NameCacheEntry = struct {
    bytes: []u8,
    num_chars: usize,
};

/// Shared parsing context for BinXML processing.
///
/// Manages per-chunk state including template caches, name caches, and a scoped
/// arena allocator. All chunk-scoped allocations use the arena, which is reset
/// atomically between chunks via `resetPerChunk()`.
pub const Context = struct {
    /// Cache key for template definitions: offset + GUID for uniqueness.
    pub const DefKey = struct {
        def_data_off: u32,
        guid: [16]u8,
    };

    /// Backing allocator for long-lived allocations (cache hash maps).
    allocator: std.mem.Allocator,
    /// Arena for chunk-scoped allocations (IR elements, names, etc.).
    arena: std.heap.ArenaAllocator,
    /// Template definition cache: DefKey -> parsed IR element.
    cache: std.AutoHashMap(DefKey, *IR.Element),
    /// Name cache: offset -> (UTF-16 bytes, char count).
    name_cache: std.AutoHashMap(u32, NameCacheEntry),

    /// Creates a new context with the given backing allocator.
    pub fn init(allocator: std.mem.Allocator) !Context {
        return .{
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .cache = std.AutoHashMap(DefKey, *IR.Element).init(allocator),
            .name_cache = std.AutoHashMap(u32, NameCacheEntry).init(allocator),
        };
    }

    /// Releases all resources held by this context.
    pub fn deinit(self: *Context) void {
        self.cache.deinit();
        self.name_cache.deinit();
        self.arena.deinit();
    }

    /// Resets chunk-local state for processing a new chunk.
    ///
    /// Clears all caches and resets the arena allocator while retaining
    /// hash map capacity to avoid repeated allocations.
    pub fn resetPerChunk(self: *Context) void {
        self.cache.clearRetainingCapacity();
        self.name_cache.clearRetainingCapacity();
        _ = self.arena.reset(.retain_capacity);
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

    /// Pre-populates the name cache using offsets from the chunk header.
    ///
    /// This is a best-effort optimization that avoids repeated lookups during parsing.
    /// Invalid offsets or malformed names are silently skipped since this is optional
    /// pre-warming - the actual parsing will handle errors properly if encountered.
    pub fn preCacheFromChunkHeader(self: *Context, chunk: []const u8, offsets: []const u32) void {
        for (offsets) |off| {
            // Skip null offsets and out-of-bounds
            if (off == 0 or off >= chunk.len) continue;
            // Best-effort: errors during pre-caching are non-fatal
            _ = self.getOrReadName(chunk, off) catch continue;
        }
    }
};
