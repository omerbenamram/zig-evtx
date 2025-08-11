const std = @import("std");
const IRModule = @import("../ir.zig");
const IR = IRModule.IR;
const util = @import("../util.zig");

// --- Context and template cache (IR) ---
// Keep this file renderer-free to avoid cycles. Lifetime: per parser/run, with resetPerChunk().

pub const NameCacheEntry = struct { bytes: []u8, num_chars: usize };

pub const Context = struct {
    pub const DefKey = struct {
        def_data_off: u32,
        guid: [16]u8,

        pub fn hash(self: @This()) u64 {
            var h = std.hash.Wyhash.init(0);
            h.update(std.mem.asBytes(&self.def_data_off));
            h.update(&self.guid);
            return h.final();
        }

        pub fn eql(a: @This(), b: @This()) bool {
            return a.def_data_off == b.def_data_off and std.mem.eql(u8, &a.guid, &b.guid);
        }
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
};
