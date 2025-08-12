const std = @import("std");
const builtin = @import("builtin");
const alloc_mod = @import("alloc");

pub const Level = enum(u8) { err = 1, warn = 2, info = 3, debug = 4, trace = 5 };

fn parseLevel(s: []const u8) ?Level {
    if (std.ascii.eqlIgnoreCase(s, "error") or std.mem.eql(u8, s, "1")) return .err;
    if (std.ascii.eqlIgnoreCase(s, "warn") or std.mem.eql(u8, s, "warning") or std.mem.eql(u8, s, "2")) return .warn;
    if (std.ascii.eqlIgnoreCase(s, "info") or std.mem.eql(u8, s, "3")) return .info;
    if (std.ascii.eqlIgnoreCase(s, "debug") or std.mem.eql(u8, s, "4")) return .debug;
    if (std.ascii.eqlIgnoreCase(s, "trace") or std.mem.eql(u8, s, "5")) return .trace;
    return null;
}

var global_level: Level = .warn;
var global_level_loaded: bool = false;

// Compile-time switch: TRACE logs are only enabled in Debug builds
const TRACE_ENABLED: bool = builtin.mode == .Debug;

fn loadGlobalLevel() void {
    if (global_level_loaded) return;
    global_level_loaded = true;
    const allocator = alloc_mod.get();
    const key_list = [_][]const u8{ "EVTX_LOG_LEVEL", "EVTX_LOG" };
    var i: usize = 0;
    while (i < key_list.len) : (i += 1) {
        if (std.process.getEnvVarOwned(allocator, key_list[i])) |val| {
            defer allocator.free(val);
            if (parseLevel(std.mem.trim(u8, val, " \t\r\n"))) |lvl| {
                global_level = lvl;
                return;
            }
        } else |_| {}
    }
}

fn ensureMap() *std.StringHashMap(Level) {
    if (!module_levels_inited) {
        module_levels = std.StringHashMap(Level).init(alloc_mod.get());
        module_levels_inited = true;
    }
    return &module_levels;
}

var module_levels_inited: bool = false;
var module_levels: std.StringHashMap(Level) = undefined;

fn cacheModuleLevel(module: []const u8, lvl: Level) void {
    var map = ensureMap();
    const mod_copy = alloc_mod.get().dupe(u8, module) catch return;
    map.put(mod_copy, lvl) catch {};
}

pub fn clearModuleLevelCache() void {
    if (!module_levels_inited) return;
    module_levels.clearRetainingCapacity();
}

fn upperModuleName(buf: []u8, module: []const u8) []const u8 {
    var n: usize = 0;
    while (n < module.len and n < buf.len) : (n += 1) {
        const c = module[n];
        buf[n] = switch (c) {
            'a'...'z' => c - 32,
            'A'...'Z', '0'...'9' => c,
            else => '_',
        };
    }
    return buf[0..n];
}

fn envKeyForModule(buf: []u8, module: []const u8) []const u8 {
    // Format: EVTX_LOG_<UPPERCASE_MODULE>
    var i: usize = 0;
    const prefix = "EVTX_LOG_";
    if (buf.len < prefix.len) return buf[0..0];
    std.mem.copyForwards(u8, buf[0..prefix.len], prefix);
    i = prefix.len;
    if (i >= buf.len) return buf[0..i];
    const rem = buf[i..];
    const u = upperModuleName(rem, module);
    return buf[0 .. i + u.len];
}

fn getModuleLevel(module: []const u8) Level {
    loadGlobalLevel();
    var map = ensureMap();
    if (map.get(module)) |lvl| return lvl;
    // Check env override
    var key_buf: [128]u8 = undefined;
    const key = envKeyForModule(&key_buf, module);
    if (key.len > 0) {
        if (std.process.getEnvVarOwned(alloc_mod.get(), key)) |val| {
            defer alloc_mod.get().free(val);
            if (parseLevel(std.mem.trim(u8, val, " \t\r\n"))) |lvl| {
                cacheModuleLevel(module, lvl);
                return lvl;
            }
        } else |_| {}
    }
    // Fallback to global; cache this decision to avoid repeated getenv calls
    cacheModuleLevel(module, global_level);
    return global_level;
}

fn levelTag(lvl: Level) []const u8 {
    return switch (lvl) {
        .err => "ERROR",
        .warn => "WARN",
        .info => "INFO",
        .debug => "DEBUG",
        .trace => "TRACE",
    };
}

fn shouldLog(module: []const u8, lvl: Level) bool {
    if (!TRACE_ENABLED and lvl == .trace) return false;
    const eff = getModuleLevel(module);
    return @intFromEnum(lvl) <= @intFromEnum(eff);
}

fn writePrefix(w: anytype, lvl: Level, module: []const u8) !void {
    // Minimal timestamp (ms since start)
    const ts_ms: i128 = std.time.milliTimestamp();
    try w.print("[{s}] {s}: ", .{ levelTag(lvl), module });
    _ = ts_ms; // keep for future if needed
}

fn logInternal(module: []const u8, lvl: Level, comptime fmt: []const u8, args: anytype) void {
    if (!shouldLog(module, lvl)) return;
    var stderr = std.io.getStdErr().writer();
    writePrefix(stderr, lvl, module) catch return;
    stderr.print(fmt, args) catch return;
    stderr.writeByte('\n') catch {};
}

pub const Logger = struct {
    module: []const u8,

    pub fn enabled(self: Logger, lvl: Level) bool {
        return shouldLog(self.module, lvl);
    }

    pub fn err(self: Logger, comptime fmt: []const u8, args: anytype) void {
        logInternal(self.module, .err, fmt, args);
    }
    pub fn warn(self: Logger, comptime fmt: []const u8, args: anytype) void {
        logInternal(self.module, .warn, fmt, args);
    }
    pub fn info(self: Logger, comptime fmt: []const u8, args: anytype) void {
        logInternal(self.module, .info, fmt, args);
    }
    pub fn debug(self: Logger, comptime fmt: []const u8, args: anytype) void {
        logInternal(self.module, .debug, fmt, args);
    }
    pub fn trace(self: Logger, comptime fmt: []const u8, args: anytype) void {
        if (!TRACE_ENABLED) return;
        logInternal(self.module, .trace, fmt, args);
    }
};

pub fn scoped(module: []const u8) Logger {
    return .{ .module = module };
}

pub fn setGlobalLevel(lvl: Level) void {
    global_level = lvl;
    global_level_loaded = true;
    // Changing the global level should invalidate per-module cached levels
    clearModuleLevelCache();
}

pub fn setModuleLevel(module: []const u8, lvl: Level) void {
    var map = ensureMap();
    // Store owned key to make it stable
    const mod_copy = alloc_mod.get().dupe(u8, module) catch return;
    map.put(mod_copy, lvl) catch {};
}
