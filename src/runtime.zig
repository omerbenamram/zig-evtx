const std = @import("std");
const builtin = @import("builtin");
const logger = @import("logger.zig");

const log = logger.scoped("evtx");

pub fn ignoreSigpipe() void {
    if (comptime builtin.os.tag != .windows) {
        const act = std.posix.Sigaction{
            .handler = .{ .handler = std.posix.SIG.IGN },
            .mask = std.mem.zeroes(std.posix.sigset_t),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.PIPE, &act, null);
    }
}

pub fn configureVerbosity(verbosity: u8) void {
    const levels = levelsForVerbosity(verbosity);
    logger.setModuleLevel("evtx", levels.evtx);
    logger.setModuleLevel("binxml", levels.binxml);

    if (verbosity >= 1) {
        log.info("reading file header...", .{});
    }
}

fn levelsForVerbosity(verbosity: u8) struct { evtx: logger.Level, binxml: logger.Level } {
    return switch (verbosity) {
        0 => .{ .evtx = .warn, .binxml = .warn },
        1 => .{ .evtx = .info, .binxml = .warn },
        2 => .{ .evtx = .debug, .binxml = .debug },
        else => .{ .evtx = .trace, .binxml = .trace },
    };
}
