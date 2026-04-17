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

pub fn shouldTreatOutputErrorAsCleanExit(err: anyerror, kind: std.Io.File.Kind) bool {
    return shouldTreatOutputErrorAsCleanExitForKind(err, kind);
}

pub fn shouldTreatOutputErrorAsCleanExitForKind(err: anyerror, maybe_kind: ?std.Io.File.Kind) bool {
    if (err == error.BrokenPipe) return true;
    if (err != error.WriteFailed) return false;
    if (comptime builtin.os.tag == .windows) return false;

    const kind = maybe_kind orelse return false;
    return kind == .named_pipe or kind == .unix_domain_socket;
}

pub fn shouldTreatOutputFileErrorAsCleanExit(io: std.Io, file: std.Io.File, err: anyerror) bool {
    const st = file.stat(io) catch return shouldTreatOutputErrorAsCleanExitForKind(err, null);
    return shouldTreatOutputErrorAsCleanExitForKind(err, st.kind);
}

pub fn configureVerbosity(verbosity: u8) void {
    if (verbosity == 0) return;

    const levels = levelsForVerbosity(verbosity);
    logger.setModuleLevel("evtx", levels.evtx);
    logger.setModuleLevel("binxml", levels.binxml);

    log.info("reading file header...", .{});
}

fn levelsForVerbosity(verbosity: u8) struct { evtx: logger.Level, binxml: logger.Level } {
    return switch (verbosity) {
        0 => .{ .evtx = .warn, .binxml = .warn },
        1 => .{ .evtx = .info, .binxml = .warn },
        2 => .{ .evtx = .debug, .binxml = .debug },
        else => .{ .evtx = .trace, .binxml = .trace },
    };
}

test "output error clean-exit semantics distinguish broken pipes from generic write failures" {
    try std.testing.expect(shouldTreatOutputErrorAsCleanExit(error.BrokenPipe, .file));
    try std.testing.expect(shouldTreatOutputErrorAsCleanExit(error.WriteFailed, .named_pipe));
    try std.testing.expect(shouldTreatOutputErrorAsCleanExit(error.WriteFailed, .unix_domain_socket));
    try std.testing.expect(!shouldTreatOutputErrorAsCleanExit(error.WriteFailed, .file));
    try std.testing.expect(!shouldTreatOutputErrorAsCleanExit(error.AccessDenied, .named_pipe));
    try std.testing.expect(!shouldTreatOutputErrorAsCleanExitForKind(error.WriteFailed, null));
}

test "configureVerbosity zero preserves environment-derived module levels" {
    var env = std.process.Environ.Map.init(std.testing.allocator);
    defer env.deinit();
    defer logger.clearEnvironmentForTests();

    try env.put("EVTX_LOG_EVTX", "debug");
    logger.initEnvironment(&env);

    try std.testing.expect(logger.scoped("evtx").enabled(.debug));
    configureVerbosity(0);
    try std.testing.expect(logger.scoped("evtx").enabled(.debug));
}
