const std = @import("std");
const py = @import("./pydust.build.zig");

pub fn build(b: *std.Build) void {
    const target_query = b.standardTargetOptionsQueryOnly(.{});
    const target = b.resolveTargetQuery(target_query);
    const optimize = b.standardOptimizeOption(.{});

    // Original executable target
    const dep_opts = .{ .target = target_query, .optimize = optimize };
    const zbench_mod = b.dependency("zbench", dep_opts).module("zbench");

    const exe = b.addExecutable(.{
        .name = "evtx_dump_zig",
        .root_source_file = .{ .cwd_relative = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the evtx_dump_zig tool");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    const test_run = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);

    // zBench microbench executable
    const zbench_exe = b.addExecutable(.{
        .name = "bench_utf_zbench",
        .root_source_file = .{ .cwd_relative = "src/bench_utf_zbench.zig" },
        .target = target,
        .optimize = optimize,
    });
    zbench_exe.root_module.addImport("zbench", zbench_mod);
    b.installArtifact(zbench_exe);
    const zbench_run = b.addRunArtifact(zbench_exe);
    const zbench_step = b.step("bench-zbench", "Run zBench microbenchmarks");
    zbench_step.dependOn(&zbench_run.step);

    // Pydust Python extension module target (self-managed)
    const pydust = py.addPydust(b, .{ .test_step = test_step });
    _ = pydust.addPythonModule(.{
        .name = "evtxzig._lib",
        .root_source_file = b.path("src/evtx_pydust.zig"),
        .limited_api = true,
        .target = target_query,
        .optimize = optimize,
    });
}
