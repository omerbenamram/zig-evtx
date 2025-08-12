const std = @import("std");
const py = @import("./pydust.build.zig");

pub fn build(b: *std.Build) void {
    // Note: pydust helper declares and reads the 'python-exe' option itself.
    // Avoid declaring it here to prevent duplicate option panics.

    const target_query = b.standardTargetOptionsQueryOnly(.{});
    const target = b.resolveTargetQuery(target_query);
    const optimize = b.standardOptimizeOption(.{});

    // Build options
    const with_python = b.option(bool, "with-python", "Build the pydust Python extension module") orelse false;
    const use_c_alloc = b.option(bool, "use-c-alloc", "Link libc and use std.heap.c_allocator via alloc module") orelse true;
    // python-exe already declared above for CLI pass-through even if with_python=false

    // Original executable target
    const dep_opts = .{ .target = target_query, .optimize = optimize };
    const zbench_mod = b.dependency("zbench", dep_opts).module("zbench");

    const exe = b.addExecutable(.{
        .name = "evtx_dump_zig",
        .root_source_file = .{ .cwd_relative = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    // Provide alloc module and optionally link libc
    const alloc_mod = b.createModule(.{ .root_source_file = .{ .cwd_relative = "src/alloc.zig" } });
    exe.root_module.addImport("alloc", alloc_mod);
    if (use_c_alloc) {
        exe.linkLibC();
    }
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
    unit_tests.root_module.addImport("alloc", alloc_mod);
    if (use_c_alloc) {
        unit_tests.linkLibC();
    }
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
    zbench_exe.root_module.addImport("alloc", alloc_mod);
    if (use_c_alloc) {
        zbench_exe.linkLibC();
    }
    b.installArtifact(zbench_exe);
    const zbench_run = b.addRunArtifact(zbench_exe);
    const zbench_step = b.step("bench-zbench", "Run zBench microbenchmarks");
    zbench_step.dependOn(&zbench_run.step);

    // Pydust Python extension module target (self-managed)
    if (with_python) {
        const pydust = py.addPydust(b, .{ .test_step = test_step });
        const pymod = pydust.addPythonModule(.{
            .name = "evtxzig._lib",
            .root_source_file = b.path("src/evtx_pydust.zig"),
            .limited_api = true,
            .target = target_query,
            .optimize = optimize,
        });
        // Ensure our Python module and its tests see the same alloc module used by the main exe
        pymod.library_step.root_module.addImport("alloc", alloc_mod);
        pymod.test_step.root_module.addImport("alloc", alloc_mod);
    }
}
