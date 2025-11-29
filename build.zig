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

    // Provide alloc module and optionally link libc
    const alloc_mod = b.createModule(.{
        .root_source_file = b.path("src/alloc.zig"),
    });

    const exe_root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const exe = b.addExecutable(.{
        .name = "evtx_dump_zig",
        .root_module = exe_root_mod,
    });
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

    // Dependency modules (used by tests and snapshot tool)
    const dep_opts = .{ .target = target_query, .optimize = optimize };
    const mvzr_mod = b.dependency("mvzr", dep_opts).module("mvzr");

    const test_root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unit_tests = b.addTest(.{
        .root_module = test_root_mod,
    });
    // Optional filter from CLI: -Dtest-filter (unused on 0.14 runner, kept for future)
    unit_tests.root_module.addImport("alloc", alloc_mod);
    unit_tests.root_module.addImport("mvzr", mvzr_mod);
    if (use_c_alloc) {
        unit_tests.linkLibC();
    }
    const test_run = b.addRunArtifact(unit_tests);
    // Always execute the test run step even if inputs are unchanged.
    test_run.has_side_effects = true;
    // Note: stdio = .inherit breaks test runner IPC in Zig 0.15.2, omit it
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);

    // zBench microbench executable
    const zbench_mod = b.dependency("zbench", dep_opts).module("zbench");
    const zbench_exe_root_mod = b.createModule(.{
        .root_source_file = b.path("src/bench_utf_zbench.zig"),
        .target = target,
        .optimize = optimize,
    });
    const zbench_exe = b.addExecutable(.{
        .name = "bench_utf_zbench",
        .root_module = zbench_exe_root_mod,
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

    // Snapshot test tool executable
    const snapshot_tool_root_mod = b.createModule(.{
        .root_source_file = b.path("src/snapshot_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    const snapshot_tool = b.addExecutable(.{
        .name = "snapshot_test",
        .root_module = snapshot_tool_root_mod,
    });
    snapshot_tool.root_module.addImport("alloc", alloc_mod);
    snapshot_tool.root_module.addImport("mvzr", mvzr_mod);
    if (use_c_alloc) {
        snapshot_tool.linkLibC();
    }
    b.installArtifact(snapshot_tool);
    const snapshot_run = b.addRunArtifact(snapshot_tool);
    snapshot_run.has_side_effects = true;
    snapshot_run.stdio = .inherit;
    if (b.args) |args| snapshot_run.addArgs(args);
    const snapshot_step = b.step("snapshot", "Run snapshot tests");
    snapshot_step.dependOn(&snapshot_run.step);

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
