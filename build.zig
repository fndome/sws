const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{ .cpu_arch = .x86_64, .os_tag = .linux } });
    const optimize = b.standardOptimizeOption(.{});

    const enable_tls = b.option(bool, "enable-tls", "Enable TLS support (via tls.zig)") orelse false;

    const tls_dep = if (enable_tls)
        b.lazyDependency("tls_zig", .{})
    else
        null;

    const is_linux = target.result.os.tag == .linux;

    const mod = b.addModule("sws", .{
        .root_source_file = if (is_linux) b.path("src/root.zig") else b.path("src/root_dev.zig"),
        .target = target,
    });
    if (tls_dep) |dep| {
        mod.addImport("tls", dep.module("tls"));
    } else {
        const tls_noop = b.addModule("tls-noop", .{
            .root_source_file = b.path("src/tls/noop.zig"),
        });
        mod.addImport("tls", tls_noop);
    }

    const build_options = b.addOptions();
    build_options.addOption(bool, "tls_enabled", enable_tls);
    mod.addOptions("build_options", build_options);

    if (is_linux) {
        // ── Linux: io_uring production build ──
        const exe = b.addExecutable(.{
            .name = "sws",
            .root_module = b.createModule(.{
                .link_libc = true,
                .root_source_file = b.path("src/example.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "sws", .module = mod }},
            }),
        });
        if (tls_dep) |dep| exe.root_module.addImport("tls", dep.module("tls"));
        exe.root_module.addOptions("build_options", build_options);
        b.installArtifact(exe);

        const example_exe = b.addExecutable(.{
            .name = "sws-example",
            .root_module = b.createModule(.{
                .link_libc = true,
                .root_source_file = b.path("example/main.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "sws", .module = mod }},
            }),
        });
        if (tls_dep) |dep| example_exe.root_module.addImport("tls", dep.module("tls"));
        example_exe.root_module.addOptions("build_options", build_options);
        b.installArtifact(example_exe);

        const im_bench_exe = b.addExecutable(.{
            .name = "im-bench",
            .root_module = b.createModule(.{
                .link_libc = true,
                .root_source_file = b.path("example/im_bench.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "sws", .module = mod }},
            }),
        });
        if (tls_dep) |dep| im_bench_exe.root_module.addImport("tls", dep.module("tls"));
        im_bench_exe.root_module.addOptions("build_options", build_options);
        b.installArtifact(im_bench_exe);

        const run_im_bench = b.step("run-im-bench", "Run IM-scenario WebSocket benchmark");
        const run_im_bench_cmd = b.addRunArtifact(im_bench_exe);
        run_im_bench_cmd.step.dependOn(b.getInstallStep());
        run_im_bench.dependOn(&run_im_bench_cmd.step);

        const run_example = b.step("run-example", "Run example/main.zig");
        const run_example_cmd = b.addRunArtifact(example_exe);
        run_example_cmd.step.dependOn(b.getInstallStep());
        run_example.dependOn(&run_example_cmd.step);

        const run_step = b.step("run", "Run the app");
        const run_cmd = b.addRunArtifact(exe);
        run_step.dependOn(&run_cmd.step);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| run_cmd.addArgs(args);

        const exe_tests = b.addTest(.{ .root_module = exe.root_module });
        const run_exe_tests = b.addRunArtifact(exe_tests);

        const test_step = b.step("test", "Run tests");
        const mod_tests = b.addTest(.{ .root_module = mod });
        if (tls_dep) |dep| mod_tests.root_module.addImport("tls", dep.module("tls"));
        mod_tests.root_module.addOptions("build_options", build_options);
        const run_mod_tests = b.addRunArtifact(mod_tests);
        test_step.dependOn(&run_mod_tests.step);
        test_step.dependOn(&run_exe_tests.step);
    } else {
        // ── Non-Linux: DevServer build ──
        const dev_exe = b.addExecutable(.{
            .name = "sws-dev",
            .root_module = b.createModule(.{
                .link_libc = true,
                .root_source_file = b.path("example/dev_main.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "sws", .module = mod }},
            }),
        });
        b.installArtifact(dev_exe);

        const run_dev = b.step("run", "Run the dev server");
        const run_dev_cmd = b.addRunArtifact(dev_exe);
        run_dev_cmd.step.dependOn(b.getInstallStep());
        run_dev.dependOn(&run_dev_cmd.step);
        if (b.args) |args| run_dev_cmd.addArgs(args);

        const test_step = b.step("test", "Run tests");
        const mod_tests = b.addTest(.{ .root_module = mod });
        if (tls_dep) |dep| mod_tests.root_module.addImport("tls", dep.module("tls"));
        mod_tests.root_module.addOptions("build_options", build_options);
        const run_mod_tests = b.addRunArtifact(mod_tests);
        test_step.dependOn(&run_mod_tests.step);
    }
}
