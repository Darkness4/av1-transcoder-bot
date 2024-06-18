const std = @import("std");

pub fn buildStaticExecutable(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "av1-transcoder",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .linkage = .static,
        .link_libc = true,
    });

    exe.addIncludePath(.{
        .src_path = .{ .owner = b, .sub_path = "src" },
    });
    exe.addIncludePath(.{
        .src_path = .{ .owner = b, .sub_path = "/usr/include" },
    });
    exe.addObjectFile(.{ .src_path = .{
        .owner = b,
        .sub_path = "/usr/lib/libavcodec.a",
    } });
    exe.addObjectFile(.{ .src_path = .{
        .owner = b,
        .sub_path = "/usr/lib/libavutil.a",
    } });
    exe.addObjectFile(.{ .src_path = .{
        .owner = b,
        .sub_path = "/usr/lib/libavformat.a",
    } });
    exe.addObjectFile(.{ .src_path = .{
        .owner = b,
        .sub_path = "/usr/lib/libswresample.a",
    } });
    exe.addObjectFile(.{ .src_path = .{
        .owner = b,
        .sub_path = "/usr/lib/libSvtAv1Dec.a",
    } });
    exe.addObjectFile(.{ .src_path = .{
        .owner = b,
        .sub_path = "/usr/lib/libSvtAv1Enc.a",
    } });

    return exe;
}

fn buildDynamicExecutable(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "av1-transcoder",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .linkage = .dynamic,
        .link_libc = true,
    });

    exe.addIncludePath(.{
        .src_path = .{ .owner = b, .sub_path = "src" },
    });
    exe.linkSystemLibrary2("libavcodec", .{ .preferred_link_mode = .dynamic });
    exe.linkSystemLibrary2("libavutil", .{ .preferred_link_mode = .dynamic });
    exe.linkSystemLibrary2("libavformat", .{ .preferred_link_mode = .dynamic });
    exe.linkSystemLibrary2("swresample", .{ .preferred_link_mode = .dynamic });

    // No need to explicitly link to the SVT-AV1 libraries, as they are linked to the libavcodec library.

    return exe;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const static_option = b.option(bool, "static", "Build a static executable") orelse false;

    const exe = if (static_option)
        buildStaticExecutable(b, target, optimize)
    else
        buildDynamicExecutable(b, target, optimize);

    const zigcli_dep = b.dependency("zig-cli", .{ .target = target });
    const zigcli_mod = zigcli_dep.module("zig-cli");
    exe.root_module.addImport("zig-cli", zigcli_mod);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
