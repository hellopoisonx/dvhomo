const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const goose_dep = b.dependency("goose", .{
        .target = target,
        .optimize = optimize,
    });

    const mihomo_dep = b.dependency("mihomo_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const system_mod = b.addModule("system", .{
        .root_source_file = b.path("src/system/linux.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "goose", .module = goose_dep.module("goose") },
        },
    });

    const dvui_dep = b.dependency("dvui", .{ .target = target, .optimize = optimize, .backend = .sdl3 });

    const unit_tests = b.addTest(.{ .root_module = system_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const exe = b.addExecutable(.{
        .name = "dvhomo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "system", .module = system_mod },
                .{ .name = "mihomo_zig", .module = mihomo_dep.module("mihomo") },
                .{ .name = "dvui", .module = dvui_dep.module("dvui_sdl3") },
                .{ .name = "sdl-backend", .module = dvui_dep.module("sdl3") },
            },
        }),
    });
    b.installArtifact(exe);
    const run_step = b.step("run", "Run dvhomo");
    run_step.dependOn(&b.addRunArtifact(exe).step);
}
