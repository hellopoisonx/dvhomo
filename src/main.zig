const std = @import("std");
const system = @import("system");
const mihomo = @import("mihomo_zig");

const home_dir = "src/test_home";
const config_path = home_dir ++ "/test.yaml";

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    const config = try std.Io.Dir.readFileAlloc(
        .cwd(),
        io,
        config_path,
        gpa,
        .limited(1 << 20),
    );
    defer gpa.free(config);

    try mihomo.start(gpa, home_dir, config);
    try io.sleep(.fromSeconds(3), .awake);
    try mihomo.stop();
}
