const std = @import("std");
const probe = @import("probe.zig");

pub fn main() !void {
    const files: []const [*:0]const u8 = &.{"test.mp4"};
    try probe.probe(files, false);
}
