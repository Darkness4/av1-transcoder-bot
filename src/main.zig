const std = @import("std");
const av = @import("av.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var args = std.ArrayList([*:0]const u8).init(allocator);
    defer args.deinit();

    var it = try std.process.argsWithAllocator(allocator);
    defer it.deinit();

    _ = it.next(); // skip the program name
    while (it.next()) |arg| {
        try args.append(arg.ptr);
    }

    av.concat("out.mp4", args.items, false) catch |err| switch (err) {
        error.AVError => {},
        else => return err,
    };
}
