const std = @import("std");

const c = @cImport({
    @cInclude("libavutil/error.h");
});

pub fn print(prefix: []const u8, err: c_int) void {
    var buf = [_]u8{0} ** c.AV_ERROR_MAX_STRING_SIZE;
    _ = c.av_make_error_string(&buf, c.AV_ERROR_MAX_STRING_SIZE, err);
    std.debug.print("{s} error: {s}\n", .{ prefix, buf });
}
