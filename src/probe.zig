const std = @import("std");

const c = @cImport({
    @cInclude("stddef.h");
    @cInclude("stdlib.h");
    @cInclude("probe.h");
    @cInclude("libavutil/common.h");
});

pub fn probe(files: []const [*:0]const u8, quiet: bool) !void {
    const err = c.probe(files.len, @constCast(@ptrCast(files.ptr)), @intFromBool(quiet));
    switch (err) {
        0, c.AVERROR_EOF => return,
        else => {
            var buf = [_]u8{0} ** c.AV_ERROR_MAX_STRING_SIZE;
            _ = c.av_make_error_string(@constCast(@ptrCast(&buf)), c.AV_ERROR_MAX_STRING_SIZE, err);
            std.debug.print("probe error: {s}\n", .{buf});
            return error.AvError;
        },
    }
}
