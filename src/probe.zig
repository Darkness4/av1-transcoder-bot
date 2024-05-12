const std = @import("std");

const c = @cImport({
    @cInclude("stddef.h");
    @cInclude("stdlib.h");
    @cInclude("stdio.h");
    @cInclude("libavformat/avformat.h");
    @cInclude("libavutil/avutil.h");
    @cInclude("libavutil/log.h");
});

pub fn probe(files: []const [*:0]const u8, quiet: bool) !void {
    if (files.len == 0) {
        return;
    }

    if (quiet) {
        c.av_log_set_level(c.AV_LOG_ERROR);
    } else {
        c.av_log_set_level(c.AV_LOG_INFO);
    }

    // For each input
    for (files) |input_file| {
        var ifmt_ctx: ?[*]c.AVFormatContext = null;
        var ret = c.avformat_open_input(&ifmt_ctx, input_file, null, null);
        if (ret < 0) {
            print_error("avformat_open_input", ret);
            return error.AvError;
        }
        defer c.avformat_close_input(&ifmt_ctx);

        // Retrieve input stream information
        ret = c.avformat_find_stream_info(ifmt_ctx, null);
        if (ret < 0) {
            print_error("avformat_find_stream_info", ret);
            return error.AvError;
        }

        // Print input information
        c.av_dump_format(ifmt_ctx, 0, input_file, 0);
    }
}

fn print_error(prefix: []const u8, err: c_int) void {
    var buf = [_]u8{0} ** c.AV_ERROR_MAX_STRING_SIZE;
    _ = c.av_make_error_string(@constCast(@ptrCast(&buf)), c.AV_ERROR_MAX_STRING_SIZE, err);
    std.debug.print("{s} error: {s}\n", .{ prefix, buf });
}
