const std = @import("std");

const err = @import("error.zig");

const c = @cImport({
    @cInclude("libavformat/avformat.h");
    @cInclude("libavutil/avutil.h");
});

pub fn probe(files: [][*:0]const u8, quiet: bool) !void {
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
            err.print("avformat_open_input", ret);
            return error.AVError;
        }
        defer c.avformat_close_input(&ifmt_ctx);

        // Retrieve input stream information
        ret = c.avformat_find_stream_info(ifmt_ctx, null);
        if (ret < 0) {
            err.print("avformat_find_stream_info", ret);
            return error.AVError;
        }

        // Print input information
        c.av_dump_format(ifmt_ctx, 0, input_file, 0);
    }
}

pub fn concat(output_file: [*:0]const u8, input_files: [][*:0]const u8, audio_only: bool) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    c.av_log_set_level(c.AV_LOG_ERROR);

    if (input_files.len == 0) {
        return;
    }

    var opts: ?*c.AVDictionary = null;
    defer {
        if (opts != null) c.av_dict_free(&opts);
    }

    var optional_pkt: ?*c.AVPacket = c.av_packet_alloc();
    if (optional_pkt == null) {
        err.print("av_packet_alloc", c.AVERROR(c.ENOMEM));
        return error.AVError;
    }
    defer c.av_packet_free(&optional_pkt);

    var prev_dts = try std.ArrayList([]i64).initCapacity(allocator, input_files.len);
    defer {
        for (prev_dts.items) |pdts| {
            allocator.free(pdts);
        }
        prev_dts.deinit();
    }
    var prev_pts = try std.ArrayList([]i64).initCapacity(allocator, input_files.len);
    defer {
        for (prev_pts.items) |ppts| {
            allocator.free(ppts);
        }
        prev_pts.deinit();
    }

    // Open output file
    var optional_ofmt_ctx: ?*c.AVFormatContext = null;
    var ret = c.avformat_alloc_output_context2(&optional_ofmt_ctx, null, null, output_file);
    if (ret < 0) {
        err.print("avformat_alloc_output_context2", ret);
        return error.AVError;
    }
    var ofmt_ctx = optional_ofmt_ctx.?;
    defer {
        if (ofmt_ctx.oformat.*.flags & c.AVFMT_NOFILE == 0) {
            _ = c.avio_close(ofmt_ctx.pb);
        }
        c.avformat_free_context(ofmt_ctx);
    }

    // For each input file
    for (input_files, 0..input_files.len) |input_file, input_idx| {
        // Open input file
        var optional_ifmt_ctx: ?*c.AVFormatContext = null;
        ret = c.avformat_open_input(&optional_ifmt_ctx, input_file, null, null);
        if (ret < 0) {
            err.print("avformat_open_input", ret);
            return error.AVError;
        }
        defer c.avformat_close_input(&optional_ifmt_ctx);
        const ifmt_ctx = optional_ifmt_ctx.?;

        // Find input stream info
        ret = c.avformat_find_stream_info(ifmt_ctx, null);
        if (ret < 0) {
            err.print("avformat_find_stream_info", ret);
            return error.AVError;
        }

        c.av_dump_format(ifmt_ctx, 0, input_file, 0);

        // Alloc array of streams
        const stream_mapping_size = ifmt_ctx.nb_streams;
        var stream_mapping = try allocator.alloc(i64, stream_mapping_size);
        defer allocator.free(stream_mapping);
        var prev_duration = try allocator.alloc(i64, stream_mapping_size);
        defer allocator.free(prev_duration);
        var dts_offset = try allocator.alloc(i64, stream_mapping_size);
        defer allocator.free(dts_offset);
        try prev_dts.append(try allocator.alloc(i64, stream_mapping_size));
        try prev_pts.append(try allocator.alloc(i64, stream_mapping_size));

        // Add audio and video streams to output context.
        // Map streams from input to output.
        {
            var stream_index: u64 = 0;
            for (0..stream_mapping_size) |i| {
                const in_stream = ifmt_ctx.streams[i];
                const in_codecpar = in_stream.*.codecpar;

                // Blacklist any no audio/video/sub streams
                if (audio_only and in_stream.*.codecpar.*.codec_type != c.AVMEDIA_TYPE_AUDIO) {
                    std.debug.print("Input {}, blacklisted stream #{} ({s})\n", .{ input_idx, i, c.av_get_media_type_string(in_codecpar.*.codec_type) });
                    stream_mapping[i] = -1;
                    continue;
                } else if (in_codecpar.*.codec_type != c.AVMEDIA_TYPE_AUDIO and in_codecpar.*.codec_type != c.AVMEDIA_TYPE_VIDEO and in_codecpar.*.codec_type != c.AVMEDIA_TYPE_SUBTITLE) {
                    std.debug.print("Input {}, blacklisted stream #{} ({s})\n", .{ input_idx, i, c.av_get_media_type_string(in_codecpar.*.codec_type) });
                    stream_mapping[i] = -1;
                    continue;
                }

                // Map stream (not clever, assuming video is first)
                stream_mapping[i] = @as(i64, @intCast(stream_index));
                stream_index += 1;
                std.debug.print("Input {}, mapping stream {} ({s}) to output stream {}\n", .{ input_idx, i, c.av_get_media_type_string(in_codecpar.*.codec_type), stream_mapping[i] });

                // Only create streams based on the first video.
                // I.e., arrangement of streams is based on the first video.
                if (input_idx == 0) {
                    const out_stream = c.avformat_new_stream(optional_ofmt_ctx, null);
                    if (out_stream == null) {
                        std.debug.print("Failed to allocate output stream\n", .{});
                        return error.AVError;
                    }
                    // Note: The stream is attached to the output context, so no need to free it.
                    ret = c.avcodec_parameters_copy(out_stream.*.codecpar, in_codecpar);
                    if (ret < 0) {
                        err.print("avcodec_parameters_copy", ret);
                        return error.AVError;
                    }
                    out_stream.*.codecpar.*.codec_tag = 0;
                    if (in_codecpar.*.codec_type == c.AVMEDIA_TYPE_VIDEO) {
                        out_stream.*.time_base = in_stream.*.time_base;
                    } else if (in_codecpar.*.codec_type == c.AVMEDIA_TYPE_AUDIO) {
                        out_stream.*.time_base = c.AVRational{ .num = 1, .den = in_codecpar.*.sample_rate };
                    }

                    std.debug.print("Created output stream #{} ({s})\n", .{ stream_index - 1, c.av_get_media_type_string(in_codecpar.*.codec_type) });
                }

                // Set to zero
                prev_duration[i] = 0;
                dts_offset[i] = 0;
                // TODO: check out of bounds
                prev_dts.items[input_idx][i] = c.AV_NOPTS_VALUE;
                prev_pts.items[input_idx][i] = c.AV_NOPTS_VALUE;
            }
        }

        // Write header based on the first input file
        if (input_idx == 0) {
            c.av_dump_format(optional_ofmt_ctx, 0, output_file, 1);

            // Open output file with avio
            if (ofmt_ctx.oformat.*.flags & c.AVFMT_NOFILE == 0) {
                ret = c.avio_open(&ofmt_ctx.pb, output_file, c.AVIO_FLAG_WRITE);
                if (ret < 0) {
                    err.print("avio_open", ret);
                    return error.AVError;
                }
            }
            // TODO: close avio file

            // Set "faststart" option
            ret = c.av_dict_set(&opts, "movflags", "faststart", 0);
            if (ret < 0) {
                err.print("av_dict_set", ret);
                return error.AVError;
            }

            // Write header
            ret = c.avformat_write_header(optional_ofmt_ctx, &opts);
            if (ret < 0) {
                err.print("avformat_write_header", ret);
                return error.AVError;
            }
        }

        while (true) {
            ret = c.av_read_frame(ifmt_ctx, optional_pkt);
            if (ret < 0) {
                // No more packets
                break;
            }
            defer c.av_packet_unref(optional_pkt);
            const pkt = optional_pkt.?;

            const in_stream_index = @as(usize, @intCast(pkt.stream_index));
            const out_stream_index = @as(usize, @intCast(stream_mapping[in_stream_index]));

            // Packet is blacklisted
            if (in_stream_index >= stream_mapping_size or out_stream_index < 0) {
                continue;
            }

            const in_stream = ifmt_ctx.streams[in_stream_index];
            const out_stream = ofmt_ctx.streams[out_stream_index];

            pkt.pts = c.av_rescale_q_rnd(pkt.pts, in_stream.*.time_base, out_stream.*.time_base, c.AV_ROUND_NEAR_INF | c.AV_ROUND_PASS_MINMAX) + dts_offset[out_stream_index];
            pkt.dts = c.av_rescale_q_rnd(pkt.dts, in_stream.*.time_base, out_stream.*.time_base, c.AV_ROUND_NEAR_INF | c.AV_ROUND_PASS_MINMAX) + dts_offset[out_stream_index];
            pkt.duration = c.av_rescale_q(pkt.duration, in_stream.*.time_base, out_stream.*.time_base);

            // Offset due to concatenation
            if (input_idx > 0 and prev_pts.items[input_idx - 1][out_stream_index] != c.AV_NOPTS_VALUE) {
                pkt.pts += prev_pts.items[input_idx - 1][out_stream_index] + 1;
            }
            if (input_idx > 0 and
                prev_pts.items[input_idx - 1][out_stream_index] != c.AV_NOPTS_VALUE)
            {
                pkt.dts += prev_dts.items[input_idx - 1][out_stream_index] + 1;
            }

            // Discontinuity handler
            var delta: i64 = 0;
            if (prev_dts.items[input_idx][out_stream_index] == c.AV_NOPTS_VALUE) {
                // Offset because of initial discontinuity
                if (input_idx > 0 and prev_dts.items[input_idx - 1][out_stream_index] != c.AV_NOPTS_VALUE) {
                    delta = prev_dts.items[input_idx - 1][out_stream_index] + 1 - pkt.dts;
                } else {
                    delta = -pkt.dts;
                }

                dts_offset[out_stream_index] += delta;
                std.debug.print("Input {}, stream #{} ({s}) initial discontinuity, shifting {}, new offset={}\n", .{ input_idx, out_stream_index, c.av_get_media_type_string(in_stream.*.codecpar.*.codec_type), delta, dts_offset[out_stream_index] });
            } else if (prev_dts.items[input_idx][out_stream_index] != c.AV_NOPTS_VALUE and
                prev_dts.items[input_idx][out_stream_index] >= pkt.dts)
            {
                // Offset because of discontinuity
                delta = prev_dts.items[input_idx][out_stream_index] - pkt.dts + prev_duration[out_stream_index];
                dts_offset[out_stream_index] += delta;
                std.debug.print("Input {}, stream #{} ({s}) discontinuity, shifting {}, new offset={}\n", .{ input_idx, out_stream_index, c.av_get_media_type_string(in_stream.*.codecpar.*.codec_type), delta, dts_offset[out_stream_index] });
            }
            pkt.pts += delta;
            pkt.dts += delta;

            // Update the previous decoding timestamp
            prev_dts.items[input_idx][out_stream_index] = pkt.dts;
            prev_pts.items[input_idx][out_stream_index] = pkt.pts;
            prev_duration[out_stream_index] = pkt.duration;

            pkt.pos = -1;

            // Write packet
            ret = c.av_interleaved_write_frame(optional_ofmt_ctx, optional_pkt);
            if (ret < 0) {
                err.print("av_interleaved_write_frame", ret);
                return error.AVError;
            }
        } // while packets.
    } // for each input.

    // Write trailer: file is ready and readable.
    _ = c.av_write_trailer(optional_ofmt_ctx);
}
