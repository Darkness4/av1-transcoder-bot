const std = @import("std");

const err = @import("error.zig");

const c = @cImport({
    @cInclude("libavcodec/avcodec.h");
    @cInclude("libavformat/avformat.h");
    @cInclude("libavutil/avutil.h");
});

const StreamContext = struct {
    dec_ctx: ?*c.AVCodecContext = null,
    enc_ctx: ?*c.AVCodecContext = null,

    dec_frame: ?*c.AVFrame = null,

    pub fn deinit(self: *StreamContext) void {
        if (self.dec_ctx != null) {
            c.avcodec_free_context(&self.dec_ctx);
        }
        if (self.enc_ctx != null) {
            c.avcodec_free_context(&self.enc_ctx);
        }
        if (self.dec_frame != null) {
            c.av_frame_free(&self.dec_frame);
        }
    }
};

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

pub const ConcatOptions = struct {
    audio_only: bool = false,
    to_av1: bool = false,
};

pub fn concat(output_file: [*:0]const u8, input_files: [][*:0]const u8, opts: ConcatOptions) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    c.av_log_set_level(c.AV_LOG_ERROR);

    if (input_files.len == 0) {
        return;
    }

    var av_opts: ?*c.AVDictionary = null;
    defer {
        if (av_opts != null) c.av_dict_free(&av_opts);
    }

    var optional_pkt: ?*c.AVPacket = c.av_packet_alloc();
    if (optional_pkt == null) {
        err.print("av_packet_alloc", c.AVERROR(c.ENOMEM));
        return error.AVError;
    }
    defer c.av_packet_free(&optional_pkt);
    const pkt = optional_pkt.?;

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
        var stream_ctx = try std.ArrayList(StreamContext).initCapacity(allocator, stream_mapping_size);
        defer {
            for (stream_ctx.items) |*sc| {
                sc.deinit();
            }
            stream_ctx.deinit();
        }
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
                if (opts.audio_only and in_stream.*.codecpar.*.codec_type != c.AVMEDIA_TYPE_AUDIO) {
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
                const out_stream_index = @as(usize, @intCast(stream_mapping[i]));
                std.debug.print("Input {}, mapping stream {} ({s}) to output stream {}\n", .{ input_idx, i, c.av_get_media_type_string(in_codecpar.*.codec_type), out_stream_index });

                // Prepare decoder context if using AV1 transcoding
                if (opts.to_av1 and in_codecpar.*.codec_type == c.AVMEDIA_TYPE_VIDEO) {
                    // TODO: skip transcoding if not AV1
                    stream_ctx.items[out_stream_index].dec_ctx = try prepare_decoder(in_stream);
                    // Note: checks for freeing dec_ctx is above.
                    stream_ctx.items[out_stream_index].dec_frame = c.av_frame_alloc();
                    if (stream_ctx.items[out_stream_index].dec_frame == null) {
                        err.print("av_frame_alloc", c.AVERROR(c.ENOMEM));
                        return error.AVError;
                    }
                }

                // Only create streams based on the first video.
                // I.e., arrangement of streams is based on the first video.
                if (input_idx == 0) {
                    const out_stream = c.avformat_new_stream(optional_ofmt_ctx, null);
                    if (out_stream == null) {
                        err.print("avformat_new_stream", c.AVERROR(c.ENOMEM));
                        return error.AVError;
                    }

                    out_stream.*.codecpar.*.codec_tag = 0;
                    switch (in_codecpar.*.codec_type) {
                        c.AVMEDIA_TYPE_VIDEO => {
                            if (opts.to_av1) {
                                stream_ctx.items[out_stream_index].enc_ctx = try prepare_encoder(ofmt_ctx, stream_ctx.items[out_stream_index].dec_ctx.?);
                                // Note: checks for freeing enc_ctx is above.
                                out_stream.*.time_base = stream_ctx.items[out_stream_index].enc_ctx.?.time_base;

                                // Copy codec parameters
                                ret = c.avcodec_parameters_from_context(out_stream.*.codecpar, stream_ctx.items[out_stream_index].enc_ctx);
                                if (ret < 0) {
                                    err.print("avcodec_parameters_from_context", ret);
                                    return error.AVError;
                                }
                            } else {
                                // Remux
                                ret = c.avcodec_parameters_copy(out_stream.*.codecpar, in_codecpar);
                                if (ret < 0) {
                                    err.print("avcodec_parameters_copy", ret);
                                    return error.AVError;
                                }

                                out_stream.*.time_base = in_stream.*.time_base;
                            }
                        },
                        c.AVMEDIA_TYPE_AUDIO => {
                            // Remux
                            ret = c.avcodec_parameters_copy(out_stream.*.codecpar, in_codecpar);
                            if (ret < 0) {
                                err.print("avcodec_parameters_copy", ret);
                                return error.AVError;
                            }

                            out_stream.*.time_base = c.AVRational{ .num = 1, .den = in_codecpar.*.sample_rate };
                        },
                        else => {
                            // Remux
                            ret = c.avcodec_parameters_copy(out_stream.*.codecpar, in_codecpar);
                            if (ret < 0) {
                                err.print("avcodec_parameters_copy", ret);
                                return error.AVError;
                            }
                        },
                    }

                    std.debug.print("Created output stream #{} ({s})\n", .{ out_stream_index, c.av_get_media_type_string(in_codecpar.*.codec_type) });
                }

                // Set to zero
                prev_duration[i] = 0;
                dts_offset[i] = 0;
                prev_dts.items[input_idx][i] = c.AV_NOPTS_VALUE;
                prev_pts.items[input_idx][i] = c.AV_NOPTS_VALUE;
            }
        }

        // Write header based on the first input file
        if (input_idx == 0) {
            c.av_dump_format(ofmt_ctx, 0, output_file, 1);

            // Open output file with avio
            if (ofmt_ctx.oformat.*.flags & c.AVFMT_NOFILE == 0) {
                ret = c.avio_open(&ofmt_ctx.pb, output_file, c.AVIO_FLAG_WRITE);
                if (ret < 0) {
                    err.print("avio_open", ret);
                    return error.AVError;
                }
            }
            // Note: checks for avio_close is above.

            // Set "faststart" option
            ret = c.av_dict_set(&av_opts, "movflags", "faststart", 0);
            if (ret < 0) {
                err.print("av_dict_set", ret);
                return error.AVError;
            }
            // Note: checks for dict_free is above.

            // Write header
            ret = c.avformat_write_header(ofmt_ctx, &av_opts);
            if (ret < 0) {
                err.print("avformat_write_header", ret);
                return error.AVError;
            }
        }

        while (true) {
            ret = c.av_read_frame(ifmt_ctx, pkt);
            if (ret < 0) {
                // No more packets
                break;
            }
            defer c.av_packet_unref(pkt);

            const in_stream_index = @as(usize, @intCast(pkt.stream_index));

            // Packet is blacklisted
            if (in_stream_index >= stream_mapping_size or stream_mapping[in_stream_index] < 0) {
                continue;
            }
            const out_stream_index = @as(usize, @intCast(stream_mapping[in_stream_index]));

            const in_stream = ifmt_ctx.streams[in_stream_index];
            const out_stream = ofmt_ctx.streams[out_stream_index];

            // DTS and PTS of last input file for concatenation
            var previous_input_dts: ?*i64 = null;
            var previous_input_pts: ?*i64 = null;
            if (input_idx > 0) {
                previous_input_dts = &prev_dts.items[input_idx - 1][out_stream_index];
                previous_input_pts = &prev_pts.items[input_idx - 1][out_stream_index];
            }

            const previous_dts: *i64 = &prev_dts.items[input_idx][out_stream_index];
            const previous_pts: *i64 = &prev_pts.items[input_idx][out_stream_index];
            const previous_duration: *i64 = &prev_duration[out_stream_index];

            // TODO: here add transcoding
            if (opts.to_av1) {} else {
                try remux_write_frame(.{
                    .in_stream = in_stream,
                    .out_stream = out_stream,
                    .pkt = pkt,
                    .ofmt_ctx = ofmt_ctx,
                    .dts_offset = &dts_offset[out_stream_index],
                    .previous_dts = previous_dts,
                    .previous_pts = previous_pts,
                    .previous_duration = previous_duration,
                    .previous_input_dts = previous_input_dts,
                    .previous_input_pts = previous_input_pts,
                    .out_stream_index = out_stream_index,
                    .input_index = input_idx,
                });
            }
        } // while packets.
    } // for each input.

    // Write trailer: file is ready and readable.
    _ = c.av_write_trailer(optional_ofmt_ctx);
}

fn prepare_decoder(in_stream: *c.AVStream) !*c.AVCodecContext {
    // Prepare decoder context
    const dec = c.avcodec_find_decoder(in_stream.*.codecpar.*.codec_id);
    if (dec == null) {
        std.debug.print("couldn't find decoder\n", .{});
        return error.AVError;
    }
    const codec_ctx = c.avcodec_alloc_context3(dec);
    if (codec_ctx == null) {
        err.print("avcodec_alloc_context3", c.AVERROR(c.ENOMEM));
        return error.AVError;
    }
    errdefer c.avcodec_free_context(@constCast(@ptrCast(&codec_ctx)));
    const ret = c.avcodec_parameters_to_context(codec_ctx, in_stream.*.codecpar);
    if (ret < 0) {
        err.print("avcodec_parameters_to_context", ret);
        return error.AVError;
    }
    return codec_ctx;
}

fn prepare_encoder(ofmt_ctx: *c.AVFormatContext, dec_ctx: *c.AVCodecContext) !*c.AVCodecContext {
    const enc = c.avcodec_find_encoder(c.AV_CODEC_ID_AV1);
    if (enc == null) {
        std.debug.print("couldn't find encoder\n", .{});
        return error.AVError;
    }
    const codec_ctx = c.avcodec_alloc_context3(enc);
    if (codec_ctx == null) {
        err.print("avcodec_alloc_context3", c.AVERROR(c.ENOMEM));
        return error.AVError;
    }
    errdefer c.avcodec_free_context(@constCast(@ptrCast(&codec_ctx)));

    // Copy codec format
    codec_ctx.*.width = dec_ctx.*.width;
    codec_ctx.*.height = dec_ctx.*.height;
    codec_ctx.*.sample_aspect_ratio = dec_ctx.*.sample_aspect_ratio;
    if (enc.*.pix_fmts != null) {
        codec_ctx.*.pix_fmt = enc.*.pix_fmts[0];
    } else {
        codec_ctx.*.pix_fmt = dec_ctx.*.pix_fmt;
    }
    codec_ctx.*.time_base = c.av_inv_q(dec_ctx.*.framerate);

    if (ofmt_ctx.*.oformat.*.flags & c.AVFMT_GLOBALHEADER != 0) {
        codec_ctx.*.flags |= c.AV_CODEC_FLAG_GLOBAL_HEADER;
    }

    // Open encoder
    const ret = c.avcodec_open2(codec_ctx, enc, null);
    if (ret < 0) {
        err.print("avcodec_open2", ret);
        return error.AVError;
    }

    return codec_ctx;
}

fn encode_write_frame(ofmt_ctx: *c.AVFormatContext, stream_ctx: *StreamContext, dec_frame: *c.AVFrame, stream_index: i64, enc_pkt: *c.AVPacket) !void {
    // TODO: check why
    c.av_packet_unref(enc_pkt);

    // Send frame to encoder
    var ret = c.avcodec_send_frame(stream_ctx.enc_ctx, dec_frame);
    if (ret < 0) {
        err.print("avcodec_send_frame", ret);
        return error.AVError;
    }

    while (ret >= 0) {
        // Read encoded data from the encoder.
        ret = c.avcodec_receive_packet(stream_ctx.enc_ctx, enc_pkt);
        if (ret == c.AVERROR(c.EAGAIN) or ret == c.AVERROR_EOF) {
            return;
        } else if (ret < 0) {
            err.print("avcodec_receive_packet", ret);
            return error.AVError;
        }

        // Remux the packet
        enc_pkt.stream_index = stream_index;
        // TODO: handle pts, dts, duration

        // Write packet
        // Compared to a simple remuxing, they may be more packets to write coming from the encoder.
        ret = c.av_interleaved_write_frame(ofmt_ctx, enc_pkt);
        if (ret < 0) {
            err.print("av_interleaved_write_frame", ret);
            return error.AVError;
        }
    }
}

fn remux_write_frame(opts: struct {
    in_stream: *c.AVStream,
    out_stream: *c.AVStream,
    ofmt_ctx: *c.AVFormatContext,

    input_index: usize,
    out_stream_index: usize,

    dts_offset: *i64,
    previous_dts: *i64,
    previous_pts: *i64,
    previous_duration: *i64,
    previous_input_dts: ?*i64,
    previous_input_pts: ?*i64,

    pkt: *c.AVPacket,
}) !void {
    c.av_packet_rescale_ts(opts.pkt, opts.in_stream.*.time_base, opts.out_stream.*.time_base);

    // Offset due to discontinuity
    opts.pkt.pts += opts.dts_offset.*;
    opts.pkt.dts += opts.dts_offset.*;

    // Offset due to concatenation
    if (opts.previous_input_pts != null and opts.previous_input_pts.?.* != c.AV_NOPTS_VALUE) {
        opts.pkt.pts += opts.previous_input_pts.?.* + 1;
    }
    if (opts.previous_input_dts != null and opts.previous_input_dts.?.* != c.AV_NOPTS_VALUE) {
        opts.pkt.dts += opts.previous_input_dts.?.* + 1;
    }

    // Discontinuity detection
    // Set the dts_offset for the next iteration.
    var delta: i64 = 0;
    if (opts.previous_dts.* == c.AV_NOPTS_VALUE) {
        // Offset because of initial discontinuity
        if (opts.previous_input_dts != null and opts.previous_input_dts.?.* != c.AV_NOPTS_VALUE) {
            // Take account of the concatenation
            delta = opts.previous_input_dts.?.* + 1 - opts.pkt.dts;
        } else {
            delta = -opts.pkt.dts;
        }

        opts.dts_offset.* += delta;

        std.debug.print("Input {}, stream #{} ({s}) initial discontinuity, shifting {}, new offset={}\n", .{ opts.input_index, opts.out_stream_index, c.av_get_media_type_string(opts.in_stream.*.codecpar.*.codec_type), delta, opts.dts_offset.* });
    } else if (opts.previous_dts.* != c.AV_NOPTS_VALUE and
        opts.previous_dts.* >= opts.pkt.dts)
    {
        // Offset because of discontinuity
        delta = opts.previous_dts.* - opts.pkt.dts + opts.previous_duration.*;
        opts.dts_offset.* += delta;

        std.debug.print("Input {}, stream #{} ({s}) discontinuity, shifting {}, new offset={}\n", .{ opts.input_index, opts.out_stream_index, c.av_get_media_type_string(opts.in_stream.*.codecpar.*.codec_type), delta, opts.dts_offset.* });
    }

    // Offsets the current packet
    opts.pkt.pts += delta;
    opts.pkt.dts += delta;

    // Update the previous decoding timestamp
    opts.previous_dts.* = opts.pkt.dts;
    opts.previous_pts.* = opts.pkt.pts;
    opts.previous_duration.* = opts.pkt.duration;

    opts.pkt.pos = -1;

    // Write packet
    const ret = c.av_interleaved_write_frame(opts.ofmt_ctx, opts.pkt);
    if (ret < 0) {
        err.print("av_interleaved_write_frame", ret);
        return error.AVError;
    }
}
