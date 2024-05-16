const std = @import("std");

const err = @import("error.zig");

const c = @cImport({
    @cInclude("libavcodec/avcodec.h");
    @cInclude("libavformat/avformat.h");
    @cInclude("libavutil/avutil.h");
});

const Transcoder = struct {
    dec_ctx: ?*c.AVCodecContext = null,
    enc_ctx: ?*c.AVCodecContext = null,

    dec_frame: ?*c.AVFrame = null,
    enc_pkt: ?*c.AVPacket = null,

    fn prepare_decoder(
        self: *Transcoder,
        ifmt_ctx: *const c.AVFormatContext,
        in_stream: *const c.AVStream,
    ) !*c.AVCodecContext {
        // Prepare decoder context
        const dec = c.avcodec_find_decoder(in_stream.*.codecpar.*.codec_id);
        if (dec == null) {
            std.debug.print("couldn't find decoder\n", .{});
            return error.AVError;
        }
        const dec_ctx = c.avcodec_alloc_context3(dec);
        if (dec_ctx == null) {
            err.print("avcodec_alloc_context3", c.AVERROR(c.ENOMEM));
            return error.AVError;
        }
        errdefer c.avcodec_free_context(@constCast(@ptrCast(&dec_ctx)));
        var ret = c.avcodec_parameters_to_context(dec_ctx, in_stream.*.codecpar);
        if (ret < 0) {
            err.print("avcodec_parameters_to_context", ret);
            return error.AVError;
        }

        // Inform the decoder about the timebase for the packet timestamps.
        // This is highly recommended, but not mandatory.
        dec_ctx.*.pkt_timebase = in_stream.*.time_base;

        if (dec_ctx.*.codec_type == c.AVMEDIA_TYPE_VIDEO) {
            dec_ctx.*.framerate = c.av_guess_frame_rate(@constCast(ifmt_ctx), @constCast(in_stream), null);
            if (dec_ctx.*.framerate.num == 0 or dec_ctx.*.framerate.den == 0) {
                err.print("couldn't guess framerate", c.AVERROR(c.EINVAL));
                return error.AVError;
            }
        }

        ret = c.avcodec_open2(dec_ctx, dec, null);
        if (ret < 0) {
            err.print("avcodec_open2", ret);
            return error.AVError;
        }

        self.dec_ctx = dec_ctx;
        self.dec_frame = c.av_frame_alloc();
        if (self.dec_frame == null) {
            err.print("av_frame_alloc", c.AVERROR(c.ENOMEM));
            return error.AVError;
        }

        return dec_ctx;
    }

    fn prepare_encoder(self: *Transcoder, ofmt_ctx: *const c.AVFormatContext) !*c.AVCodecContext {
        const enc = c.avcodec_find_encoder(c.AV_CODEC_ID_AV1);
        if (enc == null) {
            std.debug.print("couldn't find encoder\n", .{});
            return error.AVError;
        }
        const enc_ctx = c.avcodec_alloc_context3(enc);
        if (enc_ctx == null) {
            err.print("avcodec_alloc_context3", c.AVERROR(c.ENOMEM));
            return error.AVError;
        }
        errdefer c.avcodec_free_context(@constCast(@ptrCast(&enc_ctx)));

        const dec_ctx = self.dec_ctx.?;

        // Copy codec format
        enc_ctx.*.width = dec_ctx.*.width;
        enc_ctx.*.height = dec_ctx.*.height;
        enc_ctx.*.sample_aspect_ratio = dec_ctx.*.sample_aspect_ratio;
        if (enc.*.pix_fmts != null) {
            enc_ctx.*.pix_fmt = enc.*.pix_fmts[0];
        } else {
            enc_ctx.*.pix_fmt = dec_ctx.*.pix_fmt;
        }
        enc_ctx.*.time_base = c.av_inv_q(dec_ctx.*.framerate);
        // Set lossless encoding
        enc_ctx.*.properties |= c.AV_CODEC_PROP_LOSSLESS;

        if (ofmt_ctx.*.oformat.*.flags & c.AVFMT_GLOBALHEADER != 0) {
            enc_ctx.*.flags |= c.AV_CODEC_FLAG_GLOBAL_HEADER;
        }

        // Open encoder
        const ret = c.avcodec_open2(enc_ctx, enc, null);
        if (ret < 0) {
            err.print("avcodec_open2", ret);
            return error.AVError;
        }

        self.enc_ctx = enc_ctx;
        self.enc_pkt = c.av_packet_alloc();
        if (self.enc_pkt == null) {
            err.print("av_packet_alloc", c.AVERROR(c.ENOMEM));
            return error.AVError;
        }

        return enc_ctx;
    }

    pub fn deinit(self: *Transcoder) void {
        if (self.dec_ctx != null) {
            c.avcodec_free_context(&self.dec_ctx);
        }
        if (self.enc_ctx != null) {
            c.avcodec_free_context(&self.enc_ctx);
        }
        if (self.dec_frame != null) {
            c.av_frame_free(&self.dec_frame);
        }
        if (self.enc_pkt != null) {
            c.av_packet_free(&self.enc_pkt);
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

pub const ConcatContext = struct {
    av_opts: ?*c.AVDictionary,
    pkt: *c.AVPacket,
    allocator: std.mem.Allocator,
    prev_dts: std.ArrayList([]i64),
    prev_duration: std.ArrayList([]i64),
    stream_ctxs: std.ArrayList([]StreamContext),

    pub fn init(allocator: std.mem.Allocator, input_files_len: usize) !ConcatContext {
        const optional_pkt: ?*c.AVPacket = c.av_packet_alloc();
        if (optional_pkt == null) {
            err.print("av_packet_alloc", c.AVERROR(c.ENOMEM));
            return error.AVError;
        }

        var prev_dts = try std.ArrayList([]i64).initCapacity(allocator, input_files_len);
        errdefer {
            for (prev_dts.items) |pdts| {
                allocator.free(pdts);
            }
            prev_dts.deinit();
        }
        var prev_duration = try std.ArrayList([]i64).initCapacity(allocator, input_files_len);
        errdefer {
            for (prev_duration.items) |pduration| {
                allocator.free(pduration);
            }
            prev_duration.deinit();
        }
        var stream_ctxs = try std.ArrayList([]StreamContext).initCapacity(allocator, input_files_len);
        errdefer {
            for (stream_ctxs.items) |stream_ctx| {
                allocator.free(stream_ctx);
            }
            stream_ctxs.deinit();
        }

        // Set "faststart" option
        var optional_av_opts: ?*c.AVDictionary = null;
        const ret = c.av_dict_set(&optional_av_opts, "movflags", "faststart", 0);
        if (ret < 0) {
            err.print("av_dict_set", ret);
            return error.AVError;
        }

        return ConcatContext{
            .av_opts = optional_av_opts.?,
            .pkt = optional_pkt.?,
            .allocator = allocator,
            .prev_dts = prev_dts,
            .prev_duration = prev_duration,
            .stream_ctxs = stream_ctxs,
        };
    }

    pub fn deinit(self: ConcatContext) void {
        if (self.av_opts != null) {
            c.av_dict_free(@constCast(@ptrCast(&self.av_opts)));
        }
        c.av_packet_free(@constCast(@ptrCast(&self.pkt)));

        for (self.prev_dts.items) |pdts| {
            self.allocator.free(pdts);
        }
        self.prev_dts.deinit();

        for (self.prev_duration.items) |ppts| {
            self.allocator.free(ppts);
        }
        self.prev_duration.deinit();

        for (self.stream_ctxs.items) |stream_ctx| {
            self.allocator.free(stream_ctx);
        }
        self.stream_ctxs.deinit();
    }
};

pub fn concat(output_file: [*:0]const u8, input_files: [][*:0]const u8, opts: ConcatOptions) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    c.av_log_set_level(c.AV_LOG_ERROR);

    if (input_files.len == 0) {
        return;
    }

    var ctx = try ConcatContext.init(allocator, input_files.len);
    defer ctx.deinit();

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
        var dts_offset = try allocator.alloc(i64, stream_mapping_size);
        for (dts_offset) |*dts| {
            dts.* = 0;
        }
        defer allocator.free(dts_offset);
        var transcoders = try allocator.alloc(Transcoder, stream_mapping_size);
        for (transcoders) |*tc| {
            tc.* = .{};
        }
        defer {
            for (transcoders) |*tc| {
                tc.deinit();
            }
            allocator.free(transcoders);
        }

        try ctx.prev_dts.append(try allocator.alloc(i64, stream_mapping_size));
        try ctx.prev_duration.append(try allocator.alloc(i64, stream_mapping_size));
        try ctx.stream_ctxs.append(try allocator.alloc(StreamContext, stream_mapping_size));

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
                    _ = try transcoders[out_stream_index].prepare_decoder(ifmt_ctx, in_stream);
                }

                // Only create streams based on the first video.
                // I.e., arrangement of streams is based on the first video.
                if (input_idx == 0) {
                    const out_stream = c.avformat_new_stream(optional_ofmt_ctx, null);
                    if (out_stream == null) {
                        err.print("avformat_new_stream", c.AVERROR(c.ENOMEM));
                        return error.AVError;
                    }
                    switch (in_codecpar.*.codec_type) {
                        c.AVMEDIA_TYPE_VIDEO => {
                            if (opts.to_av1 and transcoders[out_stream_index].dec_ctx != null) {
                                const enc_ctx = try transcoders[out_stream_index].prepare_encoder(ofmt_ctx);

                                // Copy codec parameters
                                ret = c.avcodec_parameters_from_context(out_stream.*.codecpar, transcoders[out_stream_index].enc_ctx);
                                if (ret < 0) {
                                    err.print("avcodec_parameters_from_context", ret);
                                    return error.AVError;
                                }

                                out_stream.*.time_base = enc_ctx.*.time_base;
                            } else {
                                // Remux
                                ret = c.avcodec_parameters_copy(out_stream.*.codecpar, in_codecpar);
                                if (ret < 0) {
                                    err.print("avcodec_parameters_copy", ret);
                                    return error.AVError;
                                }
                                out_stream.*.codecpar.*.codec_tag = 0;
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
                            out_stream.*.codecpar.*.codec_tag = 0;
                            out_stream.*.time_base = c.AVRational{ .num = 1, .den = in_codecpar.*.sample_rate };
                        },
                        else => {
                            // Remux
                            ret = c.avcodec_parameters_copy(out_stream.*.codecpar, in_codecpar);
                            if (ret < 0) {
                                err.print("avcodec_parameters_copy", ret);
                                return error.AVError;
                            }
                            out_stream.*.codecpar.*.codec_tag = 0;
                        },
                    }

                    std.debug.print("Created output stream #{} ({s})\n", .{ out_stream_index, c.av_get_media_type_string(in_codecpar.*.codec_type) });
                }

                // Set to zero
                dts_offset[out_stream_index] = 0;
                ctx.prev_dts.items[input_idx][out_stream_index] = c.AV_NOPTS_VALUE;
                ctx.prev_duration.items[input_idx][out_stream_index] = 0;

                // DTS and PTS of last input file for concatenation
                const previous_input_dts: ?*i64 = if (input_idx > 0) &ctx.prev_dts.items[input_idx - 1][out_stream_index] else null;
                const previous_input_duration: ?*i64 = if (input_idx > 0) &ctx.prev_duration.items[input_idx - 1][out_stream_index] else null;
                ctx.stream_ctxs.items[input_idx][out_stream_index] = .{
                    .in_stream = in_stream,
                    .out_stream = ofmt_ctx.streams[out_stream_index],
                    .ofmt_ctx = ofmt_ctx,
                    .dts_offset = &dts_offset[out_stream_index],
                    .previous_dts = &ctx.prev_dts.items[input_idx][out_stream_index],
                    .previous_duration = &ctx.prev_duration.items[input_idx][out_stream_index],
                    .previous_input_dts = previous_input_dts,
                    .previous_input_duration = previous_input_duration,
                    .stream_index = out_stream_index,
                    .input_index = input_idx,
                    .transcoder = &transcoders[out_stream_index],
                };
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
            // Note: checks for avio_close is above.;

            // Write header
            ret = c.avformat_write_header(ofmt_ctx, &ctx.av_opts);
            if (ret < 0) {
                err.print("avformat_write_header", ret);
                return error.AVError;
            }
        }

        while (true) {
            ret = c.av_read_frame(ifmt_ctx, ctx.pkt);
            if (ret < 0) {
                // No more packets
                break;
            }
            defer c.av_packet_unref(ctx.pkt);

            const in_stream_index = @as(usize, @intCast(ctx.pkt.stream_index));

            // Packet is blacklisted
            if (in_stream_index >= stream_mapping_size or stream_mapping[in_stream_index] < 0) {
                continue;
            }
            const out_stream_index = @as(usize, @intCast(stream_mapping[in_stream_index]));
            const stream_ctx = ctx.stream_ctxs.items[input_idx][out_stream_index];

            if (opts.to_av1 and stream_ctx.transcoder.enc_ctx != null) {
                // Input to decoder timebase
                try stream_ctx.transcode_write_frame(ctx.pkt);
            } else {
                // Remux packet
                c.av_packet_rescale_ts(ctx.pkt, stream_ctx.in_stream.*.time_base, stream_ctx.out_stream.*.time_base);

                try stream_ctx.fix_ts(ctx.pkt);

                ret = c.av_interleaved_write_frame(ofmt_ctx, ctx.pkt);
                if (ret < 0) {
                    err.print("av_interleaved_write_frame", ret);
                    return error.AVError;
                }
            }
        } // while packets.

        // Flush encoder
        for (ctx.stream_ctxs.items[input_idx]) |*sc| {
            if (sc.transcoder.enc_ctx != null) {
                try sc.flush_encoder();
            }
        }
    } // for each input.

    // Write trailer: file is ready and readable.
    _ = c.av_write_trailer(optional_ofmt_ctx);
}

const StreamContext = struct {
    in_stream: *c.AVStream,
    out_stream: *c.AVStream,

    ofmt_ctx: *c.AVFormatContext,
    transcoder: *Transcoder,

    input_index: usize,
    stream_index: usize,

    dts_offset: *i64,
    previous_dts: *i64,
    previous_duration: *i64,
    previous_input_dts: ?*i64,
    previous_input_duration: ?*i64,

    fn transcode_write_frame(self: StreamContext, pkt: *c.AVPacket) !void {
        // Send packet to decoder
        var ret = c.avcodec_send_packet(self.transcoder.*.dec_ctx, pkt);
        if (ret < 0) {
            err.print("avcodec_send_packet", ret);
            return error.AVError;
        }

        while (ret >= 0) {
            // Fetch decoded frame from decoded packet
            ret = c.avcodec_receive_frame(self.transcoder.*.dec_ctx, self.transcoder.*.dec_frame);
            if (ret == c.AVERROR(c.EAGAIN) or ret == c.AVERROR_EOF) {
                return;
            } else if (ret < 0) {
                err.print("avcodec_receive_frame", ret);
                return error.AVError;
            }
            const frame = self.transcoder.*.dec_frame.?;
            defer c.av_frame_unref(frame);

            frame.*.pts = frame.best_effort_timestamp;
            try self.encode_write_frame(frame);
        }
    }

    fn encode_write_frame(self: StreamContext, dec_frame: ?*c.AVFrame) !void {
        const pkt = self.transcoder.enc_pkt.?;
        c.av_packet_unref(pkt);

        if (dec_frame != null and dec_frame.?.*.pts != c.AV_NOPTS_VALUE) {
            dec_frame.?.*.pts = c.av_rescale_q(dec_frame.?.*.pts, self.transcoder.dec_ctx.?.*.pkt_timebase, self.transcoder.enc_ctx.?.*.time_base);
        }

        // Send frame to encoder
        var ret = c.avcodec_send_frame(self.transcoder.enc_ctx, dec_frame);
        if (ret < 0) {
            err.print("avcodec_send_frame", ret);
            return error.AVError;
        }

        while (ret >= 0) {
            // Read encoded data from the encoder.
            ret = c.avcodec_receive_packet(self.transcoder.enc_ctx, pkt);
            if (ret == c.AVERROR(c.EAGAIN) or ret == c.AVERROR_EOF) {
                return;
            } else if (ret < 0) {
                err.print("avcodec_receive_packet", ret);
                return error.AVError;
            }

            // Remux the packet
            pkt.stream_index = @as(c_int, @intCast(self.stream_index));

            // Encoder to output timebase
            c.av_packet_rescale_ts(pkt, self.transcoder.enc_ctx.?.*.time_base, self.out_stream.*.time_base);

            try self.fix_ts(pkt);

            // Write packet
            ret = c.av_interleaved_write_frame(self.ofmt_ctx, pkt);
            if (ret < 0) {
                err.print("av_interleaved_write_frame", ret);
                return error.AVError;
            }
        }
    }

    fn flush_encoder(self: StreamContext) !void {
        if (self.transcoder.enc_ctx.?.*.codec.*.capabilities & c.AV_CODEC_CAP_DELAY == 0) {
            return;
        }

        try self.encode_write_frame(null);
    }

    fn fix_ts(self: StreamContext, pkt: *c.AVPacket) !void {
        // Add past offsets.
        var delta: i64 = self.dts_offset.*;

        if (self.previous_dts.* == c.AV_NOPTS_VALUE) {
            // Initial discontinuity
            delta -= pkt.dts;

            // Concatenation
            if (self.previous_input_dts != null and self.previous_input_dts.?.* != c.AV_NOPTS_VALUE) {
                delta += self.previous_input_dts.?.* + self.previous_input_duration.?.*;

                std.debug.print("Input {}, stream #{} ({s}) concatenation, last.dts={}, pkt.dts={}, new offset={}\n", .{ self.input_index, self.stream_index, c.av_get_media_type_string(self.in_stream.*.codecpar.*.codec_type), self.previous_input_dts.?.*, pkt.dts, delta });
                self.previous_dts.* = self.previous_input_dts.?.*;
                self.previous_duration.* = self.previous_input_duration.?.*;
            }
        }

        // Discontinuity detection
        // Set the dts_offset for the next iteration.
        if (self.previous_dts.* != c.AV_NOPTS_VALUE and
            self.previous_dts.* >= pkt.dts + delta)
        {
            // Offset because of discontinuity
            delta = self.previous_dts.* - pkt.dts;
            delta += if (self.previous_duration.* > 0) self.previous_duration.* else 1;

            std.debug.print("Input {}, stream #{} ({s}) discontinuity, last.dts={}, pkt.dts={}, new offset={}\n", .{ self.input_index, self.stream_index, c.av_get_media_type_string(self.in_stream.*.codecpar.*.codec_type), self.previous_dts.*, pkt.dts, delta });
        }

        // Offsets the current packet
        pkt.pts += delta;
        pkt.dts += delta;
        // std.debug.print("After Input {}, stream #{} ({s}) pkt.pts={}, pkt.dts={}, delta={}\n", .{ self.input_index, self.stream_index, c.av_get_media_type_string(self.in_stream.*.codecpar.*.codec_type), pkt.pts, pkt.dts, delta });

        // Update the previous decoding timestamp
        self.previous_dts.* = pkt.dts;
        self.previous_duration.* = pkt.duration;
        self.dts_offset.* = delta;

        pkt.pos = -1;
    }
};
