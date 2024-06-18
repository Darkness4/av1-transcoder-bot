const std = @import("std");

const err = @import("error.zig");

const c = @cImport({
    @cInclude("libavcodec/avcodec.h");
    @cInclude("libavformat/avformat.h");
    @cInclude("libavutil/avutil.h");
    @cInclude("libavutil/opt.h");
});

const AVError = error{
    Unknown,
    EOF,
    EAGAIN,
    ENOMEM,
    EINVAL,
};

fn ret_to_error(ret: c_int) AVError {
    return switch (ret) {
        c.AVERROR_EOF => AVError.EOF,
        c.AVERROR(c.EAGAIN) => AVError.EAGAIN,
        c.AVERROR(c.ENOMEM) => AVError.ENOMEM,
        else => AVError.Unknown,
    };
}

const Encoder = struct {
    enc_ctx: ?*c.AVCodecContext = null,
    enc_pkt: ?*c.AVPacket = null,

    fn prepare_encoder(self: *Encoder, ofmt_ctx: *const c.AVFormatContext, dec_ctx: *const c.AVCodecContext) !*c.AVCodecContext {
        const enc = c.avcodec_find_encoder(c.AV_CODEC_ID_AV1);
        if (enc == null) {
            std.debug.print("couldn't find encoder\n", .{});
            return AVError.Unknown;
        }
        var enc_ctx = c.avcodec_alloc_context3(enc);
        if (enc_ctx == null) {
            err.print("avcodec_alloc_context3", c.AVERROR(c.ENOMEM));
            return AVError.ENOMEM;
        }
        errdefer c.avcodec_free_context(&enc_ctx);

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
        enc_ctx.*.framerate = dec_ctx.*.framerate;
        std.debug.print("Decoder framerate: {}/{}\n", .{ dec_ctx.*.framerate.num, dec_ctx.*.framerate.den });

        // Set lossless encoding
        var ret = c.av_opt_set(enc_ctx.*.priv_data, "crf", "0", 0);
        if (ret < 0) {
            err.print("av_opt_set", ret);
            return ret_to_error(ret);
        }

        if (ofmt_ctx.*.oformat.*.flags & c.AVFMT_GLOBALHEADER != 0) {
            enc_ctx.*.flags |= c.AV_CODEC_FLAG_GLOBAL_HEADER;
        }

        // Open encoder
        ret = c.avcodec_open2(enc_ctx, enc, null);
        if (ret < 0) {
            err.print("avcodec_open2", ret);
            return ret_to_error(ret);
        }

        self.enc_ctx = enc_ctx;
        self.enc_pkt = c.av_packet_alloc();
        if (self.enc_pkt == null) {
            err.print("av_packet_alloc", c.AVERROR(c.ENOMEM));
            return AVError.ENOMEM;
        }

        return enc_ctx;
    }

    fn send_frame(self: *Encoder, frame: ?*c.AVFrame) !void {
        const ret = c.avcodec_send_frame(self.enc_ctx.?, frame);
        if (ret < 0) {
            err.print("avcodec_send_frame", ret);
            return ret_to_error(ret);
        }
    }

    fn receive_packet(self: *Encoder) !*c.AVPacket {
        const ret = c.avcodec_receive_packet(self.enc_ctx.?, self.enc_pkt.?);
        if (ret < 0) {
            switch (ret) {
                c.AVERROR_EOF => return AVError.EOF,
                c.AVERROR(c.EAGAIN) => return AVError.EAGAIN,
                else => {
                    err.print("avcodec_receive_packet", ret);
                    return ret_to_error(ret);
                },
            }
        }
        return self.enc_pkt.?;
    }

    fn unref_pkt(self: *Encoder) void {
        c.av_packet_unref(self.enc_pkt);
    }

    fn deinit(self: *Encoder) void {
        if (self.enc_ctx != null) {
            c.avcodec_free_context(&self.enc_ctx);
        }
        if (self.enc_pkt != null) {
            c.av_packet_free(&self.enc_pkt);
        }
    }
};

const Decoder = struct {
    dec_ctx: ?*c.AVCodecContext = null,
    dec_frame: ?*c.AVFrame = null,

    fn prepare_decoder(
        self: *Decoder,
        ifmt_ctx: *const c.AVFormatContext,
        in_stream: *const c.AVStream,
    ) !*c.AVCodecContext {
        // Prepare decoder context
        const dec = c.avcodec_find_decoder(in_stream.*.codecpar.*.codec_id);
        if (dec == null) {
            std.debug.print("couldn't find decoder\n", .{});
            return AVError.Unknown;
        }
        var dec_ctx = c.avcodec_alloc_context3(dec);
        if (dec_ctx == null) {
            err.print("avcodec_alloc_context3", c.AVERROR(c.ENOMEM));
            return AVError.ENOMEM;
        }
        errdefer c.avcodec_free_context(&dec_ctx);
        var ret = c.avcodec_parameters_to_context(dec_ctx, in_stream.*.codecpar);
        if (ret < 0) {
            err.print("avcodec_parameters_to_context", ret);
            return ret_to_error(ret);
        }

        // Inform the decoder about the timebase for the packet timestamps.
        // This is highly recommended, but not mandatory.
        dec_ctx.*.pkt_timebase = in_stream.*.time_base;

        if (dec_ctx.*.codec_type == c.AVMEDIA_TYPE_VIDEO) {
            dec_ctx.*.framerate = c.av_guess_frame_rate(@constCast(ifmt_ctx), @constCast(in_stream), null);
            if (dec_ctx.*.framerate.num == 0 or dec_ctx.*.framerate.den == 0) {
                err.print("couldn't guess framerate", c.AVERROR(c.EINVAL));
                return AVError.EINVAL;
            }
            std.debug.print("Guessed framerate: {}/{}\n", .{ dec_ctx.*.framerate.num, dec_ctx.*.framerate.den });
        }

        ret = c.avcodec_open2(dec_ctx, dec, null);
        if (ret < 0) {
            err.print("avcodec_open2", ret);
            return ret_to_error(ret);
        }

        self.dec_ctx = dec_ctx;
        self.dec_frame = c.av_frame_alloc();
        if (self.dec_frame == null) {
            err.print("av_frame_alloc", c.AVERROR(c.ENOMEM));
            return AVError.ENOMEM;
        }

        return dec_ctx;
    }

    fn send_packet(self: *Decoder, pkt: ?*c.AVPacket) !void {
        const ret = c.avcodec_send_packet(self.dec_ctx, pkt);
        if (ret < 0) {
            err.print("avcodec_send_packet", ret);
            return ret_to_error(ret);
        }
    }

    fn receive_frame(self: *Decoder) !*c.AVFrame {
        const ret = c.avcodec_receive_frame(self.dec_ctx, self.dec_frame.?);
        if (ret < 0) {
            switch (ret) {
                c.AVERROR_EOF => return AVError.EOF,
                c.AVERROR(c.EAGAIN) => return AVError.EAGAIN,
                else => {
                    err.print("avcodec_receive_frame", ret);
                    return ret_to_error(ret);
                },
            }
        }
        return self.dec_frame.?;
    }

    fn deinit(self: *Decoder) void {
        if (self.dec_ctx != null) {
            c.avcodec_free_context(&self.dec_ctx);
        }
        if (self.dec_frame != null) {
            c.av_frame_free(&self.dec_frame);
        }
    }
};

const StreamContext = struct {
    in_stream: *c.AVStream,
    out_stream: *c.AVStream,

    ofmt_ctx: *c.AVFormatContext,
    decoder: *Decoder,
    encoder: *Encoder,

    input_index: usize,
    stream_index: usize,

    dts_offset: []i64,
    prev_dts: [][]i64,
    prev_duration: [][]i64,

    mux_dts_offset: []i64,
    prev_mux_dts: [][]i64,
    prev_mux_duration: [][]i64,

    fn transcode_write_frame(self: StreamContext, pkt: ?*c.AVPacket) !void {
        // Send packet to decoder
        try self.decoder.send_packet(pkt);

        while (true) {
            // Fetch decoded frame from decoded packet
            const frame = self.decoder.receive_frame() catch |e| switch (e) {
                AVError.EAGAIN => return,
                AVError.EOF => return,
                else => return e,
            };
            defer c.av_frame_unref(frame);

            frame.*.pts = frame.*.best_effort_timestamp;

            if (frame.*.pts != c.AV_NOPTS_VALUE) {
                frame.*.pts = c.av_rescale_q(frame.*.pts, self.decoder.dec_ctx.?.*.pkt_timebase, self.encoder.enc_ctx.?.*.time_base);
            }

            try self.encode_write_frame(frame);
        }
    }

    fn encode_write_frame(self: StreamContext, dec_frame: ?*c.AVFrame) !void {
        self.encoder.unref_pkt();

        try self.encoder.send_frame(dec_frame);

        while (true) {
            // Read encoded data from the encoder.
            var pkt = self.encoder.receive_packet() catch |e| switch (e) {
                AVError.EAGAIN => return,
                AVError.EOF => return,
                else => return e,
            };

            // Remux the packet
            pkt.stream_index = @as(c_int, @intCast(self.stream_index));

            // Encoder to output timebase
            c.av_packet_rescale_ts(pkt, self.encoder.enc_ctx.?.*.time_base, self.out_stream.*.time_base);

            try self.fix_monotonic_ts(pkt);

            // Write packet
            const ret = c.av_interleaved_write_frame(self.ofmt_ctx, pkt);
            if (ret < 0) {
                err.print("av_interleaved_write_frame", ret);
                return ret_to_error(ret);
            }
        }
    }

    fn flush_encoder(self: StreamContext) !void {
        if (self.encoder.enc_ctx.?.*.codec.*.capabilities & c.AV_CODEC_CAP_DELAY == 0) {
            return;
        }

        try self.encode_write_frame(null);
    }

    fn flush_decoder(self: StreamContext) !void {
        if (self.decoder.dec_ctx.?.*.codec.*.capabilities & c.AV_CODEC_CAP_DELAY == 0) {
            return;
        }

        try self.transcode_write_frame(null);
    }

    fn fix_discontinuity_ts(self: StreamContext, pkt: *c.AVPacket) !void {
        // Add past offsets.
        var delta: i64 = self.dts_offset[self.stream_index];

        if (self.prev_dts[self.input_index][self.stream_index] == c.AV_NOPTS_VALUE) {
            // Initial discontinuity
            delta -= pkt.dts;

            // Concatenation
            if (self.input_index > 0 and self.prev_dts[self.input_index - 1][self.stream_index] != c.AV_NOPTS_VALUE) {
                delta += self.prev_dts[self.input_index - 1][self.stream_index];
                delta += if (self.prev_duration[self.input_index - 1][self.stream_index] > 0) self.prev_duration[self.input_index - 1][self.stream_index] else 1;

                std.debug.print("Input {}, stream #{} ({s}) concatenation, last.dts={}, pkt.dts={}, new offset={}\n", .{ self.input_index, self.stream_index, c.av_get_media_type_string(self.out_stream.*.codecpar.*.codec_type), self.prev_dts[self.input_index - 1][self.stream_index], pkt.dts, delta });
                self.prev_dts[self.input_index][self.stream_index] = self.prev_dts[self.input_index - 1][self.stream_index];
                self.prev_duration[self.input_index][self.stream_index] = self.prev_duration[self.input_index - 1][self.stream_index];
            }
        }

        // Discontinuity detection
        // Set the dts_offset for the next iteration.
        if (self.prev_dts[self.input_index][self.stream_index] != c.AV_NOPTS_VALUE and
            self.prev_dts[self.input_index][self.stream_index] >= pkt.dts + delta)
        {
            // Offset because of discontinuity
            const old_delta = delta;
            delta = self.prev_dts[self.input_index][self.stream_index] - pkt.dts;
            delta += if (self.prev_duration[self.input_index][self.stream_index] > 0) self.prev_duration[self.input_index][self.stream_index] else 1;

            std.debug.print("Input {}, stream #{} ({s}) discontinuity, last.dts={}, pkt.dts={}, new offset={}\n", .{ self.input_index, self.stream_index, c.av_get_media_type_string(self.out_stream.*.codecpar.*.codec_type), self.prev_dts[self.input_index][self.stream_index], pkt.dts + old_delta, delta });
        }

        // std.debug.print("Input {}, stream #{} ({s}) old.dts={}, old.pts={}, new.dts={}, new.pts={}\n", .{ self.input_index, self.stream_index, c.av_get_media_type_string(self.out_stream.*.codecpar.*.codec_type), pkt.dts, pkt.pts, pkt.dts + delta, pkt.pts + delta });

        // Offsets the current packet
        pkt.dts += delta;
        if (pkt.pts != c.AV_NOPTS_VALUE)
            pkt.pts += delta;

        // Update the previous decoding timestamp
        self.prev_dts[self.input_index][self.stream_index] = pkt.dts;
        self.prev_duration[self.input_index][self.stream_index] = pkt.duration;
        self.dts_offset[self.stream_index] = delta;

        pkt.pos = -1;
    }

    fn fix_monotonic_ts(self: StreamContext, pkt: *c.AVPacket) !void {
        if (pkt.dts == c.AV_NOPTS_VALUE) {
            return;
        }

        // Add past offsets.
        var delta: i64 = self.mux_dts_offset[self.stream_index];

        // Discontinuity detection
        // Set the dts_offset for the next iteration.
        if (self.prev_mux_dts[self.input_index][self.stream_index] != c.AV_NOPTS_VALUE and
            self.prev_mux_dts[self.input_index][self.stream_index] >= pkt.dts + delta)
        {
            // Offset because of discontinuity
            delta = self.prev_mux_dts[self.input_index][self.stream_index] - pkt.dts;
            delta += if (self.prev_mux_duration[self.input_index][self.stream_index] > 0) self.prev_mux_duration[self.input_index][self.stream_index] else 1;

            std.debug.print("Input {}, stream #{} ({s}) non-monotonic, last.dts={}, pkt.dts={}, new offset={}\n", .{ self.input_index, self.stream_index, c.av_get_media_type_string(self.out_stream.*.codecpar.*.codec_type), self.prev_mux_dts[self.input_index][self.stream_index], pkt.dts, delta });
        }

        // Offsets the current packet
        pkt.dts += delta;
        if (pkt.pts != c.AV_NOPTS_VALUE)
            pkt.pts += delta;

        // Update the previous decoding timestamp
        self.prev_mux_dts[self.input_index][self.stream_index] = pkt.dts;
        self.prev_mux_duration[self.input_index][self.stream_index] = pkt.duration;
        self.mux_dts_offset[self.stream_index] = delta;

        pkt.pos = -1;
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
            return ret_to_error(ret);
        }
        defer c.avformat_close_input(&ifmt_ctx);

        // Retrieve input stream information
        ret = c.avformat_find_stream_info(ifmt_ctx, null);
        if (ret < 0) {
            err.print("avformat_find_stream_info", ret);
            return ret_to_error(ret);
        }

        // Print input information
        c.av_dump_format(ifmt_ctx, 0, input_file, 0);
    }
}

pub const ConcatOptions = struct {
    audio_only: bool = false,
    to_av1: bool = false,
};

const ConcatContext = struct {
    av_opts: ?*c.AVDictionary,
    pkt: *c.AVPacket,
    allocator: std.mem.Allocator,
    prev_dts: std.ArrayList([]i64),
    prev_duration: std.ArrayList([]i64),

    encoders: ?[]Encoder,
    decoders: std.ArrayList([]Decoder),
    stream_ctxs: std.ArrayList([]StreamContext),

    prev_mux_dts: std.ArrayList([]i64),
    prev_mux_duration: std.ArrayList([]i64),

    fn init(allocator: std.mem.Allocator, input_files_len: usize) !ConcatContext {
        const optional_pkt: ?*c.AVPacket = c.av_packet_alloc();
        if (optional_pkt == null) {
            err.print("av_packet_alloc", c.AVERROR(c.ENOMEM));
            return AVError.ENOMEM;
        }

        var prev_dts = try std.ArrayList([]i64).initCapacity(allocator, input_files_len);
        errdefer prev_dts.deinit();
        var prev_duration = try std.ArrayList([]i64).initCapacity(allocator, input_files_len);
        errdefer prev_duration.deinit();
        var decoders = try std.ArrayList([]Decoder).initCapacity(allocator, input_files_len);
        errdefer decoders.deinit();
        var stream_ctxs = try std.ArrayList([]StreamContext).initCapacity(allocator, input_files_len);
        errdefer stream_ctxs.deinit();
        var prev_mux_dts = try std.ArrayList([]i64).initCapacity(allocator, input_files_len);
        errdefer prev_mux_dts.deinit();
        var prev_mux_duration = try std.ArrayList([]i64).initCapacity(allocator, input_files_len);
        errdefer prev_mux_duration.deinit();

        // Set "faststart" option
        var optional_av_opts: ?*c.AVDictionary = null;
        const ret = c.av_dict_set(&optional_av_opts, "movflags", "faststart", 0);
        if (ret < 0) {
            err.print("av_dict_set", ret);
            return ret_to_error(ret);
        }

        return ConcatContext{
            .av_opts = optional_av_opts.?,
            .pkt = optional_pkt.?,
            .allocator = allocator,
            .prev_dts = prev_dts,
            .prev_duration = prev_duration,
            .decoders = decoders,
            .stream_ctxs = stream_ctxs,
            .prev_mux_dts = prev_mux_dts,
            .prev_mux_duration = prev_mux_duration,
            .encoders = null,
        };
    }

    fn alloc_prev_dts(self: *ConcatContext, stream_mapping_size: usize) !void {
        const prev_dts = try self.allocator.alloc(i64, stream_mapping_size);
        for (prev_dts) |*pdts| {
            pdts.* = c.AV_NOPTS_VALUE;
        }
        try self.prev_dts.append(prev_dts);
    }

    fn alloc_prev_duration(self: *ConcatContext, stream_mapping_size: usize) !void {
        const prev_duration = try self.allocator.alloc(i64, stream_mapping_size);
        for (prev_duration) |*ppts| {
            ppts.* = 0;
        }
        try self.prev_duration.append(prev_duration);
    }

    fn alloc_prev_mux_dts(self: *ConcatContext, stream_mapping_size: usize) !void {
        const prev_mux_dts = try self.allocator.alloc(i64, stream_mapping_size);
        for (prev_mux_dts) |*pdts| {
            pdts.* = c.AV_NOPTS_VALUE;
        }
        try self.prev_mux_dts.append(prev_mux_dts);
    }

    fn alloc_prev_mux_duration(self: *ConcatContext, stream_mapping_size: usize) !void {
        const prev_mux_duration = try self.allocator.alloc(i64, stream_mapping_size);
        for (prev_mux_duration) |*ppts| {
            ppts.* = 0;
        }
        try self.prev_mux_duration.append(prev_mux_duration);
    }

    fn alloc_encoders(self: *ConcatContext, stream_mapping_size: usize) !void {
        self.encoders = try self.allocator.alloc(Encoder, stream_mapping_size);
        for (self.encoders.?) |*tc| {
            tc.* = .{};
        }
    }

    fn alloc_decoders(self: *ConcatContext, stream_mapping_size: usize) !void {
        const decoders = try self.allocator.alloc(Decoder, stream_mapping_size);
        for (decoders) |*dec| {
            dec.* = .{};
        }
        try self.decoders.append(decoders);
    }

    fn alloc_stream_ctxs(self: *ConcatContext, stream_mapping_size: usize) !void {
        const stream_ctxs = try self.allocator.alloc(StreamContext, stream_mapping_size);
        try self.stream_ctxs.append(stream_ctxs);
    }

    fn deinit(self: ConcatContext) void {
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

        for (self.prev_mux_dts.items) |pdts| {
            self.allocator.free(pdts);
        }
        self.prev_mux_dts.deinit();

        for (self.prev_mux_duration.items) |ppts| {
            self.allocator.free(ppts);
        }
        self.prev_mux_duration.deinit();

        for (self.decoders.items) |decoders| {
            for (decoders) |*tc| {
                tc.deinit();
            }
            self.allocator.free(decoders);
        }
        self.decoders.deinit();

        if (self.encoders != null) {
            self.allocator.free(self.encoders.?);
        }
    }
};

pub fn concat(output_file: [:0]const u8, input_files: []const [:0]const u8, opts: ConcatOptions) !void {
    c.av_log_set_level(c.AV_LOG_INFO);

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
    var ret = c.avformat_alloc_output_context2(&optional_ofmt_ctx, null, null, output_file.ptr);
    if (ret < 0) {
        err.print("avformat_alloc_output_context2", ret);
        return ret_to_error(ret);
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
        ret = c.avformat_open_input(&optional_ifmt_ctx, input_file.ptr, null, null);
        if (ret < 0) {
            err.print("avformat_open_input", ret);
            return ret_to_error(ret);
        }
        defer c.avformat_close_input(&optional_ifmt_ctx);
        const ifmt_ctx = optional_ifmt_ctx.?;

        // Find input stream info
        ret = c.avformat_find_stream_info(ifmt_ctx, null);
        if (ret < 0) {
            err.print("avformat_find_stream_info", ret);
            return ret_to_error(ret);
        }

        c.av_dump_format(ifmt_ctx, 0, input_file.ptr, 0);

        // Alloc array of streams
        const stream_mapping_size = ifmt_ctx.nb_streams;
        var stream_mapping = try allocator.alloc(i64, stream_mapping_size);
        defer allocator.free(stream_mapping);
        var dts_offset = try allocator.alloc(i64, stream_mapping_size);
        for (dts_offset) |*dts| {
            dts.* = 0;
        }
        defer allocator.free(dts_offset);
        var mux_dts_offset = try allocator.alloc(i64, stream_mapping_size);
        for (mux_dts_offset) |*dts| {
            dts.* = 0;
        }
        defer allocator.free(mux_dts_offset);

        try ctx.alloc_decoders(stream_mapping_size);
        if (input_idx == 0) {
            try ctx.alloc_encoders(stream_mapping_size);
        }
        try ctx.alloc_prev_dts(stream_mapping_size);
        try ctx.alloc_prev_duration(stream_mapping_size);
        try ctx.alloc_stream_ctxs(stream_mapping_size);
        try ctx.alloc_prev_mux_dts(stream_mapping_size);
        try ctx.alloc_prev_mux_duration(stream_mapping_size);

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
                if (opts.to_av1 and in_codecpar.*.codec_type == c.AVMEDIA_TYPE_VIDEO and in_codecpar.*.codec_id != c.AV_CODEC_ID_AV1) {
                    _ = try ctx.decoders.items[input_idx][out_stream_index].prepare_decoder(ifmt_ctx, in_stream);
                }

                // Only create streams based on the first video.
                // I.e., arrangement of streams is based on the first video.
                if (input_idx == 0) {
                    const out_stream = c.avformat_new_stream(optional_ofmt_ctx, null);
                    if (out_stream == null) {
                        err.print("avformat_new_stream", c.AVERROR(c.ENOMEM));
                        return AVError.ENOMEM;
                    }
                    switch (in_codecpar.*.codec_type) {
                        c.AVMEDIA_TYPE_VIDEO => {
                            if (opts.to_av1 and ctx.decoders.items[input_idx][out_stream_index].dec_ctx != null) {
                                const enc_ctx = try ctx.encoders.?[out_stream_index].prepare_encoder(ofmt_ctx, ctx.decoders.items[input_idx][out_stream_index].dec_ctx.?);

                                // Copy codec parameters
                                ret = c.avcodec_parameters_from_context(out_stream.*.codecpar, enc_ctx);
                                if (ret < 0) {
                                    err.print("avcodec_parameters_from_context", ret);
                                    return ret_to_error(ret);
                                }

                                out_stream.*.time_base = enc_ctx.*.time_base;
                            } else {
                                // Remux
                                ret = c.avcodec_parameters_copy(out_stream.*.codecpar, in_codecpar);
                                if (ret < 0) {
                                    err.print("avcodec_parameters_copy", ret);
                                    return ret_to_error(ret);
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
                                return ret_to_error(ret);
                            }
                            out_stream.*.codecpar.*.codec_tag = 0;
                            out_stream.*.time_base = c.AVRational{ .num = 1, .den = in_codecpar.*.sample_rate };
                        },
                        else => {
                            // Remux
                            ret = c.avcodec_parameters_copy(out_stream.*.codecpar, in_codecpar);
                            if (ret < 0) {
                                err.print("avcodec_parameters_copy", ret);
                                return ret_to_error(ret);
                            }
                            out_stream.*.codecpar.*.codec_tag = 0;
                        },
                    }

                    std.debug.print("Created output stream #{} ({s})\n", .{ out_stream_index, c.av_get_media_type_string(in_codecpar.*.codec_type) });
                }

                // Set to zero
                dts_offset[out_stream_index] = 0;
                mux_dts_offset[out_stream_index] = 0;

                // DTS and PTS of last input file for concatenation
                ctx.stream_ctxs.items[input_idx][out_stream_index] = .{
                    .in_stream = in_stream,
                    .out_stream = ofmt_ctx.streams[out_stream_index],
                    .ofmt_ctx = ofmt_ctx,
                    .dts_offset = dts_offset,
                    .prev_dts = ctx.prev_dts.items,
                    .prev_duration = ctx.prev_duration.items,
                    .mux_dts_offset = mux_dts_offset,
                    .prev_mux_dts = ctx.prev_mux_dts.items,
                    .prev_mux_duration = ctx.prev_mux_duration.items,
                    .stream_index = out_stream_index,
                    .input_index = input_idx,
                    .decoder = &ctx.decoders.items[input_idx][out_stream_index],
                    .encoder = &ctx.encoders.?[out_stream_index],
                };
            }
        }

        // Write header based on the first input file
        if (input_idx == 0) {
            c.av_dump_format(ofmt_ctx, 0, output_file.ptr, 1);

            // Open output file with avio
            if (ofmt_ctx.oformat.*.flags & c.AVFMT_NOFILE == 0) {
                ret = c.avio_open(&ofmt_ctx.pb, output_file.ptr, c.AVIO_FLAG_WRITE);
                if (ret < 0) {
                    err.print("avio_open", ret);
                    return ret_to_error(ret);
                }
            }
            // Note: checks for avio_close is above.

            // Write header
            ret = c.avformat_write_header(ofmt_ctx, &ctx.av_opts);
            if (ret < 0) {
                err.print("avformat_write_header", ret);
                return ret_to_error(ret);
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
            ctx.pkt.stream_index = @as(c_int, @intCast(out_stream_index));

            const stream_ctx = ctx.stream_ctxs.items[input_idx][out_stream_index];

            if (opts.to_av1 and stream_ctx.encoder.enc_ctx != null) {
                try stream_ctx.fix_discontinuity_ts(ctx.pkt);

                // Input to decoder timebase
                try stream_ctx.transcode_write_frame(ctx.pkt);
            } else {
                c.av_packet_rescale_ts(ctx.pkt, stream_ctx.in_stream.*.time_base, stream_ctx.out_stream.*.time_base);

                try stream_ctx.fix_discontinuity_ts(ctx.pkt);

                ret = c.av_interleaved_write_frame(ofmt_ctx, ctx.pkt);
                if (ret < 0) {
                    err.print("av_interleaved_write_frame", ret);
                    return ret_to_error(ret);
                }
            }
        } // while packets.
    } // for each input.

    if (opts.to_av1) {
        // Flush decoders and encoders
        for (ctx.stream_ctxs.items[input_files.len - 1]) |*sc| {
            if (sc.decoder.dec_ctx != null) {
                try sc.flush_decoder();
            }
            if (sc.encoder.enc_ctx != null) {
                try sc.flush_encoder();
            }
        }
    }

    // Write trailer: file is ready and readable.
    _ = c.av_write_trailer(optional_ofmt_ctx);
}

fn print_avcodecpar(codecpar: *c.AVCodecParameters) void {
    std.debug.print("Codec type: {s}\n", .{c.av_get_media_type_string(codecpar.*.codec_type)});
    std.debug.print("Codec: {s}\n", .{c.avcodec_get_name(codecpar.*.codec_id)});
    std.debug.print("Codec tag: {}\n", .{codecpar.*.codec_tag});

    for (0..@as(usize, @intCast(codecpar.*.extradata_size))) |i| {
        std.debug.print("Codec extra data: {}\n", .{codecpar.*.extradata[i]});
    }
    std.debug.print("Format: {}\n", .{codecpar.*.format});
    std.debug.print("Bit rate: {}\n", .{codecpar.*.bit_rate});
    std.debug.print("Profile: {}\n", .{codecpar.*.profile});
    std.debug.print("Level: {}\n", .{codecpar.*.level});
    std.debug.print("Width: {}\n", .{codecpar.*.width});
    std.debug.print("Height: {}\n", .{codecpar.*.height});
    std.debug.print("Sample aspect ratio: {}/{}\n", .{ codecpar.*.sample_aspect_ratio.num, codecpar.*.sample_aspect_ratio.den });
    std.debug.print("Field order: {}\n", .{codecpar.*.field_order});
    std.debug.print("Color range: {}\n", .{codecpar.*.color_range});
    std.debug.print("Color primaries: {}\n", .{codecpar.*.color_primaries});
    std.debug.print("Color transfer: {}\n", .{codecpar.*.color_trc});
    std.debug.print("Color space: {}\n", .{codecpar.*.color_space});
    std.debug.print("Chroma location: {}\n", .{codecpar.*.chroma_location});
    std.debug.print("Video delay: {}\n", .{codecpar.*.video_delay});
    std.debug.print("Channel layout: {}\n", .{codecpar.*.channel_layout});
    std.debug.print("Channels: {}\n", .{codecpar.*.channels});
    std.debug.print("Sample rate: {}\n", .{codecpar.*.sample_rate});
    std.debug.print("Block align: {}\n", .{codecpar.*.block_align});
    std.debug.print("Frame size: {}\n", .{codecpar.*.frame_size});
    std.debug.print("Initial padding: {}\n", .{codecpar.*.initial_padding});
    std.debug.print("Trailing padding: {}\n", .{codecpar.*.trailing_padding});
    std.debug.print("Seek preroll: {}\n", .{codecpar.*.seek_preroll});
    std.debug.print("Channel layout(order={}, nb_channels={})\n", .{ codecpar.*.ch_layout.order, codecpar.*.ch_layout.nb_channels });
    std.debug.print("Frame rate: {}/{}\n", .{ codecpar.*.framerate.num, codecpar.*.framerate.den });

    for (0..@as(usize, @intCast(codecpar.*.nb_coded_side_data))) |i| {
        std.debug.print("Coded Side data: {}\n", .{codecpar.*.coded_side_data[i]});
    }
}
