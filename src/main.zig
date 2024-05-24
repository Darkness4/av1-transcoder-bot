const std = @import("std");
const av = @import("av.zig");
const cli = @import("zig-cli");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const gpa_allocator = gpa.allocator();

var arena = std.heap.ArenaAllocator.init(gpa_allocator);
const arena_allocator = arena.allocator();

var config = struct {
    inputs: []const []const u8 = undefined,
    output: []const u8 = "out.mp4",
    audio_only: bool = false,
    to_av1: bool = true,
}{};

pub fn main() !void {
    defer std.debug.assert(gpa.deinit() == .ok);
    defer arena.deinit();

    var r = try cli.AppRunner.init(arena_allocator);

    const app = cli.App{
        .command = cli.Command{
            .name = "transcode",
            .options = &.{
                .{
                    .long_name = "in",
                    .help = "Input files",
                    .short_alias = 'i',
                    .required = true,
                    .value_ref = r.mkRef(&config.inputs),
                },
                .{
                    .long_name = "out",
                    .help = "Output file",
                    .short_alias = 'o',
                    .value_ref = r.mkRef(&config.output),
                },
                .{
                    .long_name = "audio-only",
                    .help = "Only copy audio",
                    .short_alias = 'a',
                    .value_ref = r.mkRef(&config.audio_only),
                },
                .{
                    .long_name = "to-av1",
                    .help = "Convert to AV1",
                    .value_ref = r.mkRef(&config.to_av1),
                },
            },
            .target = cli.CommandTarget{
                .action = cli.CommandAction{
                    .exec = run_concat,
                },
            },
        },
    };

    return r.run(&app);
}

fn run_concat() !void {
    const output = try arena_allocator.dupeZ(u8, config.output);
    const inputs = try arena_allocator.alloc([:0]const u8, config.inputs.len);
    for (config.inputs, 0..config.inputs.len) |input, i| {
        const input_dup = try arena_allocator.dupeZ(u8, input);

        inputs[i] = input_dup;
    }

    try av.concat(output, inputs, .{
        .audio_only = config.audio_only,
        .to_av1 = config.to_av1,
    });
}
