# ---------------------------------------------------
FROM --platform=${BUILDPLATFORM} ghcr.io/darkness4/av1-transcoder:base as builder
# ---------------------------------------------------

WORKDIR /work

COPY . .

RUN zig build -Doptimize=ReleaseFast -Dstatic

# ----------
FROM --platform=${TARGETPLATFORM} scratch
# ----------

COPY --from=builder /work/zig-out/bin/av1-transcoder /transcoder

ENTRYPOINT ["/transcoder"]

