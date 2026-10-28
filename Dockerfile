# syntax=docker/dockerfile:1

# The build stage runs on the build machine's CPU and cross-compiles for the
# target, so a multi-arch build never runs the Go toolchain under emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.1 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# notray leaves out the system tray, which a container has no use for.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags notray -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/netscan ./cmd/netscan
RUN mkdir /out/data

# distroless/static has CA certificates, time zone data and a nonroot user
# (UID 65532), but no shell or package manager.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="NetScan" \
      org.opencontainers.image.description="Internet stability monitor" \
      org.opencontainers.image.source="https://github.com/aaronburt/netscan"

COPY --from=build /out/netscan /usr/local/bin/netscan
# Owned by the nonroot user, so a new named volume starts out writable.
COPY --from=build --chown=65532:65532 /out/data /data

ENV NETSCAN_CONTAINER=1 \
    NETSCAN_DATA_DIR=/data

# The dashboard binds to loopback. With host networking that is the host's
# loopback, so open it on the host or through an SSH tunnel.
EXPOSE 9095

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/netscan", "-headless"]
