# syntax=docker.io/docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# VettID push gateway — small, non-root, static, reproducible image.
#   docker build -t vettid-push .
#   docker buildx build --platform linux/amd64,linux/arm64 -t vettid-push .
#   make image-repro        # two clean builds, compared
# Binary path is stable: /vettid-push. Container health check:
# /vettid-push -healthcheck
#
# Reproducible: both base images are pinned by digest, the build is
# -trimpath with an empty build id and no VCS stamping, and nothing but
# the binary is added. With a fixed SOURCE_DATE_EPOCH (make image-repro)
# two builds of one commit give the same image.

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.10-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X main.version=${VERSION}" -o /out/vettid-push ./cmd/vettid-push

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/vettid-push /vettid-push
USER 65532:65532
ENV PUSH_LISTEN_ADDR=:8080
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 CMD ["/vettid-push", "-healthcheck"]
ENTRYPOINT ["/vettid-push"]
