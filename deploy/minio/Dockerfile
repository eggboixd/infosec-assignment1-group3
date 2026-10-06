# syntax=docker/dockerfile:1
#
# MinIO no longer publishes public container images and its repositories are
# archived, so this builds the last community releases of the server and the
# mc client from source at pinned commits.
#   minio RELEASE.2025-10-15T17-29-55Z
#   mc    RELEASE.2025-08-13T08-35-41Z

# ---- build ----
# Go version matches the upstream toolchain lines in each go.mod.
FROM golang:1.24.8-alpine AS build
RUN apk add --no-cache git
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
ARG MINIO_COMMIT=9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a
ARG MC_COMMIT=7394ce0dd2a80935aded936b09fa12cbb3cb8096

WORKDIR /src/minio
RUN git init -q . \
 && git fetch -q --depth 1 https://github.com/minio/minio.git "${MINIO_COMMIT}" \
 && git checkout -q FETCH_HEAD \
 && go build -tags kqueue -trimpath -ldflags "$(go run buildscripts/gen-ldflags.go)" -o /out/minio .

WORKDIR /src/mc
RUN git init -q . \
 && git fetch -q --depth 1 https://github.com/minio/mc.git "${MC_COMMIT}" \
 && git checkout -q FETCH_HEAD \
 && go build -tags kqueue -trimpath -ldflags "$(go run buildscripts/gen-ldflags.go)" -o /out/mc .

# ---- run ----
# Alpine provides the shell used by the minio-init job and wget for the
# healthcheck.
FROM alpine:3.24
RUN addgroup -S -g 10001 minio \
 && adduser -S -D -H -u 10001 -G minio minio \
 && mkdir -p /data \
 && chown minio:minio /data
COPY --from=build /out/minio /out/mc /usr/local/bin/
USER minio
ENV MC_CONFIG_DIR=/tmp/.mc
EXPOSE 9000 9001
ENTRYPOINT ["minio"]
CMD ["server", "/data", "--console-address", ":9001"]
