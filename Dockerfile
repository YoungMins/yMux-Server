# syntax=docker/dockerfile:1

# 1. Build the web app (PWA) with Node 22 and pnpm.
FROM node:22-alpine AS web
WORKDIR /src/web
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

# 2. Build the server (pure Rust TLS client, no OpenSSL) with the PWA embedded.
FROM rust:1-alpine AS server
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY --from=web /src/web/dist ./web/dist
RUN cargo build --release --locked

# 3. Small runtime image, non-root, state in /data.
FROM alpine:3
RUN addgroup -S ymux && adduser -S -G ymux -H -h /data ymux \
 && mkdir -p /data && chown ymux:ymux /data
COPY --from=server /src/target/release/ymux-server /usr/local/bin/ymux-server
ENV YMUX_SERVER_BIND=0.0.0.0:8787 \
    YMUX_SERVER_DATA_DIR=/data
USER ymux
VOLUME /data
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8787/healthz || exit 1
ENTRYPOINT ["ymux-server"]
