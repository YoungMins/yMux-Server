# syntax=docker/dockerfile:1

# 1. Build the web app (PWA) with Node 22 and pnpm.
FROM node:22-alpine AS web
WORKDIR /src/web
# pnpm 10 like CI (newer majors refuse a lockfile with packages younger than a day).
RUN corepack enable && corepack prepare pnpm@10 --activate
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

# 2. Build the server (pure Rust TLS client, no OpenSSL) with the PWA embedded.
FROM rust:1-alpine AS server
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
# Dependencies first: this layer is rebuilt only when Cargo.toml / Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
 && echo 'fn main() {}' > src/main.rs \
 && echo '' > src/lib.rs \
 && echo 'fn main() {}' > build.rs \
 && cargo build --release --locked \
 && rm -rf src build.rs
COPY build.rs ./
COPY src ./src
COPY --from=web /src/web/dist ./web/dist
# The stub build above leaves newer-looking artifacts for the crate itself: force a rebuild.
RUN touch src/main.rs src/lib.rs build.rs && cargo build --release --locked

# 3. Small runtime image, non-root, state in /data.
FROM alpine:3
LABEL org.opencontainers.image.title="yMux server" \
      org.opencontainers.image.description="Relay between a yMux desktop and your phone (PWA, WebSocket relay, Web Push)" \
      org.opencontainers.image.source="https://github.com/YoungMins/yMux-Server" \
      org.opencontainers.image.licenses="MIT"
# /data is created owned by the service user, so a new named volume (which copies this
# directory's ownership on first use) is writable without running as root.
RUN addgroup -S ymux && adduser -S -G ymux -H -h /data ymux \
 && mkdir -p /data && chown ymux:ymux /data
COPY --from=server /src/target/release/ymux-server /usr/local/bin/ymux-server
ENV YMUX_SERVER_BIND=0.0.0.0:11020 \
    YMUX_SERVER_DATA_DIR=/data
USER ymux
VOLUME /data
EXPOSE 11020
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD wget -qO- http://127.0.0.1:11020/healthz >/dev/null || exit 1
ENTRYPOINT ["ymux-server"]
