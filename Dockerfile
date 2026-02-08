ARG CADDY_VERSION=
FROM caddy:${CADDY_VERSION}builder AS builder
RUN caddy-builder \
    github.com/caddy-dns/gigahost

FROM caddy:${CADDY_VERSION}alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
