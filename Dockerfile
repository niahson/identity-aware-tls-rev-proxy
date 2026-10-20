# syntax=docker/dockerfile:1
FROM rust:1.85-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,id=identity-proxy-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=identity-proxy-target,target=/build/target \
    cargo build --locked --release --bin identity-aware-tls-rev-proxy \
    && cp /build/target/release/identity-aware-tls-rev-proxy /build/identity-aware-tls-rev-proxy

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 arkion-proxy \
    && useradd --create-home --shell /usr/sbin/nologin \
        --uid 10001 --gid 10001 arkion-proxy

COPY --from=builder /build/identity-aware-tls-rev-proxy /usr/local/bin/identity-aware-tls-rev-proxy

USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/identity-aware-tls-rev-proxy"]
