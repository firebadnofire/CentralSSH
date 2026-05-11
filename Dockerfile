# syntax=docker/dockerfile:1

FROM rust:1.89-bookworm AS builder

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tools ./tools
COPY examples ./examples

RUN cargo build --locked --release && strip target/release/centralssh

FROM debian:bookworm-slim AS runtime

ENV CENTRALSSH_LOG=info \
    CENTRALSSH_LOG_FORMAT=json \
    CENTRALSSH_HEALTHCHECK_TARGET=127.0.0.1:7788

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates netcat-openbsd openssh-client tini \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/centralssh /var/lib/centralssh/keys /var/log/centralssh /usr/local/share/centralssh/examples

COPY --from=builder /src/target/release/centralssh /usr/local/sbin/centralssh
COPY --from=builder /src/tools/cssh-keyscan /usr/local/bin/cssh-keyscan
COPY --from=builder /src/examples/config.toml /usr/local/share/centralssh/examples/config.toml
COPY --from=builder /src/examples/servers.toml /usr/local/share/centralssh/examples/servers.toml
COPY container/entrypoint.sh /usr/local/bin/centralssh-entrypoint
COPY container/healthcheck.sh /usr/local/bin/centralssh-healthcheck

RUN chmod 0755 /usr/local/sbin/centralssh /usr/local/bin/cssh-keyscan /usr/local/bin/centralssh-entrypoint /usr/local/bin/centralssh-healthcheck \
    && chmod 0700 /etc/centralssh /var/lib/centralssh /var/lib/centralssh/keys /var/log/centralssh

EXPOSE 7788/tcp
VOLUME ["/etc/centralssh", "/var/lib/centralssh", "/var/log/centralssh"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/centralssh-entrypoint"]
CMD ["/usr/local/sbin/centralssh"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["/usr/local/bin/centralssh-healthcheck"]
