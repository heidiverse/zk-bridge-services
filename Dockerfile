FROM rust:1.91-slim-bookworm AS builder
RUN apt-get update && apt-get install -y \
    libssl-dev \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Setup project strucutre
RUN mkdir -p /app/next-gen-signatures/src /app/next-gen-signing-service/src

COPY ./Cargo.toml /app/Cargo.toml
COPY ./Cargo.lock /app/Cargo.lock
COPY ./next-gen-signatures /app/next-gen-signatures
COPY ./next-gen-signing-service /app/next-gen-signing-service
COPY ./rdf-util /app/rdf-util
COPY ./zkp-util /app/zkp-util

RUN cargo build --release



FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/next-gen-signing-service /usr/bin/web-server
# NOTE: Config is loaded dynamically at startup so we can add it after building.
COPY ./Rocket.toml /app/Rocket.toml
COPY ./jsonld /app/jsonld

CMD ["/usr/bin/web-server"]
