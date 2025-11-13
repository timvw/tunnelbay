# syntax=docker/dockerfile:1.20

FROM rust:1.91 AS builder
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /app

# Dependency caching
COPY Cargo.toml Cargo.lock ./
COPY proto/Cargo.toml proto/Cargo.toml
COPY bay/Cargo.toml bay/Cargo.toml
COPY buoy/Cargo.toml buoy/Cargo.toml
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends musl-tools && \
    ln -sf /usr/bin/musl-gcc /usr/bin/x86_64-unknown-linux-musl-gcc && \
    rm -rf /var/lib/apt/lists/*

# Actual build
COPY . .
RUN cargo build --release -p bay --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/bay /bay
ENTRYPOINT ["/bay"]
