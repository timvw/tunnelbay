# syntax=docker/dockerfile:1.6

FROM rust:1.91 AS builder
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY proto/Cargo.toml proto/Cargo.toml
COPY buoy/Cargo.toml buoy/Cargo.toml
COPY bay/Cargo.toml bay/Cargo.toml
RUN mkdir -p proto/src buoy/src bay/src && \
    echo 'pub fn stub() {}' > proto/src/lib.rs && \
    echo 'fn main() {}' > buoy/src/main.rs && \
    echo 'fn main() {}' > bay/src/main.rs && \
    cargo build --release -p buoy --target x86_64-unknown-linux-musl

RUN rm -rf proto/src buoy/src bay/src
COPY . .
RUN cargo build --release -p buoy --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/buoy /buoy
ENTRYPOINT ["/buoy"]
