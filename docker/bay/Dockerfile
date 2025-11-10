# syntax=docker/dockerfile:1.6

FROM rust:1.91 AS builder
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /app

# Dependency caching
COPY Cargo.toml Cargo.lock ./
COPY proto/Cargo.toml proto/Cargo.toml
COPY bay/Cargo.toml bay/Cargo.toml
COPY buoy/Cargo.toml buoy/Cargo.toml
RUN mkdir -p proto/src bay/src buoy/src && \
    echo 'pub fn stub() {}' > proto/src/lib.rs && \
    echo 'fn main() {}' > bay/src/main.rs && \
    echo 'fn main() {}' > buoy/src/main.rs && \
    cargo build --release -p bay --target x86_64-unknown-linux-musl

# Actual build
RUN rm -rf proto/src bay/src buoy/src
COPY . .
RUN cargo build --release -p bay --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/bay /bay
ENTRYPOINT ["/bay"]
