FROM rust:latest as builder

# Install dependencies
RUN apt-get update && apt-get install -y cmake llvm clang libclang-dev

# Install dependency builder for cargo
RUN cargo install cargo-build-deps

# That would be cached if Cargo.lock haven't been changed
RUN cd /tmp && USER=root cargo new --bin project
WORKDIR /tmp/project
COPY Cargo.toml Cargo.lock rust-toolchain ./
RUN cargo build-deps --release

# Copy the rest of sources & build
COPY src/ ./src
COPY cli.yml ./cli.yml
RUN cargo build --release
RUN mkdir /build -p && cp ./target/release/jade-signer /build/

# Runtume image is Ubuntu 18.04, 'cause it's the base image of rust:latest
FROM ubuntu:18.04

USER root
WORKDIR /root
COPY --from=builder /build/jade-signer /usr/bin/

# Run cmd
CMD /usr/bin/jade-signer server
