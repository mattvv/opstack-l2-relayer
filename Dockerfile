# If destined for AWS ECS, we need to install OpenSSL runtime libraries and
# use this Docker base image to be compatible with Fargate. It's possible to
# move to an alpine image but the cross compilation is more significantly more complex.
FROM rust:1.79-slim-buster AS builder

# We need libssl-dev pkg-config for OpenSSL
RUN apt-get update && apt-get install -y libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs && \
    cargo build --release && \
    rm -f target/release/deps/explore_rs*

COPY src ./src
RUN cargo build --release

# Final stage
FROM rust:1.79-slim-buster

# Install OpenSSL runtime libraries
RUN apt-get update && apt-get install -y libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/bin
COPY --from=builder /usr/src/app/target/release/relayer .

CMD ["./relayer"]
