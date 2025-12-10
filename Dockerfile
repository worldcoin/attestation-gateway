####################################################################################################
## Base image
####################################################################################################
FROM rust:1.85.1-slim AS chef
USER root
WORKDIR /app

# Install dependencies for cross-compilation (perl & make are required for openssl-sys)
RUN apt-get update && apt-get install -y \
    musl-tools \
    ca-certificates \
    perl \
    make \
 && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

RUN cargo install cargo-chef

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM planner AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --target x86_64-unknown-linux-musl

####################################################################################################
## Final image
####################################################################################################
FROM scratch
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/attestation-gateway /app/attestation-gateway

USER 100
EXPOSE 8000
CMD ["/app/attestation-gateway"]