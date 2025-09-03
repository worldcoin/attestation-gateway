####################################################################################################
## Base image
####################################################################################################
FROM public.ecr.aws/docker/library/rust:1-bookworm AS chef
USER root
WORKDIR /app
RUN cargo install cargo-chef

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked

####################################################################################################
## Final image
####################################################################################################
FROM scratch
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/release/attestation-gateway /app/attestation-gateway

USER 100
EXPOSE 8000
CMD ["/app/attestation-gateway"]