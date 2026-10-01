# LombokMiner Docker Image
# Build:  docker build -t lombokminer:latest .
# Run:    docker run -d -p 8080:8080 -v ./lombokminer.toml:/etc/lombokminer/lombokminer.toml lombokminer:latest mine

FROM rust:1.80-slim AS builder

RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl --bin lombokminer

# Minimal production image — no OS, no shell, just the binary
FROM scratch

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/lombokminer /lombokminer
COPY --from=builder /build/dashboard/index.html /dashboard/index.html

EXPOSE 8080 9100 4028

ENTRYPOINT ["/lombokminer"]
CMD ["mine"]
