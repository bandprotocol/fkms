# Build stage
FROM rust:1.85.1-slim AS builder
WORKDIR /usr/src/app
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 fkms
USER fkms
WORKDIR /home/fkms

# Copy the binary from builder
COPY --from=builder /usr/src/app/target/release/fkms /usr/local/bin/fkms

# Set the entrypoint
CMD ["fkms", "start"]
