# Multi-stage build for optimal image size and security
FROM rust:1.75-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy dependency files first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this layer will be cached unless Cargo.toml changes)
RUN cargo build --release && rm -rf src

# Copy source code
COPY src ./src
COPY config ./config

# Build the actual application
RUN cargo build --release

# Runtime stage - use distroless for minimal attack surface
FROM gcr.io/distroless/cc-debian12:latest

# Copy CA certificates for HTTPS requests
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/target/release/api-gateway /usr/local/bin/api-gateway

# Copy configuration files
COPY --from=builder /app/config /etc/gateway/config

# Create non-root user (distroless already provides this)
USER nonroot:nonroot

# Expose ports
EXPOSE 8080 8443 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/api-gateway", "--health-check"]

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/api-gateway"]
CMD ["--config", "/etc/gateway/config/gateway.yaml"]