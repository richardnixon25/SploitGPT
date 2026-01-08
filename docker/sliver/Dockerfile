# SploitGPT Sliver C2 Server Container
# Downloads and runs Sliver server in daemon mode for gRPC API access
#
# Build:
#   podman build -t localhost/sploitgpt-sliver:latest -f docker/sliver/Dockerfile .
#
# Run standalone:
#   podman run -d --name sliver \
#     -p 31337:31337 -p 8888:8888 -p 80:80 -p 443:443 \
#     -v sliver-data:/root/.sliver \
#     localhost/sploitgpt-sliver:latest

FROM debian:bookworm-slim

LABEL maintainer="SploitGPT"
LABEL description="Sliver C2 Server for SploitGPT integration"
LABEL version="1.6.1"

ARG SLIVER_VERSION=v1.6.1
ARG TARGETARCH=amd64

# Install runtime dependencies
# - ca-certificates: HTTPS downloads and TLS
# - curl: healthcheck and downloads
# - mingw-w64: Cross-compilation for Windows implants
# - gcc, g++: Native compilation for Linux implants
# - git: Some armory packages need git
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    mingw-w64 \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Download Sliver server binary
RUN curl -fsSL "https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-server_linux-${TARGETARCH}" \
    -o /usr/local/bin/sliver-server \
    && chmod +x /usr/local/bin/sliver-server

# Download Sliver client binary (for operator config generation)
RUN curl -fsSL "https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-client_linux-${TARGETARCH}" \
    -o /usr/local/bin/sliver-client \
    && chmod +x /usr/local/bin/sliver-client

# Create data directories
RUN mkdir -p /root/.sliver /app/configs

# Unpack embedded assets on first run (creates ~/.sliver structure)
# This pre-generates the assets so container startup is faster
RUN /usr/local/bin/sliver-server unpack --force

WORKDIR /app

# Expose ports:
# 31337 - Operator gRPC API (mTLS)
# 8888  - Default mTLS implant listener
# 80    - HTTP C2
# 443   - HTTPS C2
# 53    - DNS C2 (UDP)
# 8080  - HTTP stager
EXPOSE 31337 8888 80 443 53/udp 8080

# Persist Sliver data (configs, implants, loot, etc.)
VOLUME ["/root/.sliver"]

# Healthcheck - verify daemon is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -fsS http://127.0.0.1:31337/health 2>/dev/null || \
        test -S /root/.sliver/configs/server.json

# Entrypoint script for flexible startup
COPY docker/sliver/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["daemon"]
