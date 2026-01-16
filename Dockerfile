FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/rgregg/meshcore-proxy"
LABEL org.opencontainers.image.description="TCP proxy for MeshCore companion radios"
LABEL org.opencontainers.image.licenses="MIT"

# Install system dependencies for BLE support
RUN apt-get update && apt-get install -y --no-install-recommends \
    bluez \
    bluetooth \
    libbluetooth-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash meshcore \
    && usermod -aG dialout meshcore \
    && usermod -aG bluetooth meshcore

WORKDIR /app

# Copy package files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the package
RUN pip install --no-cache-dir .

# Switch to non-root user
USER meshcore

# Default port
EXPOSE 5000

# Default command (override with actual connection args)
ENTRYPOINT ["meshcore-proxy"]
CMD ["--help"]
