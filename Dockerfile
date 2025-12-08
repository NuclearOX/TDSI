# Dockerfile

# Stage 1: Get TFLint binary
FROM alpine:latest AS builder
RUN apk --no-cache add wget unzip
WORKDIR /tmp
# Download TFLint (Linux AMD64)
# Note: Check latest version if needed, v0.50.3 is stable
RUN wget https://github.com/terraform-linters/tflint/releases/download/v0.50.3/tflint_linux_amd64.zip && \
    unzip tflint_linux_amd64.zip

# Stage 2: Final Image
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y curl git && \
    rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install TFLint
COPY --from=builder /tmp/tflint /usr/local/bin/

# --- NEW: Install TFLint Config & Plugins ---
# 1. Copy the default config to the app directory
COPY .tflint.hcl /root/.tflint.hcl

# 2. Run init to download the 'recommended' plugin into the container layer
# This prevents TFLint from trying to download it at runtime (which is slow/flaky)
RUN tflint --init --config /root/.tflint.hcl

WORKDIR /app
COPY . /app

# Install Python deps
RUN pip install -r requirements.txt

ENTRYPOINT ["python", "run_analyzer.py"]