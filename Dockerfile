# Use an official lightweight Python runtime as a parent image
FROM python:3.11-slim

# Metadata description for the research project
LABEL description="Replication Package for Terraform Quality & Security Evolution Analysis"

# Set environment variables for Python performance and stability
# PYTHONDONTWRITEBYTECODE: Prevents Python from writing .pyc files
# PYTHONUNBUFFERED: Ensures that python output is sent straight to terminal (useful for logging)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 1. Update + Install System Dependencies
# git: required by PyDriller for repository mining
# curl: required to download the Trivy installation script
# ca-certificates: required for secure downloads
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Trivy (Security Scanner)
# Downloads and executes the official installation script
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# 3. Pre-download Trivy databases
# We download both the Vulnerability DB and the Misconfiguration (IaC) bundle
# This prevents network-related timeouts during the long mining process
RUN trivy fs --download-db-only && \
    trivy fs . --download-db-only

# 4. Set the working directory inside the container
WORKDIR /app

# 5. Install Python dependencies
# Copy requirements file first to leverage Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 6. Copy the source code into the container
COPY src/ ./src/

# 7. Create data directories for input (TerraDS) and output (CSV/Logs)
# These should be mounted as volumes during execution
RUN mkdir -p /app/data/input /app/data/output

# 8. Set Python Path and Entrypoint
# We set PYTHONPATH to /app so that 'src' is recognized as a package
ENV PYTHONPATH="/app"

# We execute the main script as a module (-m) to handle relative imports correctly
ENTRYPOINT ["python", "-m", "src.main"]