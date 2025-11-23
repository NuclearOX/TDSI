FROM python:3.11-slim

# 1. Install dependencies (curl to get Trivy)
RUN apt-get update && \
    apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*

# 2. Install Trivy (The actual scanner binary)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# 3. Set up Application Directory
WORKDIR /app

# 4. Copy Python Scripts
COPY . /app

# 5. Install Python Deps
RUN pip install --no-cache-dir -r requirements.txt

# 6. Entrypoint
ENTRYPOINT ["python", "run_analyzer.py"]