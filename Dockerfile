# Usa un'immagine base leggera di Python
FROM python:3.11-slim

# Metadati
LABEL description="Replication Package for Terraform Quality & Security Evolution"

# Variabili d'ambiente per Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 1. Installazione dipendenze di sistema
# git: necessario per PyDriller
# curl: necessario per scaricare Trivy
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 2. Installazione di Trivy (Security Scanner)
# Scarica ed esegue lo script ufficiale di installazione
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Questo crea la cache in /root/.cache/trivy
RUN trivy image --download-db-only

# 3. Setup dell'ambiente di lavoro
WORKDIR /app

# 4. Installazione dipendenze Python
# Copiamo prima il requirements per sfruttare la cache di Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copia del codice sorgente
COPY src/ ./src/

# 6. Creazione directory per i dati (punto di mount)
RUN mkdir -p /app/data/input /app/data/output

# 7. Comando di default
# Esegue lo script principale. 
# Assumiamo che main.py sia dentro src/ ma lo eseguiamo come modulo per gestire gli import
ENV PYTHONPATH="/app"
ENTRYPOINT ["python", "-m", "src.main"]