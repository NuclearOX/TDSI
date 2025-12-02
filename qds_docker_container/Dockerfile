# --- STAGE 1: Builder ---
# Utilizziamo un'immagine minima (Alpine Linux) solo per scaricare tflint.
# Questo approccio, chiamato "multi-stage build", rende l'immagine finale più piccola e pulita.
FROM alpine:latest as builder

# Installiamo i pacchetti necessari per scaricare (wget) e scompattare (unzip)
RUN apk --no-cache add wget unzip

# Creiamo una cartella di lavoro temporanea
WORKDIR /tmp

# Scarichiamo la versione di tflint specifica per Linux (amd64 è per processori standard).
# NOTA: Controlla sempre la pagina delle release di tflint su GitHub per la versione più recente.
# Link: https://github.com/terraform-linters/tflint/releases
RUN wget https://github.com/terraform-linters/tflint/releases/download/v0.50.3/tflint_linux_amd64.zip && \
    unzip tflint_linux_amd64.zip

# --- STAGE 2: Immagine Finale ---
# Partiamo da un'immagine Python ufficiale e leggera.
FROM python:3.9-slim

# Impostiamo la directory di lavoro all'interno del container.
# Tutti i comandi successivi verranno eseguiti da questo percorso.
WORKDIR /app

# Copiamo l'eseguibile tflint (per Linux!) dallo stage precedente in una directory di sistema.
# /usr/local/bin è un percorso standard per gli eseguibili e fa sì che 'tflint' sia
# richiamabile direttamente da qualsiasi punto nel container.
COPY --from=builder /tmp/tflint /usr/local/bin/

# Come buona pratica, verifichiamo che tflint sia stato installato correttamente.
# Questo comando verrà eseguito durante la costruzione dell'immagine.
RUN tflint --version

# Ora copiamo i nostri file di progetto nella directory /app
COPY qds_terraform_calculator.py .
COPY codici_terraform/ ./codici_terraform/

# Questo è il comando che verrà eseguito automaticamente all'avvio del container.
CMD ["python", "./qds_terraform_calculator.py"]