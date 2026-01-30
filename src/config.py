import os

# --- Percorsi ---
# Usiamo percorsi assoluti basati sulla struttura del container Docker
BASE_DIR = "/app"
DATA_INPUT_DIR = os.path.join(BASE_DIR, "data", "input")
DATA_OUTPUT_DIR = os.path.join(BASE_DIR, "data", "output")

# File specifici
DB_PATH = os.path.join(DATA_INPUT_DIR, "TerraDS.sqlite")
OUTPUT_CSV_PATH = os.path.join(DATA_OUTPUT_DIR, "dataset_final.csv")
LOG_FILE_PATH = os.path.join(DATA_OUTPUT_DIR, "execution.log")

# --- Configurazioni Mining ---
# Strategia "Caccia al Tesoro":
# Abbassiamo a 30 stelle per includere progetti meno "perfetti" e più dinamici.
MIN_STARS = 30          

# Analizziamo 50 repository. Statisticamente, su 50 ne troveremo almeno 
# 5-10 con una storia evolutiva interessante per la RQ3.
REPO_LIMIT = 50        

# --- Strategia di Analisi (Adaptive) ---
# Numero massimo di versioni da analizzare per ogni repository.
# Aumentato a 100 per catturare una storia profonda (anni di sviluppo).
MAX_SNAPSHOTS = 100      

# --- NUOVO: TIMEOUT PER REPOSITORY ---
# Se l'analisi di un singolo repo dura più di 1 ora (3600s), viene interrotta e si passa al successivo.
# Questo evita che un repo "impossibile" blocchi l'intera analisi.
REPO_ANALYSIS_TIMEOUT = 3600 

# --- Pesi Sicurezza (Security Debt) ---
# Basati su CVSS e letteratura (Rahman et al. 2019)
SEVERITY_WEIGHTS = {
    'CRITICAL': 9.5,
    'HIGH': 8.0,
    'MEDIUM': 5.0,
    'LOW': 2.0,
    'UNKNOWN': 0.0
}