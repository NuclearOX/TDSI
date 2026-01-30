import os
import pandas as pd
import logging
import sys
from tqdm import tqdm
from src.mining.terrads_loader import load_repositories
from src.mining.repo_miner import RepoMiner
from src import config
import multiprocessing

# --- CONFIGURAZIONE LOGGING AVANZATA ---
# Cambiamo la modalità del file a 'a' (append) per non perdere i log vecchi al riavvio
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler = logging.FileHandler(config.LOG_FILE_PATH, mode='a') 
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.INFO)
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
if root_logger.hasHandlers():
    root_logger.handlers.clear()
root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)
logging.getLogger("pydriller").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

# --- FUNZIONE WORKER (invariata) ---
def analyze_repo_worker(repo_url, repo_name, queue):
    miner = RepoMiner(repo_url, repo_name)
    results = []
    for data_point in miner.mine_history():
        results.append(data_point)
    queue.put(results)

def main():
    logger.info("="*50)
    logger.info("--- AVVIO/RIPRESA TERRA QUALITY MINER ---")
    logger.info("="*50)
    
    # --- LOGICA DI RIPRESA ---
    completed_repos = set()
    if os.path.exists(config.OUTPUT_CSV_PATH):
        try:
            # Leggiamo il CSV esistente per sapere cosa abbiamo già fatto
            df_existing = pd.read_csv(config.OUTPUT_CSV_PATH)
            if 'repo_name' in df_existing.columns:
                completed_repos = set(df_existing['repo_name'].unique())
                logger.info(f"Trovati {len(completed_repos)} repository già analizzati nel CSV. Verranno saltati.")
        except Exception as e:
            logger.warning(f"Impossibile leggere il CSV esistente per la ripresa: {e}. L'analisi ripartirà da zero.")

    # 1. Caricamento Target
    df_repos = load_repositories(
        db_path=config.DB_PATH, 
        min_stars=config.MIN_STARS, 
        limit=config.REPO_LIMIT
    )
    if df_repos.empty:
        logger.error("Nessun repository trovato.")
        return
    logger.info(f"Target totali da considerare: {len(df_repos)} repository.")

    # 2. Loop di Analisi
    pbar = tqdm(df_repos.iterrows(), total=df_repos.shape[0], desc="Repo Progress", unit="repo")
    
    for index, row in pbar:
        repo_url = row['GitUrl']
        repo_name = row['Name']
        
        # --- CONTROLLO PER SALTARE ---
        if repo_name in completed_repos:
            pbar.set_description(f"Skipping {repo_name}")
            continue # Salta al prossimo repository

        pbar.set_description(f"Processing {repo_name}")

        queue = multiprocessing.Queue()
        process = multiprocessing.Process(target=analyze_repo_worker, args=(repo_url, repo_name, queue))
        process.start()
        process.join(timeout=config.REPO_ANALYSIS_TIMEOUT)
        
        if process.is_alive():
            logger.warning(f"TIMEOUT raggiunto per {repo_name}. Processo terminato.")
            process.terminate()
            process.join()
            continue

        try:
            repo_results = queue.get_nowait()
        except Exception:
            repo_results = []

        # 3. Salvataggio Incrementale
        if repo_results:
            df_chunk = pd.DataFrame(repo_results)
            header = not os.path.exists(config.OUTPUT_CSV_PATH)
            df_chunk.to_csv(config.OUTPUT_CSV_PATH, mode='a', header=header, index=False)
            logger.info(f"Salvati {len(repo_results)} snapshot per {repo_name}.")
        else:
            logger.warning(f"Nessun dato utile estratto per {repo_name}.")

    logger.info("--- ANALISI COMPLETATA ---")

if __name__ == "__main__":
    main()