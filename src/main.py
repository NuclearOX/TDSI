import os
import pandas as pd
import logging
import sys
from tqdm import tqdm
from src.mining.terrads_loader import load_repositories
from src.mining.repo_miner import RepoMiner
from src import config
import multiprocessing
import time

# --- ADVANCED LOGGING CONFIGURATION ---
# We use 'a' (append) mode to preserve logs across system restarts or crashes
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# File Handler: writes to execution.log
file_handler = logging.FileHandler(config.LOG_FILE_PATH, mode='a') 
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

# Console Handler: writes to standard output (terminal)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.INFO)

# Root Logger Setup
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

# Clear existing handlers to prevent duplicate logs on re-import
if root_logger.hasHandlers():
    root_logger.handlers.clear()

root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

# SILENCE THIRD-PARTY LOGS
# Mute PyDriller info logs to prevent "Commit #... filtered" spam in the terminal
logging.getLogger("pydriller").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# --- MULTIPROCESSING WORKER ---
def analyze_repo_worker(repo_url, repo_name, queue):
    """
    Independent worker function to be executed in a separate process.
    Allows for isolation and hard-timeout management of resource-heavy repositories.
    """
    try:
        miner = RepoMiner(repo_url, repo_name)
        results = []
        # mine_history returns a generator, we collect data points into a list
        for data_point in miner.mine_history():
            results.append(data_point)
        # Push collected data to the shared queue
        queue.put(results)
    except Exception as e:
        logger.error(f"Worker crashed for {repo_name}: {e}")

def main():
    logger.info("="*60)
    logger.info("--- TERRAFORM QUALITY & SECURITY EVOLUTION MINER START ---")
    logger.info("="*60)
    logger.info(f"Database Path: {config.DB_PATH}")
    logger.info(f"Target Output: {config.OUTPUT_CSV_PATH}")

    # --- RESUME LOGIC (Checkpointing) ---
    # We check the existing CSV to identify repositories that have already been processed.
    # This ensures resilience against system crashes or power failures.
    completed_repos = set()
    if os.path.exists(config.OUTPUT_CSV_PATH) and os.path.getsize(config.OUTPUT_CSV_PATH) > 0:
        try:
            df_existing = pd.read_csv(config.OUTPUT_CSV_PATH, usecols=['repo_name'])
            completed_repos = set(df_existing['repo_name'].unique())
            logger.info(f"Found {len(completed_repos)} already processed repositories. They will be skipped.")
        except Exception as e:
            logger.warning(f"Could not read existing results for resume logic: {e}. Starting from scratch.")

    # 1. LOAD TARGET REPOSITORIES from TerraDS
    df_repos = load_repositories(
        db_path=config.DB_PATH, 
        min_stars=config.MIN_STARS, 
        limit=config.REPO_LIMIT
    )
    
    if df_repos.empty:
        logger.error("No target repositories found. Check database or sampling criteria.")
        return

    logger.info(f"Total targets to evaluate: {len(df_repos)} repositories.")

    # 2. MAIN ANALYSIS LOOP
    pbar = tqdm(df_repos.iterrows(), total=df_repos.shape[0], desc="Overall Progress", unit="repo")
    
    for index, row in pbar:
        repo_url = row['GitUrl']
        repo_name = row['Name']
        
        # SKIP LOGIC
        if repo_name in completed_repos:
            continue

        pbar.set_description(f"Processing {repo_name}")

        # Initialize inter-process communication queue
        queue = multiprocessing.Queue()
        
        # Launch analysis in a separate process
        process = multiprocessing.Process(
            target=analyze_repo_worker, 
            args=(repo_url, repo_name, queue)
        )
        process.start()
        
        # Wait for the process to finish or hit the global timeout (e.g., 1 hour)
        process.join(timeout=config.REPO_ANALYSIS_TIMEOUT)
        
        # TIMEOUT MANAGEMENT
        if process.is_alive():
            logger.warning(f"TIMEOUT: {repo_name} exceeded {config.REPO_ANALYSIS_TIMEOUT}s limit. Terminating.")
            process.terminate()
            process.join()
            continue # Move to the next repository

        # RETRIEVE RESULTS
        try:
            # We use get_nowait because the process is finished, the queue should have data
            repo_results = queue.get_nowait()
        except Exception:
            repo_results = []

        # 3. INCREMENTAL SAVING (Append Mode)
        if repo_results:
            df_chunk = pd.DataFrame(repo_results)
            
            # Determine if we need to write the CSV header
            file_exists = os.path.exists(config.OUTPUT_CSV_PATH)
            write_header = not file_exists or os.path.getsize(config.OUTPUT_CSV_PATH) == 0
            
            df_chunk.to_csv(config.OUTPUT_CSV_PATH, mode='a', header=write_header, index=False)
            logger.info(f"Successfully saved {len(repo_results)} snapshots for {repo_name}.")
            file_handler.flush() # Ensure logs are written to disk
        else:
            logger.warning(f"No valid IaC data points extracted for {repo_name}.")

    logger.info("="*60)
    logger.info("--- ANALYSIS COMPLETE ---")
    logger.info("="*60)

if __name__ == "__main__":
    # Fix for Windows multiprocessing support
    multiprocessing.freeze_support()
    main()