import os
import json
import pandas as pd
import logging
import sys
from tqdm import tqdm
from src.mining.terrads_loader import load_repositories
from src.mining.repo_miner import RepoMiner
from src import config
import multiprocessing
import multiprocessing.queues

# =============================================================================
# LOGGING CONFIGURATION
# Append mode ('a') preserves logs across restarts and crashes.
# The output directory is created before the FileHandler is instantiated to
# avoid a FileNotFoundError if the directory does not yet exist.
# =============================================================================
os.makedirs(config.DATA_OUTPUT_DIR, exist_ok=True)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# open(config.LOG_FILE_PATH, 'a').close()
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


# =============================================================================
# CONFIGURATION
#
# TARGET_REPOS      : desired number of repositories with actual data in the
#                     final CSV. Repos that fail (timeout, clone error, no .tf
#                     files) do NOT count toward this target.
# DROPOUT_BUFFER    : multiplier on the batch size requested from the loader to
#                     compensate for expected failures.
# MAX_MINING_ROUNDS : hard cap on retry rounds — safety guard against infinite
#                     loops when the candidate pool is nearly exhausted.
# =============================================================================
TARGET_REPOS      = config.REPO_LIMIT   # 500
DROPOUT_BUFFER    = 1.1
MAX_MINING_ROUNDS = 10


# =============================================================================
# CHECKPOINT HELPERS
#
# Two-file checkpointing strategy:
#
#   OUTPUT_CSV_PATH       — append-only raw data; one row per snapshot.
#   COMPLETED_REPOS_PATH  — JSON list of ALL repo names that have been
#                           fully attempted, regardless of outcome.
#                           This includes both repos with data in the CSV
#                           AND repos that produced no data (failures).
#
# The distinction between "attempted" and "has data in CSV" is critical:
#   * attempted_repos  = set loaded from COMPLETED_REPOS_PATH
#                        used as exclude_repos for the loader so that
#                        failed repos are never re-sampled.
#   * repos_in_csv     = _count_repos_in_csv()
#                        the TRUE progress metric used to decide whether
#                        the TARGET_REPOS goal has been reached.
#
# Recovery procedure on restart
# ──────────────────────────────
# 1. Read COMPLETED_REPOS_PATH  →  set of all attempted repo names.
# 2. Read CSV repo_name column  →  set of names with rows in the file.
# 3. Incomplete = (in CSV) − (attempted).  At most ONE such repo exists
#    (the one being processed when the crash occurred).
# 4. Strip its rows from the CSV; it will be re-attempted in the next round.
# =============================================================================

COMPLETED_REPOS_PATH = os.path.join(config.DATA_OUTPUT_DIR, "attempted_repos.json")


def _load_attempted_repos() -> set:
    """
    Returns the set of all repo names that have been fully attempted in a
    prior run, regardless of whether they produced data.
    """
    if not os.path.exists(COMPLETED_REPOS_PATH):
        return set()
    try:
        with open(COMPLETED_REPOS_PATH, 'r') as fh:
            data = json.load(fh)
        return set(data)
    except Exception as e:
        logger.warning(f"Could not read attempted-repos file: {e}. Treating as empty.")
        return set()


def _mark_repo_attempted(repo_name: str) -> None:
    """
    Records repo_name as fully attempted (atomic read-modify-write).
    Called after processing regardless of outcome — both successes and
    failures are recorded here so they are never re-sampled.
    """
    attempted = _load_attempted_repos()
    attempted.add(repo_name)
    tmp_path = COMPLETED_REPOS_PATH + ".tmp"
    try:
        with open(tmp_path, 'w') as fh:
            json.dump(sorted(attempted), fh, indent=2)
        os.replace(tmp_path, COMPLETED_REPOS_PATH)  # atomic on POSIX
    except Exception as e:
        logger.error(f"Failed to update attempted-repos file for {repo_name}: {e}")


def _count_repos_in_csv() -> int:
    """
    Returns the number of distinct repositories that have at least one row
    in the output CSV.

    This is the TRUE progress metric: it counts only repos that were
    successfully mined and produced data, excluding repos that were attempted
    but failed (timeout, clone error, no .tf files). Those are tracked
    separately in COMPLETED_REPOS_PATH.
    """
    if not os.path.exists(config.OUTPUT_CSV_PATH):
        return 0
    if os.path.getsize(config.OUTPUT_CSV_PATH) == 0:
        return 0
    try:
        df = pd.read_csv(config.OUTPUT_CSV_PATH, usecols=['repo_name'])
        return df['repo_name'].nunique()
    except Exception as e:
        logger.warning(f"Could not count repos in CSV: {e}. Returning 0.")
        return 0


def _recover_partial_csv(attempted_repos: set) -> None:
    """
    Detects and removes rows belonging to any repo that is present in the
    CSV but absent from the attempted list (i.e. interrupted mid-run).

    At most one such repo can exist. The function rewrites the CSV in place
    after stripping the orphaned rows so the repo will be re-attempted.
    """
    if not os.path.exists(config.OUTPUT_CSV_PATH):
        return
    if os.path.getsize(config.OUTPUT_CSV_PATH) == 0:
        return

    try:
        df = pd.read_csv(config.OUTPUT_CSV_PATH)
    except Exception as e:
        logger.warning(f"Could not read CSV for recovery check: {e}")
        return

    all_in_csv = set(df['repo_name'].unique())
    incomplete  = all_in_csv - attempted_repos

    if not incomplete:
        logger.info("Checkpoint integrity OK — no partial repos detected in CSV.")
        return

    for repo_name in incomplete:
        n_rows = (df['repo_name'] == repo_name).sum()
        logger.warning(
            f"Detected incomplete repo '{repo_name}' ({n_rows} orphaned rows). "
            f"Removing from CSV and scheduling for reprocessing."
        )
        df = df[df['repo_name'] != repo_name]

    df.to_csv(config.OUTPUT_CSV_PATH, index=False)
    logger.info(f"CSV rewritten after removing {len(incomplete)} incomplete repo(s).")


# =============================================================================
# MULTIPROCESSING WORKER
# =============================================================================

def analyze_repo_worker(
    repo_url: str,
    repo_name: str,
    result_queue: multiprocessing.Queue,
) -> None:
    """
    Entry point for the child process.

    Mines the full history of one repository and pushes the collected data
    points into result_queue. An empty list is pushed on failure so that
    the parent's queue.get() unblocks immediately instead of waiting for
    the full timeout.
    """
    try:
        miner = RepoMiner(repo_url, repo_name)
        results = [dp for dp in miner.mine_history()]
        result_queue.put(results)
    except Exception as e:
        logger.error(f"Worker crashed for {repo_name}: {e}")
        result_queue.put([])


# =============================================================================
# SINGLE-REPO PROCESSING
# =============================================================================

def _process_single_repo(repo_url: str, repo_name: str) -> list:
    """
    Spawns an isolated child process for one repository, enforces the
    wall-clock timeout, and returns the list of collected data points
    (empty list on failure or timeout).
    """
    result_queue = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=analyze_repo_worker,
        args=(repo_url, repo_name, result_queue),
    )
    process.start()

    repo_results: list = []
    try:
        repo_results = result_queue.get(timeout=config.REPO_ANALYSIS_TIMEOUT)
        process.join()

    except multiprocessing.queues.Empty:
        logger.warning(
            f"TIMEOUT: {repo_name} exceeded {config.REPO_ANALYSIS_TIMEOUT}s. "
            f"Terminating process."
        )
        if process.is_alive():
            process.terminate()
        process.join()

    except Exception as e:
        logger.error(f"Unexpected error retrieving results for {repo_name}: {e}")
        if process.is_alive():
            process.terminate()
        process.join()

    finally:
        result_queue.close()
        result_queue.join_thread()

    return repo_results


def _save_repo_results(repo_name: str, repo_results: list) -> None:
    """
    Writes repo_results to the CSV (append mode) and marks the repo as
    attempted in the checkpoint file.

    Both successes (data written to CSV) and failures (empty list) are
    marked as attempted so they are never re-sampled in future rounds.
    The write-then-mark order guarantees that a crash between the two
    operations is detected and recovered on the next restart.
    """
    if repo_results:
        df_chunk = pd.DataFrame(repo_results)
        write_header = (
            not os.path.exists(config.OUTPUT_CSV_PATH)
            or os.path.getsize(config.OUTPUT_CSV_PATH) == 0
        )
        df_chunk.to_csv(config.OUTPUT_CSV_PATH, mode='a', header=write_header, index=False)
        file_handler.flush()
        _mark_repo_attempted(repo_name)
        logger.info(f"Saved and marked attempted: {repo_name} ({len(repo_results)} snapshots).")
    else:
        # Failure (timeout, clone error, no .tf files): no data written to CSV.
        # Mark as attempted so it is excluded from future sampling rounds,
        # but it does NOT count toward TARGET_REPOS (tracked via CSV count).
        _mark_repo_attempted(repo_name)
        logger.warning(
            f"No valid IaC data points for {repo_name}. "
            f"Marked as attempted (will not count toward target)."
        )


# =============================================================================
# MAIN ORCHESTRATION
# =============================================================================

def main() -> None:
    logger.info("=" * 60)
    logger.info("--- TERRAFORM QUALITY & SECURITY EVOLUTION MINER START ---")
    logger.info("=" * 60)
    logger.info(f"Database Path    : {config.DB_PATH}")
    logger.info(f"Target Output    : {config.OUTPUT_CSV_PATH}")
    logger.info(f"Attempted list   : {COMPLETED_REPOS_PATH}")
    logger.info(f"Target repos     : {TARGET_REPOS} (repos with data in CSV)")
    logger.info(f"Dropout buffer   : {DROPOUT_BUFFER}x")
    logger.info(f"Max rounds       : {MAX_MINING_ROUNDS}")
    logger.info(f"Min stars        : {config.MIN_STARS}")
    logger.info(f"Repo timeout (s) : {config.REPO_ANALYSIS_TIMEOUT}")

    # -------------------------------------------------------------------------
    # CHECKPOINT RECOVERY
    # Load all previously attempted repos, then strip any partial CSV data
    # from the repo that was being processed when the last crash occurred.
    # -------------------------------------------------------------------------
    attempted_repos = _load_attempted_repos()
    logger.info(f"Repos attempted in prior runs: {len(attempted_repos)}")

    _recover_partial_csv(attempted_repos)

    repos_in_csv = _count_repos_in_csv()
    logger.info(f"Repos with data in CSV: {repos_in_csv}/{TARGET_REPOS}")

    # -------------------------------------------------------------------------
    # DYNAMIC SAMPLING LOOP
    #
    # Progress is measured by _count_repos_in_csv() — the number of repos
    # that actually produced data — NOT by len(attempted_repos), which
    # includes failures and would cause the loop to stop prematurely.
    #
    # attempted_repos is passed as exclude_repos to the loader so that both
    # successful and failed repos are never re-sampled in later rounds.
    # -------------------------------------------------------------------------
    for round_num in range(1, MAX_MINING_ROUNDS + 1):

        repos_in_csv = _count_repos_in_csv()
        repos_needed = TARGET_REPOS - repos_in_csv

        if repos_needed <= 0:
            logger.info(
                f"Target of {TARGET_REPOS} repositories reached "
                f"({repos_in_csv} repos with data in CSV). Mining complete."
            )
            break

        batch_size = max(1, int(repos_needed * DROPOUT_BUFFER))

        logger.info(
            f"Round {round_num}/{MAX_MINING_ROUNDS} — "
            f"have {repos_in_csv}/{TARGET_REPOS} repos with data, "
            f"need {repos_needed} more, "
            f"requesting batch of {batch_size} (buffer {DROPOUT_BUFFER}x)."
        )

        df_batch = load_repositories(
            db_path=config.DB_PATH,
            min_stars=config.MIN_STARS,
            limit=batch_size,
            exclude_repos=attempted_repos,
        )

        if df_batch.empty:
            logger.warning(
                "Candidate pool exhausted — no more unseen repositories "
                "satisfy the star filter. Stopping."
            )
            break

        logger.info(f"Batch contains {len(df_batch)} candidates.")

        pbar = tqdm(
            df_batch.iterrows(),
            total=df_batch.shape[0],
            desc=f"Round {round_num}",
            unit="repo",
        )

        for _, row in pbar:
            repo_url:  str = row['GitUrl']
            repo_name: str = row['Name']

            # Guard: skip if somehow already attempted (e.g. duplicate Name
            # returned by the loader due to a race condition or DB quirk).
            if repo_name in attempted_repos:
                continue

            # Register as attempted immediately — before processing starts —
            # so that a crash during mining excludes this repo from future
            # rounds even if _save_repo_results is never reached.
            attempted_repos.add(repo_name)

            pbar.set_description(f"Round {round_num} — {repo_name}")

            repo_results = _process_single_repo(repo_url, repo_name)
            _save_repo_results(repo_name, repo_results)

            # Re-read CSV count after each repo to get the accurate progress.
            repos_in_csv = _count_repos_in_csv()

            # Early exit from the inner loop if target is already reached
            # mid-batch, avoiding unnecessary mining of remaining candidates.
            if repos_in_csv >= TARGET_REPOS:
                logger.info(
                    f"Target reached mid-batch: {repos_in_csv}/{TARGET_REPOS} "
                    f"repos with data in CSV. Stopping early."
                )
                break

    # -------------------------------------------------------------------------
    # FINAL SUMMARY
    # -------------------------------------------------------------------------
    final_csv_count      = _count_repos_in_csv()
    final_attempted_count = len(_load_attempted_repos())

    logger.info("=" * 60)
    logger.info(f"Repos with data in CSV : {final_csv_count}/{TARGET_REPOS}")
    logger.info(f"Total repos attempted  : {final_attempted_count}")
    logger.info(f"Failed / no data       : {final_attempted_count - final_csv_count}")

    if final_csv_count >= TARGET_REPOS:
        logger.info("--- MINING COMPLETE ---")
    else:
        logger.warning(
            f"--- MINING ENDED EARLY: target not reached. "
            f"Candidate pool may be exhausted or MAX_MINING_ROUNDS exceeded. ---"
        )
    logger.info("=" * 60)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()