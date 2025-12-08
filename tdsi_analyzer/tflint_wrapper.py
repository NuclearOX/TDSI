import subprocess
import json
import shutil
import logging
import sys
import os

logger = logging.getLogger("TFLintWrapper")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('[%(asctime)s] [TFLINT] %(message)s', datefmt='%H:%M:%S'))
    logger.addHandler(handler)

SEVERITY_WEIGHTS = {
    'error': 10,
    'warning': 5,
    'notice': 2
}

DEFAULT_CONFIG_PATH = "/root/.tflint.hcl"

def run_tflint_analysis(base_directory: str):
    """
    Recursively finds all directories containing .tf files and runs TFLint on them.
    Aggregates findings into a single result structure.
    """
    if not shutil.which("tflint"):
        logger.error("CRITICAL: TFLint executable not found in PATH.")
        return {"issues": []}

    combined_issues = []
    scanned_dirs_count = 0
    issues_found_count = 0

    # 1. Identify all subdirectories that contain at least one .tf file
    dirs_to_scan = set()
    for root, _, files in os.walk(base_directory):
        # Skip hidden folders and terraform cache
        if "/." in root or "\\." in root: continue
        
        if any(f.endswith(".tf") for f in files):
            dirs_to_scan.add(root)
    
    if not dirs_to_scan:
        logger.warning(f"No .tf files found in {base_directory} or subdirectories.")
        return {"issues": []}

    logger.info(f"Found {len(dirs_to_scan)} subdirectories. Starting scan...")

    # 2. Run TFLint on each directory
    for subdir in dirs_to_scan:
        issues = _scan_single_directory(subdir)
        scanned_dirs_count += 1
        
        if issues:
            combined_issues.extend(issues)
            issues_found_count += len(issues)

    logger.info(f"Scan complete. Directories: {scanned_dirs_count}, Total Issues: {issues_found_count}")
    return {"issues": combined_issues}

def _scan_single_directory(path_to_scan: str):
    """Helper to run TFLint on one specific folder."""
    
    local_config = os.path.join(path_to_scan, ".tflint.hcl")
    
    # Base command
    cmd_args = ["tflint", "--format=json", "--chdir", path_to_scan]

    # FORCE CONFIG: Always use our global config if local is missing
    # This ensures plugins (AWS/GCP) are actually loaded!
    if not os.path.exists(local_config):
        if os.path.exists(DEFAULT_CONFIG_PATH):
            cmd_args.extend(["--config", DEFAULT_CONFIG_PATH])
        else:
            logger.warning("Global TFLint config not found! Scans might be ineffective.")

    try:
        # Run TFLint
        result = subprocess.run(cmd_args, capture_output=True, text=True, check=False)
        
        # --- DEBUG AGGIUNTO ---
        # Se TFLint scrive qualcosa in stderr (es. plugin mancante), stampalo come warning
        if result.stderr:
             # Filtra messaggi innocui se necessario, ma per ora stampiamo tutto per capire
             logger.warning(f"TFLint STDERR in {os.path.basename(path_to_scan)}: {result.stderr.strip()[:300]}")
        # ----------------------

        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                return data.get("issues", [])
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from TFLint in {path_to_scan}")
                
    except Exception as e:
        logger.error(f"Execution failed for {path_to_scan}: {e}")
    
    return []

def calculate_tflint_score(tflint_json) -> float:
    """Calculates a raw score based on aggregated findings."""
    if not tflint_json or 'issues' not in tflint_json:
        return 0.0
    
    score = 0.0
    for issue in tflint_json['issues']:
        sev = issue['rule']['severity']
        weight = SEVERITY_WEIGHTS.get(sev, 1)
        score += weight
        
    return score