import os
import json
import logging
import argparse
import sys
from tdsi_analyzer.security_analyzer import run_trivy_scan, calculate_sds, count_terraform_resources
from calibrate import calibrate_weights_from_results

# Configure logging to stderr so it doesn't corrupt JSON output
logger = logging.getLogger("Runner")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('[%(asctime)s] [RUNNER] %(message)s'))
    logger.addHandler(handler)

# Define Output Paths
OUTPUT_DIR = "output"
WEIGHTS_FILE = os.path.join(OUTPUT_DIR, "calibrated_weights.json")

def perform_calibration(project_directories):
    logger.info("==========================================")
    logger.info(f"   STARTING CALIBRATION: {len(project_directories)} PROJECTS")
    logger.info("==========================================")
    
    all_scans = []
    project_resources = {}

    # 1. Data Collection Loop
    for i, path in enumerate(project_directories):
        if not os.path.exists(path): 
            logger.warning(f"Path not found: {path}")
            continue
        
        logger.info(f"[{i+1}/{len(project_directories)}] Scanning: {os.path.basename(path)}")
        
        # Trivy Scan
        scan = run_trivy_scan(path)
        if scan:
            scan['project_path'] = path
            all_scans.append(scan)
        
        # Resource Counting
        res_count = count_terraform_resources(path)
        project_resources[path] = res_count

    if not all_scans:
        logger.error("No valid scans collected. Calibration aborted.")
        return

    # 2. Math & Logic
    calib_data = calibrate_weights_from_results(all_scans, project_resources)

    # 3. Persistence
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        logger.info(f"Created output directory: {OUTPUT_DIR}")
    
    with open(WEIGHTS_FILE, "w") as f:
        json.dump(calib_data, f, indent=2)
        
    logger.info("==========================================")
    logger.info(f"Calibration Complete.")
    logger.info(f"Weights saved to: {WEIGHTS_FILE}")
    logger.info("==========================================")

def perform_scoring(directory):
    logger.info(f"--- Initiating Scoring Mode for: {directory} ---")
    
    if not os.path.exists(WEIGHTS_FILE):
        logger.error(f"Weights file not found at {WEIGHTS_FILE}.")
        logger.error("Please run with --calibrate first to generate the baseline.")
        sys.exit(1)
        
    sds = calculate_sds(directory)
    
    # FINAL OUTPUT: JSON to Stdout
    result = {
        "project": directory,
        "sds": sds,
        "timestamp": str(os.times())
    }
    # This print statement is the ONLY output to stdout
    print(json.dumps(result))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TDSI Security Debt Analyzer")
    parser.add_argument("projects", nargs="+", help="List of project directories to process")
    parser.add_argument("--calibrate", action="store_true", help="Run in calibration mode")
    parser.add_argument("--scan-subdirs", action="store_true", help="Treat subdirectories of the input path as separate projects")
    
    args = parser.parse_args()

    targets = []
    for p in args.projects:
        if args.scan_subdirs and os.path.isdir(p):
            # Only include directories
            subdirs = [os.path.join(p, d) for d in os.listdir(p) if os.path.isdir(os.path.join(p, d))]
            targets.extend(subdirs)
        else:
            targets.append(p)

    if not targets:
        logger.error("No valid target directories found.")
        sys.exit(1)

    if args.calibrate:
        perform_calibration(targets)
    else:
        perform_scoring(targets[0])