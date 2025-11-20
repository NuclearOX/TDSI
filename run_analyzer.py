# run_analyzer.py

import os
import json
import logging
import sys
import argparse
from datetime import datetime 
from typing import List
from calibrate import calibrate_weights_from_results
from tdsi_analyzer.security_analyzer import run_trivy_misconfiguration_scan, calculate_sds

# Configurazione logging
logging.basicConfig(
    level=logging.INFO, 
    format='[%(asctime)s] [%(levelname)s] (RUNNER) %(message)s'
)

WEIGHTS_FILE = "calibrated_weights.json"

def perform_calibration(project_directories: List[str]):
    """Esegue la calibrazione del modello SDS su più progetti."""
    logging.info("\n--- PHASE 1: DATA GATHERING FOR CALIBRATION (MULTI-PROJECT) ---")
    
    all_scan_data = []
    
    # 1. Scansione di tutti i progetti
    for i, directory in enumerate(project_directories):
        logging.info(f"[{i+1}/{len(project_directories)}] Scanning project: {os.path.basename(directory)}")
        
        if not os.path.exists(directory):
             logging.error(f"Directory not found: {directory}. Skipping.")
             continue
             
        # La calibrazione usa solo la scansione delle misconfigurazioni
        scan_data = run_trivy_misconfiguration_scan(directory)
        if scan_data:
            # Associazione robusta: Aggiunta del percorso di scansione al risultato
            scan_data['project_path'] = directory 
            all_scan_data.append(scan_data)
            
    
    if not all_scan_data:
        logging.error("Calibration Scan Failed: No valid scan data collected from any project.")
        return

    logging.info(f"\nCollected misconfiguration data from {len(all_scan_data)}/{len(project_directories)} valid projects.")
    logging.info("\n--- PHASE 2: MODEL CALIBRATION ---")
    
    # I percorsi sono in all_scan_data
    weights = calibrate_weights_from_results(all_scan_data) 
    
    if not weights:
        logging.fatal("Phase 2 Failed: Model calibration failed. Cannot save weights.")
        return

    try:
        # Update calibration date
        weights["calibration_date"] = str(datetime.now())
        
        with open(WEIGHTS_FILE, "w") as f:
            json.dump(weights, f, indent=2)
        logging.info(f"✅ SUCCESS: Calibrated weights saved to {WEIGHTS_FILE}.")
        logging.info(f"    Max SDS Score: {weights.get('Max_SDS_Score', 0):.2f}")
        logging.info(f"    Unique rules calibrated: {weights.get('unique_rules', 0)}")
        
        # Check for secret rules
        secret_rules = [k for k, v in weights.get("weights", {}).items() 
                       if any(x in k for x in ["GEN", "AWS", "GHA", "GIT", "SECRET"])]
        if secret_rules:
            logging.info(f"    Hardcoded secret rules detected: {len(secret_rules)}")
            logging.info("    These are weighted at 8.5+ as they were exploited in 2022 breaches per GitGuardian report")
        else:
            logging.warning("    WARNING: No hardcoded secret rules detected in calibration!")
            logging.warning("    This suggests secrets scanning may not be working properly")
            
    except Exception as e:
        logging.fatal(f"Failed to save weights file: {e}")
        return

def perform_scoring(directory: str):
    """Esegue lo scoring SDS sul singolo progetto specificato."""
    if not os.path.exists(WEIGHTS_FILE):
        logging.fatal(f"Scoring Failed: Weights file ({WEIGHTS_FILE}) not found. Run calibration first!")
        return
        
    logging.info("\n--- PHASE 3: FINAL SCORING ---")
    sds = calculate_sds(directory)
    
    logging.info("==============================================")
    if sds >= 0:
        logging.info(f"✅ FINAL SDS SCORE for {os.path.basename(directory)}: {sds:.2f}/100")
        
        # Add security context based on knowledge base
        if sds > 70:
            logging.warning("⚠️  HIGH SECURITY DEBT: Score above 70 indicates significant risk")
            logging.warning("⚠️  According to GitGuardian, 2022 saw 67% increase in hardcoded secrets")
            logging.warning("⚠️  These have been exploited in attacks against Uber, CircleCI, Microsoft, etc.")
        
        logging.info("SUCCESS: The TDSI-Analyzer SDS component is functional and normalized.")
    else:
        logging.error("❌ FAILURE: SDS calculation returned an error. Check previous logs.")
    logging.info("==============================================")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TDSI-Analyzer SDS Runner: Calibrate weights on multiple projects or score a single project."
    )
    parser.add_argument(
        "projects", 
        type=str, 
        nargs='+', 
        help="One or more IaC project directories to analyze/calibrate."
    )
    parser.add_argument(
        "--calibrate", 
        action="store_true", 
        help="Run the model calibration process (requires multiple project directories). Must be run first on a representative dataset."
    )
    parser.add_argument(
        "--scan-subdirs",
        action="store_true",
        help="When provided with a directory path, scan all its immediate subdirectories as projects"
    )
    
    args = parser.parse_args()
    
    # Process --scan-subdirs option
    project_directories = []
    for path in args.projects:
        if os.path.isdir(path) and args.scan_subdirs:
            # Get immediate subdirectories (not recursive)
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    project_directories.append(item_path)
            logging.info(f"Expanded {path} to {len(project_directories)} subdirectories")
        else:
            project_directories.append(path)

    # --- INIZIO ESECUZIONE ---
    logging.info("==============================================")
    logging.info("== TDSI-ANALYZER: SDS EXECUTION RUNNER ==")
    logging.info("==============================================")

    if args.calibrate:
        logging.info("MODE: CALIBRATION (Multiple Projects)")
        if len(project_directories) < 20:
             logging.warning("WARNING: Recommended minimum 20 projects for statistically valid calibration.")
             logging.warning(f"        You are using only {len(project_directories)} projects.")
        perform_calibration(project_directories)
    else:
        if len(project_directories) != 1:
            logging.fatal("Scoring Failed: Must specify exactly one project directory when not using --calibrate.")
            sys.exit(1)
            
        logging.info("MODE: SCORING (Requires calibrated_weights.json)")
        perform_scoring(project_directories[0])