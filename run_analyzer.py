# run_analyzer.py

# python run_analyzer.py test_project --calibrate

import os
import json
import logging
import sys
import argparse
from calibrate import calibrate_weights_from_results
from tdsi_analyzer.security_analyzer import run_trivy_scan, calculate_sds

# Configurazione logging
logging.basicConfig(
    level=logging.INFO, 
    format='[%(asctime)s] [%(levelname)s] (RUNNER) %(message)s'
)

WEIGHTS_FILE = "calibrated_weights.json"

def perform_calibration(directory: str):
    """Esegue la calibrazione del modello SDS."""
    logging.info("\n--- PHASE 1: DATA GATHERING FOR CALIBRATION (SINGLE PROJECT SIMULATION) ---")
    
    # Nota: Nello studio finale, useremo un dataset di 50-100 scans per la calibrazione.
    scan_data = run_trivy_scan(directory)
    if not scan_data:
        logging.error("Calibration Scan Failed: Trivy scan did not return valid data.")
        return

    logging.info("\n--- PHASE 2: MODEL CALIBRATION ---")
    weights = calibrate_weights_from_results([scan_data]) 
    
    if not weights:
        logging.fatal("Phase 2 Failed: Model calibration failed. Cannot save weights.")
        return

    try:
        with open(WEIGHTS_FILE, "w") as f:
            json.dump(weights, f, indent=2)
        logging.info(f"✅ SUCCESS: Calibrated weights saved to {WEIGHTS_FILE}.")
    except Exception as e:
        logging.fatal(f"Failed to save weights file: {e}")
        return

def perform_scoring(directory: str):
    """Esegue lo scoring SDS sul progetto specificato."""
    if not os.path.exists(WEIGHTS_FILE):
        logging.fatal(f"Scoring Failed: Weights file ({WEIGHTS_FILE}) not found. Run calibration first!")
        return
        
    logging.info("\n--- PHASE 3: FINAL SCORING ---")
    sds = calculate_sds(directory)
    
    logging.info("==============================================")
    if sds >= 0:
        logging.info(f"✅ FINAL SDS SCORE for {os.path.basename(directory)}: {sds:.2f}/100")
        logging.info("SUCCESS: The TDSI-Analyzer SDS component is functional and normalized.")
    else:
        logging.error("❌ FAILURE: SDS calculation returned an error. Check previous logs.")
    logging.info("==============================================")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TDSI-Analyzer SDS Runner: Calibrate weights or score a project."
    )
    parser.add_argument(
        "directory", 
        type=str, 
        help="The path to the IaC project directory to analyze."
    )
    parser.add_argument(
        "--calibrate", 
        action="store_true", 
        help="Run the model calibration process (saves new weights). Must be run first on a representative dataset."
    )
    
    args = parser.parse_args()

    # --- INIZIO ESECUZIONE ---
    logging.info("==============================================")
    logging.info("== TDSI-ANALYZER: SDS EXECUTION RUNNER ==")
    logging.info("==============================================")

    if not os.path.exists(args.directory):
        logging.fatal(f"Directory not found: {args.directory}")
        sys.exit(1)

    if args.calibrate:
        logging.info("MODE: CALIBRATION")
        # In un vero scenario MSR, 'args.directory' punta a un root contenente molti progetti
        # Qui usiamo la directory di test come simulazione di un singolo campione.
        perform_calibration(args.directory)
    else:
        logging.info("MODE: SCORING (Requires calibrated_weights.json)")
        perform_scoring(args.directory)