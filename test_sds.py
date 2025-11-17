# test_sds.py

import os
import json
import logging
import sys
from calibrate import calibrate_weights_from_results
from tdsi_analyzer.security_analyzer import run_trivy_scan, calculate_sds

# Configurazione logging
logging.basicConfig(
    level=logging.INFO, 
    format='[%(asctime)s] [%(levelname)s] (TEST_RUNNER) %(message)s'
)

if __name__ == "__main__":
    logging.info("==============================================")
    logging.info("== TDSI-ANALYZER: SDS CALIBRATION AND TEST ==")
    logging.info("==============================================")
    
    test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_project")
    weights_file = "calibrated_weights.json"

    if not os.path.exists(test_dir):
        logging.fatal(f"Test directory not found: {test_dir}. Please create it and add IaC files.")
        sys.exit(1)

    # --- STEP 1: ESECUZIONE DELLA SCANSIONE DI CALIBRAZIONE ---
    logging.info("\n--- PHASE 1: DATA GATHERING (SCAN) ---")
    
    scan = run_trivy_scan(test_dir)
    if not scan:
        logging.fatal("Phase 1 Failed: Trivy scan did not return valid data.")
        sys.exit(1)

    # --- STEP 2: CALCOLO DEI PESI IBRIDI E DEL MASSIMO (M) ---
    logging.info("\n--- PHASE 2: MODEL CALIBRATION ---")
    
    # [scan] simula il dataset di calibrazione. Nello studio finale, useremo una lista di 50-100 scans.
    weights = calibrate_weights_from_results([scan]) 
    
    if not weights:
        logging.fatal("Phase 2 Failed: Model calibration failed.")
        sys.exit(1)

    try:
        with open(weights_file, "w") as f:
            json.dump(weights, f, indent=2)
        logging.info(f"SUCCESS: Calibrated weights saved, ready for SDS calculation.")
    except Exception as e:
        logging.fatal(f"Failed to save weights file: {e}")
        sys.exit(1)

    # --- STEP 3: CALCOLO FINALE DEL PUNTEGGIO SDS NORMALIZZATO ---
    logging.info("\n--- PHASE 3: FINAL SCORING ---")
    sds = calculate_sds(test_dir)
    
    logging.info("==============================================")
    if sds >= 0:
        logging.info(f"✅ FINAL SDS SCORE for {os.path.basename(test_dir)}: {sds:.2f}/100")
        logging.info("SUCCESS: The TDSI-Analyzer SDS component is functional and normalized.")
    else:
        logging.error("❌ FAILURE: SDS calculation returned an error. Check previous logs.")
    logging.info("==============================================")