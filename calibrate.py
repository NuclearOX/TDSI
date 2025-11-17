# calibrate.py
import logging
import json
from typing import Dict, Any, List

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] (CALIB) %(message)s'
)

# Range CVSS per ogni severità (min, max)
CVSS_BOUNDS = {
    "NONE": (0.0, 0.0),
    "LOW": (1.0, 3.9),
    "MEDIUM": (4.0, 6.9),
    "HIGH": (7.0, 8.9),
    "CRITICAL": (9.0, 10.0),
}

def calibrate_weights_from_results(results_list: List[Dict[str, Any]]) -> Dict[str, float] | None:
    """
    Calcola i pesi dinamici (ibridi) per ogni severità (Percentile + CVSS Clamping)
    e determina il punteggio SDS massimo (M) nel dataset di calibrazione.
    """
    logging.info("--- STARTING HYBRID WEIGHT CALIBRATION PROCESS ---")
    
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    raw_sds_scores = []

    # --- STEP 1: Conteggio Severità e Calcolo Punteggio Grezzo del Campione ---
    logging.info("STEP 1/4: Counting severity occurrences and calculating raw scores for normalization.")
    
    for data in results_list:
        results = data.get("Results", [])
        current_repo_score = 0.0
        
        for res in results:
            if "Misconfigurations" in res:
                for m in res["Misconfigurations"]:
                    sev = m.get("Severity")
                    
                    if sev in severity_counts:
                        current_repo_score += CVSS_BOUNDS[sev][1] 
                        severity_counts[sev] += 1
                        
        raw_sds_scores.append(current_repo_score)

    total_issues = sum(severity_counts.values())
    logging.info(f"Calibration Dataset Summary: Total repositories analyzed: {len(results_list)}")
    logging.info(f"Total issues counted: {total_issues}")
    logging.info(f"Distribution: {severity_counts}")

    if total_issues == 0:
        logging.warning("No issues found in dataset. Calibration aborted.")
        return None

    # --- STEP 2: Calcolo Percentili Cumulativi per Pesi Dinamici ---
    logging.info("STEP 2/4: Calculating percentile-based dynamic weights (0-10 scale).")
    ordered = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    weights_raw = {}
    cumulative_pct = 0.0

    for sev in ordered:
        count = severity_counts[sev]
        pct = count / total_issues 
        midpoint = cumulative_pct + pct / 2 
        score_0_10 = midpoint * 10 
        
        weights_raw[sev] = score_0_10
        cumulative_pct += pct
        logging.debug(
            f"-> {sev}: Count={count}, Pct={pct:.3f}, Midpoint={midpoint:.3f}, Raw Score={score_0_10:.2f}"
        )

    # --- STEP 3: Applicazione Limiti CVSS (Clamping) ---
    logging.info("STEP 3/4: Applying CVSS bounds (clamping) for final weighted parameters.")
    weights_clamped = {}
    for sev, dyn_score in weights_raw.items():
        if sev not in CVSS_BOUNDS: continue
        cvss_min, cvss_max = CVSS_BOUNDS[sev]
        final_score = max(cvss_min, min(dyn_score, cvss_max)) 
        weights_clamped[sev] = round(final_score, 2)
        
        logging.debug(
            f"-> {sev}: Dynamic={dyn_score:.2f}, CVSS Range=[{cvss_min}-{cvss_max}] -> Final Weight={weights_clamped[sev]}"
        )
        
    # --- STEP 4: Determinazione Punteggio Massimo per Normalizzazione (M) ---
    logging.info("STEP 4/4: Determining Max SDS Score (M) for 0-100 normalization.")
    max_sds_score_m = max(raw_sds_scores) if raw_sds_scores else 100.0
    
    weights_clamped["Max_SDS_Score_M"] = round(max_sds_score_m, 2)
    logging.info(f"Final Max Score M set to: {max_sds_score_m:.2f} (Max raw score found in sample).")
    logging.info(f"Final Calibrated Weights (SDS parameters): {weights_clamped}")
    logging.info("--- CALIBRATION PROCESS FINISHED ---")
    
    return weights_clamped

if __name__ == "__main__":
    logging.info("This script is part of the TDSI-Analyzer framework. Run the run_analyzer.py script for execution.")