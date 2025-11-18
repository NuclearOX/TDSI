# calibrate.py
import logging
import json
import os
from typing import Dict, Any, List
from tdsi_analyzer.security_analyzer import run_cloc_scan 

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] (CALIB) %(message)s'
)

# Range CVSS per ogni severità (min, max)
CVSS_BOUNDS = {
    "NONE": (0.0, 0.0),
    "LOW": (0.1, 3.9), 
    "MEDIUM": (4.0, 6.9),
    "HIGH": (7.0, 8.9),
    "CRITICAL": (9.0, 10.0),
}


def calibrate_weights_from_results(results_list: List[Dict[str, Any]]) -> Dict[str, float] | None: 
    """
    Calcola i pesi dinamici (ibridi) per ciascun ID della Regola e il fattore di normalizzazione 
    per densità (Max Raw Score / LOC) sull'intero campione.
    """
    logging.info("--- STARTING GRANULAR ID-BASED WEIGHT CALIBRATION PROCESS ---")
    
    rule_data = {}
    raw_sds_density_ratios = [] 
    total_issues = 0
    valid_projects_for_ratio = 0
    
    # --- STEP 1: Conteggio Issue per ID, Calcolo Punteggio Grezzo Teorico e Ratio Densità ---
    logging.info("STEP 1/4: Counting issue occurrences by Rule ID and calculating max Raw Score/LOC ratio.")
    
    
    # Primo loop: Calcola i pesi e aggrega i rapporti di densità
    for data in results_list: # Iteriamo sulla lista dei risultati
        results = data.get("Results", [])
        current_repo_raw_score = 0.0
        
        # Recupero robusto del percorso di scansione
        current_directory = data.get('project_path', '')
        if not current_directory:
            logging.error("Missing 'project_path' in scan data. Skipping this entry for density calculation.")
            continue 

        # 1a. Aggrega i dati delle issue 
        for res in results:
            if "Misconfigurations" in res:
                for m in res["Misconfigurations"]:
                    rule_id = m.get("ID")
                    sev = m.get("Severity")
                    
                    if rule_id and sev in CVSS_BOUNDS:
                        if rule_id not in rule_data:
                            rule_data[rule_id] = {"count": 0, "severity": sev}
                        rule_data[rule_id]["count"] += 1
                        total_issues += 1
                        
                        current_repo_raw_score += CVSS_BOUNDS[sev][1]

        # 1b. Calcola Raw Score / Densità per QUESTO repository
        loc = run_cloc_scan(current_directory)
        
        if loc > 0 and current_repo_raw_score > 0:
            ratio = current_repo_raw_score / loc
            raw_sds_density_ratios.append(ratio)
            logging.info(f"Project '{os.path.basename(current_directory)}': Raw Score/LOC ratio = {ratio:.6f} (Raw Score: {current_repo_raw_score:.2f}, LOC: {loc})")
            valid_projects_for_ratio += 1
        elif loc == 0:
             logging.warning(f"Project '{os.path.basename(current_directory)}': LOC is 0. Skipping density ratio calculation.")
        
    logging.info(f"Calibration Dataset Summary: Total repositories analyzed: {len(results_list)}")
    logging.info(f"Projects with valid density ratios: {valid_projects_for_ratio}")
    logging.info(f"Total unique rules found: {len(rule_data)}")
    logging.info(f"Total issues counted: {total_issues}")
    
    if total_issues == 0:
        logging.warning("No issues found in dataset. Calibration aborted.")
        return None

    severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 5}
    ordered_rules_list = sorted(
        rule_data.keys(),
        key=lambda id: (severity_order[rule_data[id]["severity"]], rule_data[id]["count"]),
        reverse=False
    )
    
    # --- STEP 2: Calcolo Pesi Dinamici (ID-BASED) ---
    logging.info("STEP 2/4: Calculating percentile-based dynamic weights (0-10 scale) for each Rule ID.")
    weights_raw = {}
    cumulative_pct = 0.0
    for rule_id in ordered_rules_list:
        count = rule_data[rule_id]["count"]
        pct = count / total_issues 
        midpoint = cumulative_pct + pct / 2 
        score_0_10 = midpoint * 10 
        weights_raw[rule_id] = score_0_10
        cumulative_pct += pct
        
    # --- STEP 3: Applicazione Limiti CVSS (Clamping) ---
    logging.info("STEP 3/4: Applying CVSS bounds (clamping) for final weighted parameters.")
    weights_clamped = {}
    for rule_id, dyn_score in weights_raw.items():
        sev = rule_data[rule_id]["severity"]
        cvss_min, cvss_max = CVSS_BOUNDS.get(sev, (0.0, 10.0))
        final_score = max(cvss_min, min(dyn_score, cvss_max)) 
        weights_clamped[rule_id] = round(final_score, 2)
        
        logging.info(f"[WEIGHT] Rule: {rule_id} ({sev}) | Dynamic: {dyn_score:.2f} | Clamped: {weights_clamped[rule_id]:.2f}")
        
    # --- STEP 4: Determinazione Max Raw Score/Densità (M_D) per Normalizzazione ---
    logging.info("STEP 4/4: Determining Max SDS Density Score (M_D) for 0-100 normalization.")
    
    if raw_sds_density_ratios:
        max_sds_density_m = max(raw_sds_density_ratios)
        logging.info(f"Calculated Maximum Density Ratio from {valid_projects_for_ratio} projects.")
    else:
        max_sds_density_m = 0.05
        logging.warning("No valid density ratios found. Using fallback value of 0.05")
    
    weights_clamped["Max_SDS_Density_M"] = round(max_sds_density_m, 6)
    logging.info(f"Final Max Density Ratio M_D set to: {max_sds_density_m:.6f} (Worst-case Raw Score / LOC in sample).")
    logging.info("--- CALIBRATION PROCESS FINISHED ---")
    
    return weights_clamped