# calibrate.py
import logging
import json
import os
import re
from datetime import datetime
from typing import Dict, Any, List, Tuple

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] (CALIB) %(message)s'
)

# Range CVSS per ogni severità (min, max)
CVSS_BOUNDS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH": (7.0, 8.9),
    "MEDIUM": (4.0, 6.9),
    "LOW": (0.1, 3.9),
    "NONE": (0.0, 0.0),
}

def calibrate_weights_from_results(results_list: List[Dict[str, Any]]) -> Dict[str, float] | None: 
    """
    Calcola i pesi dinamici (ibridi) per ciascun ID della Regola seguendo la metodologia descritta nel paper:
    1. Percentile-Based Weighting
    2. CVSS Clamping
    3. Determinazione del Max SDS Score
    """
    logging.info("--- STARTING GRANULAR ID-BASED WEIGHT CALIBRATION PROCESS ---")
    
    rule_data = {}
    raw_scores = [] 
    total_issues = 0
    valid_projects_for_score = 0
    
    # --- STEP 1: Conteggio Issue per ID e calcolo punteggio grezzo ---
    logging.info("STEP 1/3: Counting issue occurrences by Rule ID and calculating raw scores")
    
    # Primo loop: Calcola i pesi e aggrega i punteggi grezzi
    for data in results_list:
        results = data.get("Results", [])
        current_repo_raw_score = 0.0
        
        # Recupero robusto del percorso di scansione
        current_directory = data.get('project_path', '')
        if not current_directory:
            logging.error("Missing 'project_path' in scan data. Skipping this entry for score calculation.")
            continue 

        # 1a. Aggrega i dati delle issue 
        for res in results:
            # Process misconfigurations
            if "Misconfigurations" in res:
                for m in res["Misconfigurations"]:
                    rule_id = m.get("ID")
                    sev = m.get("Severity", "MEDIUM").upper()
                    
                    if rule_id and sev in CVSS_BOUNDS:
                        if rule_id not in rule_data:
                            rule_data[rule_id] = {"count": 0, "severity": sev}
                        rule_data[rule_id]["count"] += 1
                        total_issues += 1
                        
                        # Use actual CVSS score if available, otherwise use upper bound
                        cvss_score = m.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0)
                        if cvss_score == 0.0:
                            cvss_score = CVSS_BOUNDS[sev][1]
                            
                        current_repo_raw_score += cvss_score

            # Process secrets
            if "Secrets" in res:
                for s in res["Secrets"]:
                    rule_id = s.get("RuleID")
                    sev = s.get("Severity", "MEDIUM").upper()
                    
                    if rule_id and sev in CVSS_BOUNDS:
                        if rule_id not in rule_data:
                            rule_data[rule_id] = {"count": 0, "severity": sev}
                        rule_data[rule_id]["count"] += 1
                        total_issues += 1
                        
                        # Use actual CVSS score if available, otherwise use upper bound
                        cvss_score = s.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0)
                        if cvss_score == 0.0:
                            cvss_score = CVSS_BOUNDS[sev][1]
                            
                        current_repo_raw_score += cvss_score

        # 1b. Aggiungi il punteggio grezzo di QUESTO repository
        if current_repo_raw_score > 0:
            raw_scores.append(current_repo_raw_score)
            logging.info(f"Project '{os.path.basename(current_directory)}': Raw Score = {current_repo_raw_score:.2f}")
            valid_projects_for_score += 1
    
    logging.info(f"Calibration Dataset Summary: Total repositories analyzed: {len(results_list)}")
    logging.info(f"Projects with valid scores: {valid_projects_for_score}")
    logging.info(f"Total unique rules found: {len(rule_data)}")
    logging.info(f"Total issues counted: {total_issues}")
    
    if total_issues == 0:
        logging.error("No issues found in dataset. Calibration aborted.")
        return None

    # --- STEP 2: Calcolo Pesi Dinamici (Percentile-Based) con CVSS Clamping ---
    logging.info("STEP 2/3: Calculating percentile-based dynamic weights with CVSS clamping")
    
    # Ordina le regole per severità e frequenza
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    
    # Prima ordiniamo per severità
    rules_by_severity = {}
    for rule_id, data in rule_data.items():
        sev = data["severity"]
        if sev not in rules_by_severity:
            rules_by_severity[sev] = []
        rules_by_severity[sev].append((rule_id, data["count"]))
    
    # Poi calcoliamo i pesi percentili per ogni livello di severità
    weights = {}
    for sev, rules in rules_by_severity.items():
        # Ordina per frequenza (discendente)
        rules.sort(key=lambda x: x[1], reverse=True)
        
        # Calcola i pesi percentili
        total_in_severity = sum(count for _, count in rules)
        cumulative_pct = 0.0
        
        for i, (rule_id, count) in enumerate(rules):
            pct = count / total_in_severity
            midpoint = cumulative_pct + pct / 2
            # Mappa il percentile a una scala 0-10
            percentile_score = midpoint * 10
            
            # Applica il clamping CVSS
            cvss_min, cvss_max = CVSS_BOUNDS.get(sev, (0.0, 10.0))
            clamped_score = max(cvss_min, min(percentile_score, cvss_max))
            
            weights[rule_id] = round(clamped_score, 2)
            cumulative_pct += pct
            
            # Log per verifica
            logging.debug(f"Rule: {rule_id} | Severity: {sev} | Count: {count} | Percentile: {midpoint:.2f} | "
                         f"Raw Score: {percentile_score:.2f} | Clamped: {weights[rule_id]:.2f}")
    
    # --- STEP 3: Determinazione Max Raw Score per Normalizzazione ---
    logging.info("STEP 3/3: Determining Maximum Raw Score for 0-100 normalization")
    
    if raw_scores:
        # Usa il 95° percentile per evitare outlier estremi
        raw_scores.sort()
        percentile_95_idx = int(len(raw_scores) * 0.95)
        max_raw_score = raw_scores[percentile_95_idx]
        logging.info(f"Calculated 95th percentile Max Score from {valid_projects_for_score} projects: {max_raw_score:.2f}")
    else:
        max_raw_score = 2000.0
        logging.error("No valid scores found. Using fallback value of 2000.0")
    
    # --- CREAZIONE STRUTTURA PESI COMPLETA ---
    calibration_result = {
        "calibration_date": str(datetime.now()),
        "project_count": len(results_list),
        "unique_rules": len(rule_data),
        "Max_SDS_Score": round(max_raw_score, 2),
        "weights": weights
    }
    
    logging.info(f"--- CALIBRATION PROCESS FINISHED ---")
    logging.info(f"Final Max SDS Score set to: {max_raw_score:.2f} (95th percentile of sample).")
    logging.info(f"Unique rules calibrated: {len(rule_data)}")
    
    # Analisi dei pesi per verificare la distribuzione
    critical_weights = [w for r, w in weights.items() if rule_data.get(r, {}).get("severity") == "CRITICAL"]
    high_weights = [w for r, w in weights.items() if rule_data.get(r, {}).get("severity") == "HIGH"]
    medium_weights = [w for r, w in weights.items() if rule_data.get(r, {}).get("severity") == "MEDIUM"]
    low_weights = [w for r, w in weights.items() if rule_data.get(r, {}).get("severity") == "LOW"]
    
    if critical_weights:
        logging.info(f"CRITICAL weights range: {min(critical_weights):.2f} - {max(critical_weights):.2f}")
    if high_weights:
        logging.info(f"HIGH weights range: {min(high_weights):.2f} - {max(high_weights):.2f}")
    if medium_weights:
        logging.info(f"MEDIUM weights range: {min(medium_weights):.2f} - {max(medium_weights):.2f}")
    if low_weights:
        logging.info(f"LOW weights range: {min(low_weights):.2f} - {max(low_weights):.2f}")
    
    # Verifica hardcoded secrets
    secret_rules = [r for r in rule_data.keys() 
                   if any(x in r.upper() for x in ["GEN", "AWS", "GHA", "GIT", "SECRET"])]
    
    if secret_rules:
        secret_weights = [weights[r] for r in secret_rules]
        logging.info(f"\nDetected {len(secret_rules)} hardcoded secret rules")
        logging.info(f"Secret weights range: {min(secret_weights):.2f} - {max(secret_weights):.2f}")
        logging.info("These weights reflect their actual prevalence and severity as per calibration methodology")
    else:
        logging.info("\nNo hardcoded secret rules detected in this sample")
    
    return calibration_result