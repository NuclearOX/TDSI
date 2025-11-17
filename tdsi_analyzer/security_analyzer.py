# tdsi_analyzer/security_analyzer.py
import subprocess
import json
import os
import logging
from typing import Dict, Any

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] (SDS) %(message)s'
)

_weights_cache = None

def load_calibrated_weights(weights_file="calibrated_weights.json") -> Dict[str, float] | None:
    """Carica i pesi calibrati e il valore M per la normalizzazione."""
    global _weights_cache
    if _weights_cache:
        logging.debug("Returning cached weights.")
        return _weights_cache

    try:
        with open(weights_file, "r") as f:
            _weights_cache = json.load(f)
        
        if "Max_SDS_Score_M" not in _weights_cache:
            logging.fatal(f"Key 'Max_SDS_Score_M' missing. Re-run calibration.")
            return None
        
        logging.info(f"Weights loaded successfully. Max Score M: {_weights_cache.get('Max_SDS_Score_M'):.2f}")
        return _weights_cache
    except FileNotFoundError:
        logging.fatal(f"Weights file ({weights_file}) not found. Execution halted.")
        return None
    except json.JSONDecodeError:
        logging.fatal(f"Error decoding JSON from {weights_file}. Check file integrity.")
        return None

def run_trivy_scan(directory_path: str) -> Dict[str, Any] | None:
    """Esegue la scansione Trivy in un container Docker e restituisce l'output JSON."""
    abs_path = os.path.abspath(directory_path)
    logging.info(f"--- Starting Trivy Scan on: {os.path.basename(abs_path)} ---")
    
    command = [
        "docker", "run", "--rm",
        "-v", f"{abs_path}:/scan",
        "aquasec/trivy:latest",
        "config", "/scan",
        "--format", "json",
        "--exit-code", "0",
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW"
    ]

    logging.debug(f"Executing command: {' '.join(command[:4])} ...") # Truncated for readability
    
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", check=False, timeout=300
        )
        
        if result.stderr and result.returncode != 0:
            logging.warning(f"Trivy returned non-zero code ({result.returncode}). Stderr: {result.stderr.splitlines()[0]}...")
        
        if result.stdout.strip():
            logging.info("Trivy scan completed successfully.")
            return json.loads(result.stdout)
        else:
            logging.warning("Trivy scan completed but returned empty stdout (no IaC files found or error).")
            return None

    except subprocess.TimeoutExpired:
        logging.error("Trivy scan timed out (5 minutes). Increase timeout if necessary.")
        return None
    except json.JSONDecodeError as e:
        logging.fatal(f"Failed to parse Trivy JSON output: {e}. Output start: {result.stdout[:200]}...")
        return None
    except Exception as e:
        logging.fatal(f"Trivy scan failed with system error: {e}")
        return None

def calculate_sds(directory_path: str) -> float:
    """
    Calcola l'SDS: Somma ponderata delle misconfigurazioni, normalizzata su scala 0-100.
    """
    logging.info("--- Starting Weighted SDS Calculation ---")
    weights = load_calibrated_weights()
    if not weights:
        return -1

    max_sds_score_m = weights.get("Max_SDS_Score_M", 100.0)
    
    scan_data = run_trivy_scan(directory_path)
    if not scan_data:
        logging.info("No scan data returned. SDS is 0.0.")
        return 0.0

    results = scan_data.get("Results", [])
    misconfigs = []

    for r in results:
        # Filtriamo per tipi IaC che Trivy supporta
        if "Misconfigurations" in r and r.get('Type') in ['terraform', 'cloudformation', 'kubernetes', 'ansible']: 
            misconfigs.extend(r["Misconfigurations"])

    if not misconfigs:
        logging.info("No security misconfigurations found in IaC files.")
        return 0.0

    logging.info(f"Found {len(misconfigs)} security misconfigurations.")

    raw_score_sum = 0.0
    for idx, m in enumerate(misconfigs):
        sev = m.get("Severity")
        weight = weights.get(sev) 
        if weight is not None:
            raw_score_sum += weight
            logging.debug(f"Issue {idx+1}/{len(misconfigs)}: Severity={sev}, Weight={weight:.2f}, Running Sum={raw_score_sum:.2f}")
        else:
            logging.debug(f"Issue {idx+1}/{len(misconfigs)}: Unknown severity ({sev}), skipped.")

    # --- FASE CRUCIALE: Normalizzazione ---
    logging.info("--- Normalization Phase ---")
    logging.info(f"Raw Score Sum (Total Debito): {raw_score_sum:.2f}")
    logging.info(f"Normalization Factor (M): {max_sds_score_m:.2f}")
    
    sds_normalized = (raw_score_sum / max_sds_score_m) * 100.0
    
    final_sds = min(sds_normalized, 100.0) 

    logging.info(f"Calculated Normalized SDS (0-100): {final_sds:.2f}")
    logging.info("--- SDS Calculation Finished ---")
    
    return round(final_sds, 2)