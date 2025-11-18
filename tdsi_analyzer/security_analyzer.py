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
    global _weights_cache
    if _weights_cache:
        logging.debug("Returning cached weights.")
        return _weights_cache

    try:
        with open(weights_file, "r") as f:
            _weights_cache = json.load(f)
        
        if "Max_SDS_Density_M" not in _weights_cache:
            logging.fatal(f"Key 'Max_SDS_Density_M' missing. Re-run calibration.")
            return None
        
        num_weights = len(_weights_cache) - 1 
        logging.info(f"Weights loaded successfully ({num_weights} Rule IDs). Max Density Ratio M_D: {_weights_cache.get('Max_SDS_Density_M'):.6f}")
        return _weights_cache
    except FileNotFoundError:
        logging.fatal(f"Weights file ({weights_file}) not found. Execution halted.")
        return None
    except json.JSONDecodeError:
        logging.fatal(f"Error decoding JSON from {weights_file}. Check file integrity.")
        return None


def run_trivy_misconfiguration_scan(directory_path: str) -> Dict[str, Any] | None:
    """Esegue la scansione Trivy CONFIG (Misconfigurazione IaC)."""
    abs_path = os.path.abspath(directory_path)
    logging.info(f"--- Starting Trivy Misconfiguration (CONFIG) Scan on: {os.path.basename(abs_path)} ---")
    
    command = [
        "docker", "run", "--rm",
        "-v", f"{abs_path}:/scan",
        "aquasec/trivy:latest",
        "config", "/scan",
        "--format", "json",
        "--exit-code", "0",
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW"
    ]
    
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", check=False, timeout=300
        )
        if result.stdout.strip():
            logging.info("Trivy Misconfig scan completed successfully.")
            return json.loads(result.stdout)
        return None
    except Exception as e:
        logging.fatal(f"Trivy Misconfig scan failed: {e}")
        return None


def run_trivy_vulnerability_scan(directory_path: str) -> Dict[str, Any] | None:
    """Esegue la scansione Trivy VULNERABILITY (Dipendenze/CVE)."""
    abs_path = os.path.abspath(directory_path)
    logging.info(f"--- Starting Trivy Vulnerability (FS) Scan on: {os.path.basename(abs_path)} ---")
    
    command = [
        "docker", "run", "--rm",
        "-v", f"{abs_path}:/scan",
        "aquasec/trivy:latest",
        "fs", "/scan",
        "--format", "json",
        "--exit-code", "0",
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW"
    ]

    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", check=False, timeout=300
        )
        if result.stdout.strip():
            logging.info("Trivy Vulnerability scan completed successfully.")
            return json.loads(result.stdout)
        return None
    except Exception as e:
        logging.fatal(f"Trivy Vulnerability scan failed: {e}")
        return None

def run_cloc_scan(directory_path: str) -> int:
    """Conteggio nativo delle Lines of Code (LOC) per IaC - Senza dipendenze Docker"""
    logging.info(f"--- Starting Native LOC Scan for Density ---")
    logging.info(f"Scanning directory: {directory_path}")
    
    # Estensioni IaC rilevanti
    valid_extensions = {".tf", ".hcl", ".yaml", ".yml", ".json", ".py", ".go", ".sh", ".ps1"}
    total_lines = 0
    file_count = 0
    
    try:
        # Scansione ricorsiva della directory
        for root, _, files in os.walk(directory_path):
            for file in files:
                _, ext = os.path.splitext(file)
                if ext.lower() in valid_extensions:
                    file_count += 1
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Tentativo con diverse codifiche
                        encodings = ['utf-8', 'latin-1', 'cp1252']
                        content = None
                        
                        for encoding in encodings:
                            try:
                                with open(file_path, 'r', encoding=encoding) as f:
                                    content = f.readlines()
                                break
                            except UnicodeDecodeError:
                                continue
                        
                        if content is None:
                            logging.debug(f"Skipped {file} - unsupported encoding")
                            continue
                            
                        # Filtra righe di codice (non commenti, non vuote)
                        for line in content:
                            stripped = line.strip()
                            # Ignora commenti e righe vuote
                            if not stripped or stripped.startswith('#') or \
                               stripped.startswith('//') or stripped.startswith('/*') or \
                               stripped.startswith('<!--') or stripped.startswith('\"\"\"'):
                                continue
                            total_lines += 1
                            
                    except Exception as e:
                        logging.debug(f"Error processing {file_path}: {str(e)}")
                        continue
        
        if file_count > 0:
            logging.info(f"Native scan completed successfully. Scanned {file_count} files. Total IaC LOC found: {total_lines}")
        else:
            logging.warning("No relevant IaC files found in directory.")
            return 0
            
        return total_lines
        
    except Exception as e:
        logging.error(f"Native LOC scan failed: {str(e)}")
        return 0


def calculate_sds(directory_path: str) -> float:
    logging.info("--- Starting Weighted SDS Calculation ---")
    weights = load_calibrated_weights()
    if not weights:
        return -1

    max_sds_density_m = weights.get("Max_SDS_Density_M", 0.05) 
    
    # 1. Scansione del codice (Misconfigurazione)
    misconfig_data = run_trivy_misconfiguration_scan(directory_path)
    # 2. Scansione delle dipendenze (Vulnerabilità)
    vulnerability_data = run_trivy_vulnerability_scan(directory_path)
    # 3. Scansione LOC (Densità D)
    loc_density = run_cloc_scan(directory_path)

    if loc_density == 0:
        logging.warning("Code density (LOC) is zero. Cannot proceed with density normalization. Using default LOC=1 for ratio calculation.")
        loc_density = 1 

    # --- CALCOLO RAW SCORE MISCONFIGURATION (CON PESI CALIBRATI) ---
    misconfigs = []
    if misconfig_data:
        for r in misconfig_data.get("Results", []):
            if "Misconfigurations" in r and r.get('Type') in ['terraform', 'cloudformation', 'kubernetes', 'ansible']: 
                misconfigs.extend(r["Misconfigurations"])
    
    raw_score_misconfig = 0.0
    
    logging.info("\n--- DETAILED MISCONFIGURATION DEBT ---")
    if misconfigs:
        for idx, m in enumerate(misconfigs):
            rule_id = m.get("ID")
            weight = weights.get(rule_id, 0.0) 
            raw_score_misconfig += weight
            
            logging.info(f"[{idx+1}/{len(misconfigs)}] Rule: {rule_id} (Sev: {m.get('Severity')}) -> Weight: {weight:.2f}")
    else:
        logging.info("No misconfigurations found.")


    # --- CALCOLO RAW SCORE VULNERABILITY (CON PESI CVSS NATIVI) ---
    vulnerabilities = []
    if vulnerability_data:
        for r in vulnerability_data.get("Results", []):
            if "Vulnerabilities" in r and r.get('Type') not in ['config']:
                vulnerabilities.extend(r["Vulnerabilities"])

    raw_score_vulnerability = 0.0
    
    logging.info("\n--- DETAILED VULNERABILITY DEBT (CVEs) ---")
    if vulnerabilities:
        for idx, v in enumerate(vulnerabilities):
            cvss_score = v.get("Vulnerability", {}).get("CVSS", {}).get("V3Score", 0.0)
            raw_score_vulnerability += cvss_score
            
            logging.info(f"[{idx+1}/{len(vulnerabilities)}] CVE: {v.get('VulnerabilityID')} (Sev: {v.get('Severity')}) -> Score: {cvss_score:.2f}")
    else:
        logging.info("No vulnerabilities found in dependencies.")


    # --- SOMMA TOTALE DEL DEBITO ---
    raw_score_sum = raw_score_misconfig + raw_score_vulnerability
    
    logging.info("\n--- TOTAL DEBT SUMMARY ---")
    logging.info(f"Total Misconfigurations Found: {len(misconfigs)}. Raw Score (Misconfig): {raw_score_misconfig:.2f}")
    logging.info(f"Total Vulnerabilities Found: {len(vulnerabilities)}. Raw Score (Vulns): {raw_score_vulnerability:.2f}")

    if raw_score_sum == 0.0:
        return 0.0
    
    # --- FASE DI NORMALIZZAZIONE PER DENSITÀ ---
    sds_density_ratio = raw_score_sum / loc_density
    
    logging.info("\n--- NORMALIZATION COEFFICIENTS AND FINAL SCORE ---")
    logging.info(f"Raw Score Sum (Total Debito Assoluto): {raw_score_sum:.2f}")
    logging.info(f"LOC Density (D - Righe di Codice IaC): {loc_density}")
    logging.info(f"Raw Score / Density Ratio: {sds_density_ratio:.6f}")
    logging.info(f"Normalization Factor (M_D - Max Ratio from Sample): {max_sds_density_m:.6f}")
    
    # Calcolo SDS
    sds_normalized = (sds_density_ratio / max_sds_density_m) * 100.0
    final_sds = min(sds_normalized, 100.0) 

    logging.info(f"Calculated Normalized SDS (0-100): {final_sds:.2f}")
    logging.info("--- SDS Calculation Finished ---")
    
    return round(final_sds, 2)