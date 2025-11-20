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
        
        if "Max_SDS_Score" not in _weights_cache:
            logging.error(f"Key 'Max_SDS_Score' missing. Re-run calibration.")
            return None
        
        # Count actual rule weights (excluding metadata keys)
        num_weights = sum(1 for k in _weights_cache.keys() if k not in ["calibration_date", "project_count", "unique_rules", "Max_SDS_Score"])
        logging.info(f"Weights loaded successfully ({num_weights} Rule IDs). Max SDS Score: {_weights_cache.get('Max_SDS_Score'):.2f}")
        return _weights_cache
    except FileNotFoundError:
        logging.error(f"Weights file ({weights_file}) not found. Execution halted.")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {weights_file}: {str(e)}")
        return None


def run_trivy_misconfiguration_scan(directory_path: str) -> Dict[str, Any] | None:
    """Esegue la scansione Trivy CONFIG (Misconfigurazione IaC) - CORRECTED VERSION."""
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
        # NO INVALID FLAGS - Secrets detection is ENABLED BY DEFAULT in config scanning
    ]
    
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", check=False, timeout=600
        )
        
        # Log raw output for debugging if needed
        if not result.stdout.strip():
            logging.error("Trivy returned empty output")
            return None
            
        try:
            # First try to parse as JSON
            json.loads(result.stdout)
            logging.info("Trivy Misconfig scan completed successfully")
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logging.error(f"Trivy output is not valid JSON: {str(e)}")
            logging.debug(f"Trivy raw output: {result.stdout}")
            return None
            
    except Exception as e:
        logging.error(f"Trivy Misconfig scan failed: {e}")
        return None


def run_cloc_scan(directory_path: str) -> int:
    """Conteggio nativo delle Lines of Code (LOC) per IaC"""
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

    max_sds_score = weights.get("Max_SDS_Score", 2000.0)
    
    # 1. Scansione del codice (Misconfigurazione)
    misconfig_data = run_trivy_misconfiguration_scan(directory_path)
    
    # 2. Scansione LOC (Densità D)
    loc_density = run_cloc_scan(directory_path)

    if loc_density == 0:
        logging.warning("Code density (LOC) is zero. Cannot proceed with density normalization. Using default LOC=1 for ratio calculation.")
        loc_density = 1 

    # --- CALCOLO RAW SCORE ---
    findings = []
    secret_count = 0
    
    if misconfig_data:
        for r in misconfig_data.get("Results", []):
            # Process misconfigurations
            if "Misconfigurations" in r and r.get('Type') in ['terraform', 'cloudformation', 'kubernetes', 'ansible']: 
                findings.extend(r["Misconfigurations"])
            
            # Process secrets - THIS IS THE CORRECT WAY TO ACCESS THEM
            if "Secrets" in r:
                findings.extend(r["Secrets"])
                secret_count += len(r["Secrets"])
    
    raw_score = 0.0
    
    logging.info("\n--- DETAILED SECURITY DEBT ---")
    if findings:
        for idx, finding in enumerate(findings):
            rule_id = finding.get("ID", "UNKNOWN")
            # For secrets, the rule ID is in "RuleID" field
            if "Secrets" in finding:
                rule_id = finding.get("RuleID", "SECRET_UNKNOWN")
                
            weight = weights.get("weights", {}).get(rule_id, 0.0)
            raw_score += weight
            
            # Determine if this is a secret finding
            is_secret = "Secrets" in finding or any(x in rule_id for x in ["GEN", "AWS", "GHA", "GIT", "SECRET"])
            
            finding_type = "SECRET" if is_secret else "MISCONFIG"
            logging.info(f"[{idx+1}/{len(findings)}] {finding_type}: {rule_id} (Sev: {finding.get('Severity')}) -> Weight: {weight:.2f}")
    else:
        logging.info("No security findings found.")

    # --- REPORT SECRET SPECIFIC METRICS IF FOUND ---
    if secret_count > 0:
        logging.warning(f"!!! CRITICAL: {secret_count} hardcoded secrets detected !!!")
        # Only add the contextual warning if we have evidence from knowledge base
        logging.info("!!! Note: According to GitGuardian, hardcoded secrets increased by 67% in 2022 !!!")
        logging.info("!!! However, these will be properly weighted based on actual severity !!!")

    # --- CALCOLO SDS NORMALE ---
    logging.info("\n--- NORMALIZATION COEFFICIENTS AND FINAL SCORE ---")
    logging.info(f"Raw Score Sum (Total Security Debt): {raw_score:.2f}")
    logging.info(f"LOC Density (D - Righe di Codice IaC): {loc_density}")
    logging.info(f"Normalization Factor (Max Score from Sample): {max_sds_score:.2f}")
    
    # Calcolo SDS
    sds_normalized = (raw_score / max_sds_score) * 100.0
    final_sds = min(sds_normalized, 100.0) 

    logging.info(f"Calculated Normalized SDS (0-100): {final_sds:.2f}")
    logging.info("--- SDS Calculation Finished ---")
    
    return round(final_sds, 2)