import subprocess
import json
import os
import re
import logging
import sys
import time
from typing import Dict, Any

# --- LOGGING CONFIGURATION ---
logger = logging.getLogger("SDS_Analyzer")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    # Format: [TIME] [COMPONENT] MESSAGE
    handler.setFormatter(logging.Formatter('[%(asctime)s] [SDS] %(message)s', datefmt='%H:%M:%S'))
    logger.addHandler(handler)

_weights_cache = None

# --- CONSTANTS ---
# Fallback weights (Midpoints of CVSS Classes)
FALLBACK_WEIGHTS = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.0
}

def load_calibrated_weights(weights_file="output/calibrated_weights.json") -> Dict[str, Any] | None:
    global _weights_cache
    if _weights_cache: 
        return _weights_cache
    
    try:
        with open(weights_file, "r") as f:
            _weights_cache = json.load(f)
        logger.info(f"Weights loaded. Rules: {len(_weights_cache.get('weights', {}))}")
        return _weights_cache
    except FileNotFoundError:
        logger.warning(f"Weights file not found at {weights_file}. Using Fallback defaults.")
        return None
    except Exception as e:
        logger.error(f"Error loading weights: {e}")
        return None

def run_trivy_scan(directory_path: str) -> Dict[str, Any] | None:
    abs_path = os.path.abspath(directory_path)
    logger.info(f"Target: {abs_path}")
    
    cmd = [
        "trivy", "fs",
        "--scanners", "config,secret",
        "--format", "json",
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
        "--offline-scan",         
        "--skip-db-update",       
        "--skip-java-db-update",  
        "--skip-check-update",    
        "--skip-dirs", ".terragrunt-cache",
        "--skip-dirs", ".terraform",
        "--skip-dirs", ".git",
        "--skip-dirs", "node_modules",
        "--timeout", "20m",
        abs_path
    ]
    
    TIMEOUT_SECONDS = 1200 
    start_time = time.time()
    
    try:
        logger.info(f"   -> Launching Trivy (Offline)... Timeout: {TIMEOUT_SECONDS}s")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=TIMEOUT_SECONDS)
        elapsed = time.time() - start_time
        
        if result.returncode != 0:
            logger.warning(f"   -> Trivy exit code: {result.returncode}")
            if result.stderr: logger.warning(f"   -> Error excerpt: {result.stderr[-300:]}")
        
        if not result.stdout.strip():
            logger.warning("   -> Trivy returned empty output.")
            return None
            
        data = json.loads(result.stdout)
        logger.info(f"   -> Scan complete in {elapsed:.2f}s.")
        return data
        
    except subprocess.TimeoutExpired:
        logger.error(f"   -> CRITICAL: Trivy timed out after {TIMEOUT_SECONDS}s.")
        return None
    except Exception as e:
        logger.error(f"   -> Unexpected error: {e}")
        return None

def count_terraform_resources(directory_path: str) -> int:
    resource_count = 0
    file_count = 0
    resource_pattern = re.compile(r'^\s*(resource|module)\s+"[^"]+"', re.MULTILINE)

    for root, dirs, files in os.walk(directory_path):
        dirs[:] = [d for d in dirs if d not in ['.terragrunt-cache', '.terraform', '.git']]
        for file in files:
            if file.endswith(".tf"):
                file_count += 1
                try:
                    with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                        resource_count += len(resource_pattern.findall(f.read()))
                except: continue
    
    logger.info(f"   -> Found {resource_count} Logical Resources across {file_count} files.")
    return resource_count

def calculate_sds(directory_path: str) -> float:
    logger.info("========================================")
    logger.info("   STEP 1/2: SECURITY DEBT (SDS)")
    logger.info("========================================")
    
    # Load Weights
    weights_data = load_calibrated_weights()
    max_density_threshold = weights_data.get("Max_SDS_Density", 10.0) if weights_data else 10.0
    weights_map = weights_data.get("weights", {}) if weights_data else {}

    # 1. Scan
    scan_data = run_trivy_scan(directory_path)
    if scan_data is None: return -1.0
    
    # 2. Count Resources
    resource_count = count_terraform_resources(directory_path)
    if resource_count == 0: return 0.0

    # 3. Risk Calculation
    total_risk_score = 0.0
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    if "Results" in scan_data:
        for result in scan_data["Results"]:
            all_findings = result.get("Misconfigurations", []) + result.get("Secrets", [])
            for finding in all_findings:
                rule_id = finding.get("ID", finding.get("RuleID", "UNKNOWN"))
                severity = finding.get("Severity", "LOW").upper()
                
                if severity in stats: stats[severity] += 1
                
                # Weight Logic
                if rule_id in weights_map:
                    weight = weights_map[rule_id]
                else:
                    weight = FALLBACK_WEIGHTS.get(severity, 1.0)
                
                total_risk_score += weight

    # 4. Final Math
    sds_density = total_risk_score / resource_count
    final_sds = (sds_density / max_density_threshold) * 100.0
    capped_sds = min(final_sds, 100.0)
    
    logger.info(f"--- SDS REPORT ---")
    logger.info(f"   Findings:      {stats}")
    logger.info(f"   Risk Score:    {total_risk_score:.2f} (Numerator)")
    logger.info(f"   Resources:     {resource_count} (Denominator)")
    logger.info(f"   Risk Density:  {sds_density:.4f} (Max Thresh: {max_density_threshold})")
    logger.info(f"   ✅ FINAL SDS:  {capped_sds:.2f}")

    return round(capped_sds, 2)