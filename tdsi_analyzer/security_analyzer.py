import subprocess
import json
import os
import re
import logging
import sys
import time
from typing import Dict, Any

# --- LOGGING CONFIGURATION ---
# We use a specific logger name to avoid conflicts.
# We output to STDERR so that the final JSON output (STDOUT) remains pure for piping.
logger = logging.getLogger("SDS_Analyzer")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    # Detailed format: Time | Component | Message
    handler.setFormatter(logging.Formatter('[%(asctime)s] [SDS_Analyzer] %(message)s'))
    logger.addHandler(handler)

_weights_cache = None

def load_calibrated_weights(weights_file="output/calibrated_weights.json") -> Dict[str, Any] | None:
    """
    Loads the calibration data (Weights and Max Density Threshold).
    Implements caching to prevent re-reading the file on every call.
    """
    global _weights_cache
    if _weights_cache: 
        return _weights_cache
    
    logger.info(f"Attempting to load weights from: {weights_file}")
    try:
        with open(weights_file, "r") as f:
            _weights_cache = json.load(f)
        
        # Log summary of what was loaded
        rule_count = len(_weights_cache.get("weights", {}))
        max_density = _weights_cache.get("Max_SDS_Density", "UNKNOWN")
        logger.info(f"Weights loaded successfully. Rules: {rule_count} | Max Density Threshold: {max_density}")
        return _weights_cache
    except FileNotFoundError:
        logger.error(f"CRITICAL: Weights file not found at {weights_file}. SDS will likely fail or use defaults.")
        return None
    except Exception as e:
        logger.error(f"Error loading weights: {e}")
        return None

def run_trivy_scan(directory_path: str) -> Dict[str, Any] | None:
    """
    Executes the Trivy binary directly on the filesystem.
    """
    abs_path = os.path.abspath(directory_path)
    logger.info(f"--- Step 1: Executing Trivy Scan ---")
    logger.info(f"Target: {abs_path}")
    
    cmd = [
        "trivy", "fs",
        "--scanners", "config,secret",
        "--format", "json",
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
        abs_path
    ]
    
    start_time = time.time()
    try:
        # Run the command
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        elapsed = time.time() - start_time
        
        if result.returncode != 0:
            logger.warning(f"Trivy finished with non-zero exit code: {result.returncode}")
        
        if not result.stdout.strip():
            logger.warning(f"Trivy returned empty output. (Duration: {elapsed:.2f}s)")
            return None
            
        data = json.loads(result.stdout)
        logger.info(f"Trivy scan completed in {elapsed:.2f}s. Parsing results...")
        return data
        
    except FileNotFoundError:
        logger.critical("Trivy binary not found! Is it installed in the environment?")
        return None
    except json.JSONDecodeError:
        logger.error("Trivy produced invalid JSON output. Check raw logs if debugging.")
        return None

def count_terraform_resources(directory_path: str) -> int:
    """
    Parses .tf files to count logical infrastructure resources.
    This is the Denominator for the Density Calculation.
    """
    logger.info(f"--- Step 2: Measuring Infrastructure Size (Resource Counting) ---")
    resource_count = 0
    file_count = 0
    
    # Regex to find 'resource "type" "name" {' OR 'module "name" {'
    resource_pattern = re.compile(r'^\s*(resource|module)\s+"[^"]+"', re.MULTILINE)

    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith(".tf"):
                file_count += 1
                try:
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        matches = resource_pattern.findall(content)
                        count_in_file = len(matches)
                        resource_count += count_in_file
                        # Only log verbose details for files that actually have resources
                        if count_in_file > 0:
                            logger.debug(f"   -> {file}: Found {count_in_file} resources")
                except Exception as e:
                    logger.warning(f"Could not read file {file}: {e}")
                    continue
    
    logger.info(f"Scanned {file_count} Terraform files. Total Logical Resources: {resource_count}")
    return resource_count

def calculate_sds(directory_path: str) -> float:
    """
    Calculates the Security Debt Score (SDS).
    """
    logger.info(f"STARTING SDS CALCULATION FOR: {os.path.basename(directory_path)}")
    
    # Load Weights
    weights_data = load_calibrated_weights()
    if not weights_data:
        logger.error("Aborting calculation: Weights missing.")
        return -1.0

    max_density_threshold = weights_data.get("Max_SDS_Density", 5.0)
    weights_map = weights_data.get("weights", {})

    # 1. Scan
    scan_data = run_trivy_scan(directory_path)
    
    # 2. Count Resources
    resource_count = count_terraform_resources(directory_path)
    if resource_count == 0:
        logger.warning(f"No Terraform resources found. SDS force-set to 0.0")
        return 0.0

    # 3. Aggregate Risk
    logger.info(f"--- Step 3: Aggregating Risk & Applying Weights ---")
    total_risk_score = 0.0
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    finding_count = 0
    
    if scan_data and "Results" in scan_data:
        for result in scan_data["Results"]:
            # Combine Misconfigurations + Secrets
            all_findings = result.get("Misconfigurations", []) + result.get("Secrets", [])
            
            for finding in all_findings:
                finding_count += 1
                rule_id = finding.get("ID", finding.get("RuleID", "UNKNOWN"))
                severity = finding.get("Severity", "LOW")
                
                if severity in stats: stats[severity] += 1
                
                # Weight Determination Logic
                if rule_id in weights_map:
                    weight = weights_map[rule_id]
                    # logger.debug(f"   Rule {rule_id} ({severity}) -> Calibrated Weight: {weight}")
                else:
                    # Fallback
                    weight = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0}.get(severity, 1.0)
                    logger.warning(f"   Rule {rule_id} not in calibration. Using Fallback Weight: {weight}")
                
                total_risk_score += weight

    # 4. Calculate Final Score
    logger.info(f"--- Step 4: Normalization & Scoring ---")
    logger.info(f"   Total Findings: {finding_count}")
    logger.info(f"   Severity Breakdown: {stats}")
    logger.info(f"   Total Weighted Risk (Numerator): {total_risk_score:.2f}")
    logger.info(f"   Total Resources (Denominator):   {resource_count}")
    
    # Density Calculation
    sds_density = total_risk_score / resource_count
    logger.info(f"   Calculated Risk Density: {sds_density:.4f} points/resource")
    logger.info(f"   Max Density Threshold:   {max_density_threshold:.4f}")
    
    # Final Normalization
    final_sds = (sds_density / max_density_threshold) * 100.0
    capped_sds = min(final_sds, 100.0)
    
    logger.info(f"   Raw Percentage: {final_sds:.2f}%")
    logger.info(f"✅ FINAL SDS SCORE: {capped_sds:.2f}")

    return round(capped_sds, 2)