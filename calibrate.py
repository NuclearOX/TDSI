import logging
import sys
import os
from typing import Dict, Any, List
from datetime import datetime

# Logger configuration
logger = logging.getLogger("Calibration")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('[%(asctime)s] [CALIBRATION] %(message)s'))
    logger.addHandler(handler)

CVSS_BOUNDS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH": (7.0, 8.9),
    "MEDIUM": (4.0, 6.9),
    "LOW": (0.1, 3.9)
}

def calibrate_weights_from_results(scan_results: List[Dict[str, Any]], project_resource_counts: Dict[str, int]) -> Dict[str, Any]:
    """
    Performs the Hybrid Weight Calibration and Normalization logic.
    """
    logger.info("--- Starting Weight Calibration Logic ---")
    
    rule_counts = {}
    severity_map = {}
    
    # --- STEP 1: Frequency Counting ---
    logger.info("Step 1: Analyzing vulnerability prevalence across dataset...")
    for scan in scan_results:
        if "Results" not in scan: continue
        for res in scan["Results"]:
            findings = res.get("Misconfigurations", []) + res.get("Secrets", [])
            for f in findings:
                rule_id = f.get("ID", f.get("RuleID"))
                sev = f.get("Severity", "LOW").upper()
                if rule_id:
                    rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
                    severity_map[rule_id] = sev

    total_issues = sum(rule_counts.values())
    unique_rules = len(rule_counts)
    logger.info(f"Dataset Statistics: {total_issues} total issues found across {unique_rules} unique rules.")
    
    if total_issues == 0:
        logger.error("No issues found. Calibration cannot proceed.")
        return {}

    # Log Top 5 most common issues (Insight into the dataset)
    sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
    logger.info("Top 5 Most Frequent Vulnerabilities (Lower weight applied due to high frequency):")
    for i, (rid, count) in enumerate(sorted_rules[:5]):
        pct = (count / total_issues) * 100
        logger.info(f"   {i+1}. {rid} ({severity_map[rid]}): {count} occurrences ({pct:.1f}%)")

    # --- STEP 2: Weight Calculation ---
    logger.info("Step 2: Calculating Dynamic Weights (Hybrid Approach)...")
    final_weights = {}
    
    for rule_id, count in rule_counts.items():
        sev = severity_map.get(rule_id, "LOW")
        prevalence_pct = count / total_issues
        
        # Rarity Modifier: Rare issues = Higher Impact
        rarity_modifier = 1.0 - prevalence_pct 
        
        # Base Score from CVSS Max
        base_score = CVSS_BOUNDS.get(sev, (1.0, 1.0))[1]
        
        # Formula: Weight = Base * (0.8 + (Rarity * 0.2))
        weight = base_score * (0.8 + (rarity_modifier * 0.2))
        final_weights[rule_id] = round(weight, 2)

    logger.info(f"Generated weights for {len(final_weights)} rules.")

    # --- STEP 3: Max Density Determination ---
    logger.info("Step 3: Determining Max Density Threshold (95th Percentile)...")
    project_densities = []
    
    for scan in scan_results:
        path = scan.get('project_path')
        res_count = project_resource_counts.get(path, 0)
        
        if res_count == 0: continue
        
        # Re-calculate risk using new weights
        total_risk = 0.0
        if "Results" in scan:
            for res in scan["Results"]:
                findings = res.get("Misconfigurations", []) + res.get("Secrets", [])
                for f in findings:
                    rid = f.get("ID", f.get("RuleID"))
                    total_risk += final_weights.get(rid, 0.0)
        
        density = total_risk / res_count
        project_densities.append(density)

    # Statistical Thresholding
    project_densities.sort()
    logger.info(f"Observed Project Densities (Sorted): {[round(d, 2) for d in project_densities]}")
    
    if project_densities:
        idx = int(len(project_densities) * 0.95)
        calculated_max = project_densities[idx]
        logger.info(f"95th Percentile Value: {calculated_max:.2f}")
        
        # Safety Floor
        max_density = max(calculated_max, 5.0)
        if max_density == 5.0 and calculated_max < 5.0:
            logger.info("Applied Safety Floor: Threshold raised to 5.0 to prevent score inflation.")
    else:
        max_density = 5.0
        logger.warning("No valid project densities found. Defaulting to 5.0.")

    logger.info(f"✅ Final Max Density Threshold: {max_density:.2f}")

    return {
        "calibration_date": str(datetime.now()),
        "Max_SDS_Density": round(max_density, 2),
        "weights": final_weights
    }