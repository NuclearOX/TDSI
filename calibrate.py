import logging
import sys
import numpy as np # Se non hai numpy, possiamo usare statistics o logica base, qui uso logica base per non aggiungere dipendenze
from typing import Dict, Any, List
from datetime import datetime

# Logger configuration
logger = logging.getLogger("Calibration")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('[%(asctime)s] [CALIB] %(message)s', datefmt='%H:%M:%S'))
    logger.addHandler(handler)

CVSS_BOUNDS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH": (7.0, 8.9),
    "MEDIUM": (4.0, 6.9),
    "LOW": (0.1, 3.9)
}

# Fallback weights for calibration calculation
FALLBACK_WEIGHTS = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0}

def get_percentile(data: List[float], percentile: float) -> float:
    """Calculates percentile safely without heavy dependencies."""
    if not data: return 5.0 # Safety default
    data.sort()
    k = (len(data) - 1) * percentile
    f = int(np.floor(k)) if 'numpy' in sys.modules else int(k) # Simple floor if numpy missing
    c = int(np.ceil(k)) if 'numpy' in sys.modules else int(k) + 1
    if f == c: return data[int(k)]
    return data[f] * (c - k) + data[c] * (k - f)

def calibrate_metrics(calibration_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Performs Hybrid Calibration for BOTH Security (SDS) and Quality (QDS).
    Input `calibration_data` contains:
      - 'sds_scan': The JSON from Trivy
      - 'qds_raw': The raw float score from QDS
      - 'resources': Integer count of resources
    """
    logger.info("--- Starting TDSI Hybrid Calibration ---")
    
    # --- PART 1: SDS Weights (Frequency Analysis) ---
    logger.info("Step 1/3: Calibrating Security Weights based on Prevalence...")
    rule_counts = {}
    severity_map = {}
    
    total_issues = 0
    for entry in calibration_data:
        scan = entry.get('sds_scan')
        if not scan or "Results" not in scan: continue
        
        for res in scan["Results"]:
            findings = res.get("Misconfigurations", []) + res.get("Secrets", [])
            for f in findings:
                rule_id = f.get("ID", f.get("RuleID"))
                sev = f.get("Severity", "LOW").upper()
                if rule_id:
                    rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
                    severity_map[rule_id] = sev
                    total_issues += 1

    final_weights = {}
    if total_issues > 0:
        for rule_id, count in rule_counts.items():
            sev = severity_map.get(rule_id, "LOW")
            prevalence_pct = count / total_issues
            # Rarity Modifier: Rare issues = Higher Impact
            rarity_modifier = 1.0 - prevalence_pct 
            base_score = CVSS_BOUNDS.get(sev, (1.0, 1.0))[1]
            # Formula: Weight = Base * (0.8 + (Rarity * 0.2))
            weight = base_score * (0.8 + (rarity_modifier * 0.2))
            final_weights[rule_id] = round(weight, 2)
        logger.info(f"   Generated weights for {len(final_weights)} rules.")
    else:
        logger.warning("   No security issues found in dataset. Weights skipped.")

    # --- PART 2: SDS Density Threshold ---
    logger.info("Step 2/3: Determining Max SDS Density (95th Percentile)...")
    sds_densities = []
    
    for entry in calibration_data:
        res_count = entry.get('resources', 0)
        if res_count == 0: continue
        
        # Calculate Risk Score using NEW weights
        scan = entry.get('sds_scan')
        total_risk = 0.0
        if scan and "Results" in scan:
            for res in scan["Results"]:
                findings = res.get("Misconfigurations", []) + res.get("Secrets", [])
                for f in findings:
                    rid = f.get("ID", f.get("RuleID"))
                    sev = f.get("Severity", "LOW").upper()
                    # Use calibrated weight or fallback
                    w = final_weights.get(rid, FALLBACK_WEIGHTS.get(sev, 1.0))
                    total_risk += w
        
        density = total_risk / res_count
        sds_densities.append(density)

    max_sds_density = get_percentile(sds_densities, 0.95) if sds_densities else 5.0
    # Safety Floor
    max_sds_density = max(max_sds_density, 5.0)
    logger.info(f"   SDS Densities: {[round(d,1) for d in sds_densities]}")
    logger.info(f"   ✅ Max SDS Density Threshold: {max_sds_density:.2f}")

    # --- PART 3: QDS Density Threshold ---
    logger.info("Step 3/3: Determining Max QDS Density (95th Percentile)...")
    qds_densities = []
    
    for entry in calibration_data:
        res_count = entry.get('resources', 0)
        qds_raw = entry.get('qds_raw', 0.0)
        
        if res_count > 0:
            density = qds_raw / res_count
            qds_densities.append(density)
            
    max_qds_density = get_percentile(qds_densities, 0.95) if qds_densities else 20.0
    # Safety Floor (Minimum 10 points per resource implies significant debt)
    max_qds_density = max(max_qds_density, 10.0)
    
    logger.info(f"   QDS Densities: {[round(d,1) for d in qds_densities]}")
    logger.info(f"   ✅ Max QDS Density Threshold: {max_qds_density:.2f}")

    return {
        "calibration_date": str(datetime.now()),
        "Max_SDS_Density": round(max_sds_density, 2),
        "Max_QDS_Density": round(max_qds_density, 2),
        "weights": final_weights
    }