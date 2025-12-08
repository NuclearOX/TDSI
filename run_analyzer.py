import os
import json
import logging
import argparse
import sys
import time

# Import SDS components
from tdsi_analyzer.security_analyzer import calculate_sds, run_trivy_scan, count_terraform_resources, load_calibrated_weights
# Import Calibration
from calibrate import calibrate_metrics
# Import QDS components
from tdsi_analyzer.quality_analyzer import calculate_qds

# Configure logging
logger = logging.getLogger("Runner")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('[%(asctime)s] [RUNNER] %(message)s', datefmt='%H:%M:%S'))
    logger.addHandler(handler)

OUTPUT_DIR = "output"
WEIGHTS_FILE = os.path.join(OUTPUT_DIR, "calibrated_weights.json")

def perform_calibration(project_directories):
    """
    Runs SDS and QDS on all projects to generate calibration baselines.
    """
    logger.info("==========================================")
    logger.info(f"   STARTING HYBRID CALIBRATION: {len(project_directories)} PROJECTS")
    logger.info("==========================================")
    
    calibration_data = []

    for i, path in enumerate(project_directories):
        if not os.path.exists(path): continue
        logger.info(f"[{i+1}/{len(project_directories)}] analyzing: {os.path.basename(path)}")
        
        # 1. Count Resources
        res_count = count_terraform_resources(path)
        if res_count == 0: continue

        # 2. Run Security Scan (Raw JSON needed for frequency analysis)
        sds_scan = run_trivy_scan(path)
        
        # 3. Run Quality Scan (Raw Score needed for density analysis)
        qds_result = calculate_qds(path)
        qds_raw = qds_result['total_qds']
        
        calibration_data.append({
            'path': path,
            'resources': res_count,
            'sds_scan': sds_scan,
            'qds_raw': qds_raw
        })

    if not calibration_data:
        logger.error("No valid data collected. Calibration aborted.")
        return

    # Run the math
    calib_result = calibrate_metrics(calibration_data)

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    with open(WEIGHTS_FILE, "w") as f:
        json.dump(calib_result, f, indent=2)
        
    logger.info(f"Calibration Complete. Data saved to: {WEIGHTS_FILE}")

def perform_full_analysis(directory, alpha, beta):
    """
    Runs SDS and QDS, normalizes using Calibrated Thresholds, and calculates TDSI.
    """
    logger.info(f"--- Initiating TDSI Analysis for: {directory} ---")
    
    # Load Calibration Data
    calib_data = load_calibrated_weights()
    if calib_data:
        qds_threshold = calib_data.get("Max_QDS_Density", 30.0)
        logger.info(f"Loaded Calibrated Thresholds -> SDS_Max: {calib_data.get('Max_SDS_Density')}, QDS_Max: {qds_threshold}")
    else:
        qds_threshold = 30.0
        logger.warning("Using Default Thresholds (Uncalibrated).")

    logger.info(f"Parameters: Alpha={alpha}, Beta={beta}, QDS_Threshold={qds_threshold}")
    
    # 0. Count Resources
    resource_count = count_terraform_resources(directory)
    if resource_count == 0:
        logger.error("No resources found. Cannot calculate Debt Density.")
        return

    # 1. Calculate SDS (Returns Normalized 0-100)
    sds_score = calculate_sds(directory)
    
    # 2. Calculate QDS (Returns Raw)
    qds_result = calculate_qds(directory)
    raw_qds = qds_result['total_qds']
    
    # 3. Normalize QDS
    # Formula: (Raw_QDS / Resources) / Threshold * 100
    qds_density = raw_qds / resource_count
    normalized_qds = (qds_density / qds_threshold) * 100.0
    normalized_qds = min(normalized_qds, 100.0) 
    
    # 4. TDSI
    tdsi_score = (alpha * sds_score) + (beta * normalized_qds)
    
    logger.info("==========================================")
    logger.info("   🏁 FINAL TDSI RESULTS")
    logger.info("==========================================")
    logger.info(f"   SDS (Security): {sds_score:.2f}%")
    logger.info(f"   QDS (Quality):  {normalized_qds:.2f}% (Raw: {raw_qds:.0f}, Density: {qds_density:.2f})")
    logger.info(f"   --------------------------------------")
    logger.info(f"   🏆 TDSI SCORE:  {tdsi_score:.2f} / 100")
    logger.info("==========================================")

    result = {
        "project": directory,
        "tdsi_score": round(tdsi_score, 2),
        "components": {
            "sds_normalized": round(sds_score, 2),
            "qds_normalized": round(normalized_qds, 2),
            "qds_raw": raw_qds
        },
        "parameters": {
            "alpha": alpha,
            "beta": beta,
            "qds_threshold": qds_threshold,
            "resources_scanned": resource_count
        },
        "details": {
            "qds_breakdown": qds_result['breakdown']
        },
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TDSI Analyzer")
    parser.add_argument("projects", nargs="+", help="Project directories")
    parser.add_argument("--calibrate", action="store_true", help="Run SDS+QDS Calibration")
    parser.add_argument("--alpha", type=float, default=0.5, help="Weight for Security")
    parser.add_argument("--beta", type=float, default=0.5, help="Weight for Quality")
    parser.add_argument("--scan-subdirs", action="store_true", help="Treat subdirectories as projects") # Added missing logic
    
    args = parser.parse_args()
    
    targets = []
    for p in args.projects:
        if args.scan_subdirs and os.path.isdir(p):
            subdirs = [os.path.join(p, d) for d in os.listdir(p) if os.path.isdir(os.path.join(p, d))]
            targets.extend(subdirs)
        else:
            targets.append(p)

    if args.calibrate:
        perform_calibration(targets)
    else:
        # Se ci sono più target in modalità non-calibrate, analizza solo il primo o fai loop? 
        # Per ora analizziamo il primo per semplicità dell'output JSON singolo
        perform_full_analysis(targets[0], args.alpha, args.beta)