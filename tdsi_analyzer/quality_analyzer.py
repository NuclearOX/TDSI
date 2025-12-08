import logging
import sys
from typing import Dict, Any

from .tflint_wrapper import run_tflint_analysis, calculate_tflint_score
from .custom_smells import check_custom_smells

logger = logging.getLogger("QDS_Orchestrator")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('[%(asctime)s] [QDS] %(message)s', datefmt='%H:%M:%S'))
    logger.addHandler(handler)

# Weights
W_DOC = 2.0
W_MONO = 15.0
W_DUP = 10.0

def calculate_qds(directory: str) -> Dict[str, Any]:
    logger.info("========================================")
    logger.info("   STEP 2/2: QUALITY DEBT (QDS)")
    logger.info("========================================")
    
    # 1. TFLint
    logger.info("Running TFLint Analysis...")
    tflint_raw = run_tflint_analysis(directory)
    tflint_score = calculate_tflint_score(tflint_raw)
    
    # 2. Custom Smells
    logger.info("Running Custom Smell Detection...")
    custom_metrics = check_custom_smells(directory)
    
    # 3. Calculation
    custom_score = (custom_metrics['missing_descriptions'] * W_DOC) + \
                   (custom_metrics['monolithic_modules'] * W_MONO) + \
                   (custom_metrics['duplicated_blocks'] * W_DUP)
    
    total_qds_raw = tflint_score + custom_score
    
    logger.info(f"--- QDS RAW REPORT ---")
    logger.info(f"   TFLint Score:  {tflint_score}")
    logger.info(f"   Custom Score:  {custom_score} (Docs={custom_metrics['missing_descriptions']}, Monoliths={custom_metrics['monolithic_modules']}, Dups={custom_metrics['duplicated_blocks']})")
    logger.info(f"   ✅ RAW QDS:    {total_qds_raw}")
    
    return {
        "total_qds": round(total_qds_raw, 2),
        "breakdown": {
            "tflint_score": tflint_score,
            "custom_score": custom_score,
            "metrics": custom_metrics
        }
    }