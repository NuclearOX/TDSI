# test_sds_2.py

import os
import json

from calibrate import calibrate_weights_from_results
from tdsi_analyzer.security_analyzer import (
    run_trivy_scan,
    calculate_sds
)

if __name__ == "__main__":
    test_dir = os.path.join(os.path.dirname(__file__), "test_project")
    weights_file = "calibrated_weights.json"

    print("\n============================")
    print("STEP 1: CALIBRATION SCAN")
    print("============================")

    scan = run_trivy_scan(test_dir)
    if not scan:
        print("Calibration scan failed.")
        exit(1)

    print("\n============================")
    print("STEP 2: CALCULATION OF DYNAMIC WEIGHTS")
    print("============================")

    weights = calibrate_weights_from_results([scan])
    if not weights:
        print("Calibration error.")
        exit(1)

    with open(weights_file, "w") as f:
        json.dump(weights, f, indent=2)

    print(f"Saved calibrated weights → {weights_file}")

    print("\n============================")
    print("STEP 3: SDS CALCULATION")
    print("============================")

    sds = calculate_sds(test_dir)
    print("\n--- FINAL SDS SCORE ---")
    print(f"SDS Score: {sds}")

    if sds >= 0:
        print("SUCCESS: SDS computed successfully.")
    else:
        print("FAILURE: SDS returned an error.")
