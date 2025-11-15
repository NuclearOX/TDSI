# tdsi_analyzer/security_analyzer.py

import subprocess
import json
import os

_weights_cache = None


def load_calibrated_weights(weights_file="calibrated_weights.json"):
    global _weights_cache
    if _weights_cache:
        return _weights_cache

    try:
        with open(weights_file, "r") as f:
            _weights_cache = json.load(f)
        print(f"Loaded calibrated weights: {_weights_cache}")
        return _weights_cache
    except FileNotFoundError:
        print("FATAL: Calibrated weights file not found. Run calibration first.")
        return None


def run_trivy_scan(directory_path: str) -> dict | None:
    """
    Esegue Trivy via Docker e ritorna l'output JSON parsificato.
    """
    abs_path = os.path.abspath(directory_path)
    command = [
        "docker", "run", "--rm",
        "-v", f"{abs_path}:/scan",
        "aquasec/trivy:latest",
        "config", "/scan",
        "--format", "json",
        "--exit-code", "0",
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW"
    ]

    print(f"Running Trivy scan on {directory_path}...")

    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8"
        )
        return json.loads(result.stdout)
    except Exception as e:
        print(f"FATAL: Trivy scan error: {e}")
        return None


def calculate_sds(directory_path: str) -> float:
    """
    Calcola lo SDS usando i pesi dinamici CVSS-normalized.
    """
    weights = load_calibrated_weights()
    if not weights:
        return -1

    scan_data = run_trivy_scan(directory_path)
    if not scan_data:
        return -1

    results = scan_data.get("Results", [])
    misconfigs = []

    for r in results:
        if "Misconfigurations" in r:
            misconfigs.extend(r["Misconfigurations"])

    if not misconfigs:
        print("No misconfigurations found.")
        return 0

    print(f"Found {len(misconfigs)} misconfigurations.")

    score = 0.0
    for m in misconfigs:
        sev = m.get("Severity")
        if sev in weights:
            score += weights[sev]
        else:
            print(f"WARNING: Unknown severity {sev}")

    return round(score, 2)
