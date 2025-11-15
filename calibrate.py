# calibrate.py
import json

# Range CVSS per ogni severità (min, max)
CVSS_BOUNDS = {
    "NONE": (0.0, 0.0),
    "LOW": (1.0, 3.9),
    "MEDIUM": (4.0, 6.9),
    "HIGH": (7.0, 8.9),
    "CRITICAL": (9.0, 10.0),
}


def calibrate_weights_from_results(results_list: list) -> dict:
    """
    Calibra dinamicamente i pesi delle severità basandosi sui percentili
    e applica i limiti min/max derivati dai range CVSS.
    """

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    # --- STEP 1: conteggio severità ---
    for data in results_list:
        results = data.get("Results", [])
        for res in results:
            if "Misconfigurations" in res:
                for m in res["Misconfigurations"]:
                    sev = m.get("Severity")
                    if sev in severity_counts:
                        severity_counts[sev] += 1

    total_issues = sum(severity_counts.values())
    if total_issues == 0:
        print("WARN: No issues found in dataset. Cannot calibrate.")
        return None

    print("\n--- Severity Count ---")
    print(severity_counts)

    # --- STEP 2: calcolo percentili cumulativi ---
    ordered = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    weights_raw = {}
    cumulative = 0.0

    for sev in ordered:
        count = severity_counts[sev]
        pct = count / total_issues

        midpoint = cumulative + pct / 2  # percentile medio della fascia
        score_0_10 = midpoint * 10       # scala 0–10

        weights_raw[sev] = score_0_10
        cumulative += pct

    print("\n--- Dynamic Percentile Weights (0–10) ---")
    print(weights_raw)

    # --- STEP 3: applicazione limiti CVSS ---
    weights_clamped = {}
    for sev, dyn_score in weights_raw.items():
        cvss_min, cvss_max = CVSS_BOUNDS[sev]
        final_score = max(cvss_min, min(dyn_score, cvss_max))
        weights_clamped[sev] = round(final_score, 2)

    print("\n--- Final CVSS-Clamped Weights ---")
    print(weights_clamped)

    return weights_clamped


if __name__ == "__main__":
    print("This script should be called from test_sds.py.")
