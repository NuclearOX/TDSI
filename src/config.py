import os

# --- PATH CONFIGURATION (DYNAMIC) ---
# Automatically detects if running inside a Docker container or locally.
if os.path.exists("/.dockerenv"):
    # Inside Docker: use absolute paths.
    BASE_DIR = "/app"
else:
    # Local execution: use the current working directory.
    BASE_DIR = os.getcwd()

# Define data directories based on the detected base path.
DATA_INPUT_DIR = os.path.join(BASE_DIR, "data", "input")
DATA_OUTPUT_DIR = os.path.join(BASE_DIR, "data", "output")

# Specific file paths for the study's artifacts.
DB_PATH = os.path.join(DATA_INPUT_DIR, "TerraDS.sqlite")
OUTPUT_CSV_PATH = os.path.join(DATA_OUTPUT_DIR, "dataset_final.csv") # Naming convention for clean data
LOG_FILE_PATH = os.path.join(DATA_OUTPUT_DIR, "execution.log")

# --- MINING & SAMPLING STRATEGY ---
# Gold Standard: 384+ samples for 95% confidence and 5% margin of error.
# We round up to 500 for a robust sample size.
REPO_LIMIT = 500       

# Relevant Population Filter: Minimum stars to exclude toy projects.
MIN_STARS = 10          

# --- EVOLUTIONARY ANALYSIS CONFIGURATION (RQ3) ---
# Maximum number of snapshots to analyze per repository.
# 100 snapshots provide a deep longitudinal view across a project's history.
MAX_SNAPSHOTS = 100      

# Minimum data points required for a statistically significant trend test.
MIN_SNAPSHOTS_FOR_STATS = 5

# --- TIMEOUT SETTINGS (CRITICAL FOR ROBUSTNESS) ---
# Global timeout for the analysis of a single repository (in seconds).
# 5400s (90 minutes) is an aggressive but safe upper bound to prevent stalls.
REPO_ANALYSIS_TIMEOUT = 5400 

# Internal timeout for the Trivy CLI scanner per snapshot.
# Set to 50 minutes to handle very large modules without being killed prematurely
# by the global timeout. The Python timeout MUST be greater than this value.
TRIVY_CLI_TIMEOUT = "60m"

# --- SECURITY DEBT WEIGHTS ---
# Based on CVSS v3.1 severity classes and academic literature (e.g., Rahman et al. 2019).
# These weights serve as a proxy for Remediation Effort.
SEVERITY_WEIGHTS = {
    'CRITICAL': 9.5,
    'HIGH': 8.0,
    'MEDIUM': 5.0,
    'LOW': 2.0,
    'UNKNOWN': 0.0
}