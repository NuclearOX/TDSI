import os

# --- PATH CONFIGURATION ---
# Absolute paths based on the Docker container filesystem structure
BASE_DIR = "/app"
DATA_INPUT_DIR = os.path.join(BASE_DIR, "data", "input")
DATA_OUTPUT_DIR = os.path.join(BASE_DIR, "data", "output")

# Specific file paths for input database and output results
DB_PATH = os.path.join(DATA_INPUT_DIR, "TerraDS.sqlite")
OUTPUT_CSV_PATH = os.path.join(DATA_OUTPUT_DIR, "dataset_final.csv")
LOG_FILE_PATH = os.path.join(DATA_OUTPUT_DIR, "execution.log")

# --- MINING & SAMPLING STRATEGY ---
# MIN_STARS: Minimum GitHub stars to filter out "toy" or empty projects.
# A threshold of 30 is low enough to capture growing projects but high enough to ensure a baseline of community interest.
MIN_STARS = 10          

# REPO_LIMIT: Maximum number of repositories to analyze in one execution.
# For a Master's Thesis, a sample size between 50 and 100 is scientifically significant.
REPO_LIMIT = 100       

# --- EVOLUTIONARY ANALYSIS CONFIGURATION (RQ3) ---
# MAX_SNAPSHOTS: Maximum number of versions (Tags or Commits) to analyze per repository.
# 100 snapshots provide a deep longitudinal view of the software evolution.
MAX_SNAPSHOTS = 100      

# MIN_SNAPSHOTS_FOR_STATS: Minimum data points required to run a trend test (Mann-Kendall).
# Repositories with fewer than 5 structural changes are excluded from RQ3 trend analysis.
MIN_SNAPSHOTS_FOR_STATS = 5

# --- TIMEOUT SETTINGS ---
# REPO_ANALYSIS_TIMEOUT: Global limit for a single repository analysis (in seconds).
# 3600s (1 hour) is a robust threshold to prevent "huge" repos from blocking the pipeline.
REPO_ANALYSIS_TIMEOUT = 3600 

# TRIVY_TIMEOUT: Internal timeout for the Trivy CLI scanner per snapshot.
# 15 minutes ensure that even complex modules are fully scanned.
TRIVY_CLI_TIMEOUT = "50m"

# --- SECURITY DEBT WEIGHTS ---
# Weights based on CVSS v3.1 severity classes and academic literature (e.g., Rahman et al. 2019).
# These weights represent the "Remediation Effort" proxy for Security Debt.
SEVERITY_WEIGHTS = {
    'CRITICAL': 9.5,
    'HIGH': 8.0,
    'MEDIUM': 5.0,
    'LOW': 2.0,
    'UNKNOWN': 0.0
}