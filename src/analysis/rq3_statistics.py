"""
rq3_statistics.py — RQ3 Evolutionary Analysis
==============================================
Research Question:
    How do structural debt (StDI) and security debt (SDI) co-evolve during
    the entire lifecycle of an IaC project, and what is the prevalence of
    joint monotonic trends observable in the analysed population?

Pipeline position:
    Requires:
        - data/output/dataset_final.csv
        - data/output/retained_repos_after_trivy_filter.csv  (validate_sample.py)
        - data/output/figures/rq2/rq2_feature_importance.csv  (rq2_prediction.py)
    Produces:
        - data/output/figures/rq3/rq3_per_repo_results.csv
        - data/output/figures/rq3/rq3_trend_contingency.csv
        - data/output/figures/rq3/rq3_numerical_summary.txt
        - data/output/figures/rq3/selected_case_studies.json

Preprocessing (consistent with all RQ scripts):
    1. analysis_mode == 'ANALYZED'  (unique code states only)
    2. Trivy filter: only repos in retained_repos_after_trivy_filter.csv
    3. loc > 0 and security_debt_score not null

StDI construction:
    StDI_t = sum_i( z_score(metric_i)_t * importance_i )
    where importance_i comes from rq2_feature_importance.csv.
    Z-scores are computed per-repo (intra-project normalisation) so that
    StDI captures structural variation relative to each project's own
    history, not cross-project magnitude differences.

Co-evolution analysis:
    1. Mann-Kendall trend test on SDI and StDI independently per repo.
       Produces a 3x3 contingency table of joint trend combinations
       (increasing / no trend / decreasing) x (SDI / StDI).
    2. Longitudinal Spearman correlation between StDI and SDI per repo.
       Quantifies the strength and direction of co-movement.

Case study selection:
    One representative repo is selected per sufficiently populated cell
    of the 3x3 contingency table (>= MIN_CELL_SIZE_FOR_CASE_STUDY repos).
    Selection criterion: strongest absolute Spearman rho with n_snapshots
    as tiebreaker. This ensures case studies illustrate the full diversity
    of observed co-evolution behaviours without presupposing a taxonomy.
"""

import json
import logging
import os
import sys
import warnings

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

try:
    import pymannkendall as mk
    MK_AVAILABLE = True
except ImportError:
    MK_AVAILABLE = False
    warnings.warn(
        "pymannkendall not found. Mann-Kendall tests will be skipped. "
        "Install with: pip install pymannkendall"
    )

sys.path.append(os.getcwd())

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config import
# ---------------------------------------------------------------------------
try:
    from src import config
except ImportError:
    logger.error("Could not import src.config. Run this script from the project root.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
INPUT_CSV      = os.path.join(config.DATA_OUTPUT_DIR, "dataset_final.csv")
RETAINED_CSV   = os.path.join(config.DATA_OUTPUT_DIR,
                               "retained_repos_after_trivy_filter.csv")
IMPORTANCE_CSV = os.path.join(config.DATA_OUTPUT_DIR, "figures", "rq2",
                               "rq2_feature_importance.csv")
OUTPUT_DIR     = os.path.join(config.DATA_OUTPUT_DIR, "figures", "rq3")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Minimum number of repos in a contingency cell to select a case study.
MIN_CELL_SIZE_FOR_CASE_STUDY = 3

# Number of case studies to select per contingency cell.
CASE_STUDIES_PER_CELL = 1

# Ordered trend labels for the contingency table axes.
TREND_LABELS = ["increasing", "no trend", "decreasing"]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _load_and_preprocess(input_csv: str, retained_csv: str) -> pd.DataFrame:
    """
    Loads dataset_final.csv and applies the standard three-step filter:
        1. analysis_mode == 'ANALYZED'
        2. Trivy filter (only repos in retained_repos_after_trivy_filter.csv)
        3. loc > 0 and security_debt_score not null

    Returns the filtered DataFrame sorted by repo_name and author_date.
    """
    logger.info("Loading dataset...")
    df = pd.read_csv(input_csv, low_memory=False)
    logger.info(f"  Raw rows: {len(df):,}")

    df = df[df["analysis_mode"] == "ANALYZED"].copy()
    logger.info(f"  After analysis_mode filter: {len(df):,} rows")

    retained = pd.read_csv(retained_csv)["repo_name"].unique()
    df = df[df["repo_name"].isin(retained)].copy()
    logger.info(f"  After Trivy filter: {len(df):,} rows "
                f"({df['repo_name'].nunique()} repos)")

    df["loc"] = pd.to_numeric(df["loc"], errors="coerce")
    df["security_debt_score"] = pd.to_numeric(
        df["security_debt_score"], errors="coerce"
    )
    df = df[(df["loc"] > 0) & df["security_debt_score"].notna()].copy()
    logger.info(f"  After loc/SDI filter: {len(df):,} rows "
                f"({df['repo_name'].nunique()} repos)")

    df["author_date"] = pd.to_datetime(
        df["author_date"], errors="coerce", utc=True
    )
    df = df.sort_values(["repo_name", "author_date"]).reset_index(drop=True)
    return df


def _compute_stdi(group: pd.DataFrame, weights: dict) -> np.ndarray:
    """
    Computes the per-snapshot StDI series for a single repository.

    StDI_t = sum_i( z_score(metric_i)_t * importance_i )

    Z-scores are computed relative to the repo's own history so that
    StDI captures intra-project structural variation over time.
    Metrics absent from the DataFrame are silently skipped.
    """
    stdi = np.zeros(len(group))
    for feature, weight in weights.items():
        if feature not in group.columns:
            continue
        vals = pd.to_numeric(group[feature], errors="coerce").fillna(0).values
        std = vals.std()
        if std > 0:
            z = (vals - vals.mean()) / std
        else:
            z = np.zeros_like(vals)
        stdi += z * weight
    return stdi


def _mann_kendall(series: np.ndarray) -> tuple:
    """
    Runs the original Mann-Kendall trend test on a time series.

    Returns (trend_label, p_value) where trend_label is one of
    'increasing', 'decreasing', or 'no trend'.
    Returns ('no trend', None) if pymannkendall is unavailable or the
    series is too short.
    """
    if not MK_AVAILABLE or len(series) < config.MIN_SNAPSHOTS_FOR_STATS:
        return "no trend", None
    try:
        result = mk.original_test(series)
        return result.trend, result.p
    except Exception:
        return "no trend", None


def _build_contingency_table(results_df: pd.DataFrame) -> pd.DataFrame:
    """
    Builds a 3x3 contingency table of joint Mann-Kendall trend combinations.

    Rows = SDI trend  (increasing / no trend / decreasing)
    Cols = StDI trend (increasing / no trend / decreasing)

    Cell values are repo counts. This is the primary quantitative answer
    to the co-evolution question in RQ3.
    """
    contingency = pd.DataFrame(
        0,
        index=TREND_LABELS,
        columns=TREND_LABELS,
    )
    contingency.index.name   = "SDI trend"
    contingency.columns.name = "StDI trend"

    for _, row in results_df.iterrows():
        sdi_t  = row["mk_trend_sdi"]
        stdi_t = row["mk_trend_stdi"]
        if sdi_t in TREND_LABELS and stdi_t in TREND_LABELS:
            contingency.loc[sdi_t, stdi_t] += 1

    return contingency


def _select_case_studies(
    results_df: pd.DataFrame,
    contingency: pd.DataFrame,
) -> dict:
    """
    Selects one representative repo per sufficiently populated contingency
    cell (>= MIN_CELL_SIZE_FOR_CASE_STUDY repos).

    Selection criterion: strongest absolute Spearman rho with n_snapshots
    as tiebreaker. This ensures case studies cover the full observed
    diversity without presupposing a taxonomy.

    Returns a dict mapping "{sdi_trend} SDI / {stdi_trend} StDI" -> [repo_name].
    """
    selected = {}
    for sdi_t in TREND_LABELS:
        for stdi_t in TREND_LABELS:
            if contingency.loc[sdi_t, stdi_t] < MIN_CELL_SIZE_FOR_CASE_STUDY:
                continue
            candidates = results_df[
                (results_df["mk_trend_sdi"]  == sdi_t) &
                (results_df["mk_trend_stdi"] == stdi_t)
            ].copy()
            best = candidates.sort_values(
                by=["abs_spearman_rho", "n_snapshots"],
                ascending=False,
            ).head(CASE_STUDIES_PER_CELL)
            cell_label = f"{sdi_t} SDI / {stdi_t} StDI"
            selected[cell_label] = best["repo_name"].tolist()
            logger.info(f"  Case study [{cell_label}]: {selected[cell_label]}")
    return selected


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze_rq3_statistics() -> None:
    logger.info("=" * 60)
    logger.info("RQ3 — Evolutionary Analysis")
    logger.info("=" * 60)

    # 1. Validate inputs
    for path, label in [
        (INPUT_CSV,      "dataset_final.csv"),
        (RETAINED_CSV,   "retained_repos_after_trivy_filter.csv"),
        (IMPORTANCE_CSV, "rq2_feature_importance.csv"),
    ]:
        if not os.path.exists(path):
            logger.error(f"Required input not found: {path} ({label})")
            sys.exit(1)

    # 2. Load data
    df = _load_and_preprocess(INPUT_CSV, RETAINED_CSV)

    importance_df = pd.read_csv(IMPORTANCE_CSV)
    importance_df.columns = importance_df.columns.str.lower()
    weights = dict(zip(importance_df["feature"], importance_df["importance"]))
    logger.info(f"Loaded {len(weights)} feature weights from RQ2.")

    # 3. Per-repository analysis
    logger.info(f"Minimum snapshots required: {config.MIN_SNAPSHOTS_FOR_STATS}")

    per_repo_results = []
    skipped_too_few  = 0
    skipped_zero_sdi = 0

    for repo_name, group in df.groupby("repo_name"):
        group = group.reset_index(drop=True)

        if len(group) < config.MIN_SNAPSHOTS_FOR_STATS:
            skipped_too_few += 1
            continue

        sdi_series = group["security_debt_score"].values
        loc_series = group["loc"].values

        if sdi_series.max() == 0:
            skipped_zero_sdi += 1
            continue

        stdi_series = _compute_stdi(group, weights)

        mk_trend_sdi,  mk_p_sdi  = _mann_kendall(sdi_series)
        mk_trend_stdi, mk_p_stdi = _mann_kendall(stdi_series)

        if len(stdi_series) >= 3:
            corr, corr_p = spearmanr(stdi_series, sdi_series)
            if np.isnan(corr):
                corr, corr_p = 0.0, 1.0
        else:
            corr, corr_p = 0.0, 1.0

        cv_sdi = (sdi_series.std() / sdi_series.mean()
                  if sdi_series.mean() > 0 else 0.0)

        per_repo_results.append({
            "repo_name":        repo_name,
            "n_snapshots":      len(group),
            "loc_initial":      loc_series[0],
            "loc_final":        loc_series[-1],
            "sdi_initial":      sdi_series[0],
            "sdi_final":        sdi_series[-1],
            "sdi_mean":         sdi_series.mean(),
            "sdi_std":          sdi_series.std(),
            "sdi_cv":           cv_sdi,
            "stdi_mean":        stdi_series.mean(),
            "stdi_std":         stdi_series.std(),
            "mk_trend_sdi":     mk_trend_sdi,
            "mk_p_sdi":         mk_p_sdi,
            "mk_trend_stdi":    mk_trend_stdi,
            "mk_p_stdi":        mk_p_stdi,
            "spearman_rho":     corr,
            "spearman_p":       corr_p,
            "abs_spearman_rho": abs(corr),
        })

    logger.info(
        f"Repos analysed: {len(per_repo_results)} | "
        f"Skipped (too few snapshots): {skipped_too_few} | "
        f"Skipped (zero SDI): {skipped_zero_sdi}"
    )

    if not per_repo_results:
        logger.error("No valid repositories found for RQ3 analysis.")
        sys.exit(1)

    results_df = pd.DataFrame(per_repo_results)

    # 4. Save per-repo results
    per_repo_path = os.path.join(OUTPUT_DIR, "rq3_per_repo_results.csv")
    results_df.to_csv(per_repo_path, index=False)
    logger.info(f"Per-repo results saved to: {per_repo_path}")

    # 5. Contingency table SDI trend x StDI trend
    contingency = _build_contingency_table(results_df)
    contingency_path = os.path.join(OUTPUT_DIR, "rq3_trend_contingency.csv")
    contingency.to_csv(contingency_path)
    logger.info(f"Contingency table saved to: {contingency_path}")
    logger.info("Joint trend contingency table (SDI rows x StDI cols):\n"
                + contingency.to_string())

    # 6. Case study selection
    logger.info("Selecting case studies...")
    selected_cases = _select_case_studies(results_df, contingency)
    cases_path = os.path.join(OUTPUT_DIR, "selected_case_studies.json")
    with open(cases_path, "w") as fh:
        json.dump(selected_cases, fh, indent=4)
    logger.info(f"Case studies saved to: {cases_path}")

    # 7. Numerical summary for paper
    n_repos      = len(results_df)
    summary_path = os.path.join(OUTPUT_DIR, "rq3_numerical_summary.txt")

    with open(summary_path, "w") as fh:
        fh.write("=" * 60 + "\n")
        fh.write("RQ3 — EVOLUTIONARY ANALYSIS — NUMERICAL SUMMARY\n")
        fh.write("=" * 60 + "\n\n")

        fh.write(f"Repositories analysed : {n_repos}\n")
        fh.write(f"  Skipped (< {config.MIN_SNAPSHOTS_FOR_STATS} snapshots) : "
                 f"{skipped_too_few}\n")
        fh.write(f"  Skipped (zero SDI throughout) : {skipped_zero_sdi}\n\n")

        fh.write("--- Mann-Kendall SDI trend distribution ---\n")
        for trend in TREND_LABELS:
            count = (results_df["mk_trend_sdi"] == trend).sum()
            fh.write(f"  {trend}: {count} ({count/n_repos*100:.1f}%)\n")
        fh.write("\n")

        fh.write("--- Mann-Kendall StDI trend distribution ---\n")
        for trend in TREND_LABELS:
            count = (results_df["mk_trend_stdi"] == trend).sum()
            fh.write(f"  {trend}: {count} ({count/n_repos*100:.1f}%)\n")
        fh.write("\n")

        fh.write("--- Joint trend contingency table "
                 "(SDI rows x StDI cols, counts) ---\n")
        fh.write(contingency.to_string())
        fh.write("\n\n")

        concordant_inc     = int(contingency.loc["increasing",  "increasing"])
        concordant_dec     = int(contingency.loc["decreasing",  "decreasing"])
        concordant         = concordant_inc + concordant_dec
        discordant_id      = int(contingency.loc["increasing",  "decreasing"])
        discordant_di      = int(contingency.loc["decreasing",  "increasing"])
        discordant         = discordant_id + discordant_di

        fh.write(f"Concordant joint trends "
                 f"(both increasing or both decreasing): "
                 f"{concordant} ({concordant/n_repos*100:.1f}%)\n")
        fh.write(f"  Both increasing : {concordant_inc} "
                 f"({concordant_inc/n_repos*100:.1f}%)\n")
        fh.write(f"  Both decreasing : {concordant_dec} "
                 f"({concordant_dec/n_repos*100:.1f}%)\n")
        fh.write(f"Discordant joint trends : "
                 f"{discordant} ({discordant/n_repos*100:.1f}%)\n\n")

        fh.write("--- Longitudinal Spearman StDI-SDI correlation ---\n")
        fh.write(f"  Mean rho   : {results_df['spearman_rho'].mean():.3f}\n")
        fh.write(f"  Median rho : {results_df['spearman_rho'].median():.3f}\n")
        fh.write(f"  Std rho    : {results_df['spearman_rho'].std():.3f}\n")
        sig = (results_df["spearman_p"] < 0.05).sum()
        fh.write(f"  Significant (p < 0.05): {sig} "
                 f"({sig/n_repos*100:.1f}%)\n\n")

        fh.write("--- SDI variability ---\n")
        fh.write(f"  Mean CV(SDI): {results_df['sdi_cv'].mean():.3f}\n")
        fh.write(f"  Repos with CV(SDI) > 0.5: "
                 f"{(results_df['sdi_cv'] > 0.5).sum()} "
                 f"({(results_df['sdi_cv'] > 0.5).mean()*100:.1f}%)\n")

    logger.info(f"Numerical summary saved to: {summary_path}")
    logger.info("RQ3 analysis complete.")


if __name__ == "__main__":
    analyze_rq3_statistics()