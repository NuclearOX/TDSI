"""
rq1_advanced_stats.py
=====================
RQ1 — Association (multivariate component): Which structural metrics
are independent predictors of Security Debt (SDI) when controlling
for the others, and how severe is multicollinearity?

Analysis pipeline
-----------------
1. Load and preprocess (same filters as rq1_correlation.py):
   - analysis_mode == 'ANALYZED'
   - Trivy filter
   - loc > 0, security_debt_score not null

2. Variance Inflation Factor (VIF) analysis
   Detects multicollinearity among structural metrics.
   Metrics with VIF > 10 are removed iteratively until all
   remaining metrics have VIF <= 10.

3. OLS multiple linear regression
   On z-score normalised predictors (required for coefficient
   comparability across metrics with different scales).
   Dependent variable: security_debt_score (raw, not log-transformed —
   log transform is appropriate for prediction in RQ2, but here we want
   interpretable coefficients on the original scale).

4. RLM validation (Huber-T robust estimator)
   Confirms OLS findings in the presence of outliers, which are
   expected in SDI distributions (many zeros, few very high values).

5. Coefficient comparison table (OLS vs RLM).

Notes
-----
- z-score normalisation is applied AFTER VIF-based feature selection,
  so VIF is computed on the raw (but numerically cleaned) predictors.
- The constant term is included in both OLS and RLM.
- This script does NOT produce StDI — that is defined in RQ2.
- Results from this script (specifically: which metrics survive VIF
  selection) inform the feature set used in rq2_prediction.py.
"""

import os
import sys
import numpy as np
import pandas as pd
from scipy.stats import zscore
import statsmodels.api as sm
from statsmodels.stats.outliers_influence import variance_inflation_factor

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INPUT_CSV    = os.path.join('data', 'output', 'dataset_final.csv')
RETAINED_CSV = os.path.join('data', 'output', 'retained_repos_after_trivy_filter.csv')
OUTPUT_DIR   = os.path.join('data', 'output', 'figures', 'rq1')

os.makedirs(OUTPUT_DIR, exist_ok=True)

STRUCTURAL_METRICS = [
    'loc',
    'num_resources',
    'num_modules',
    'num_variables',
    'num_outputs',
    'num_providers',
    'iac_mccabe_complexity',
    'hard_coded_values',
    'comment_lines',
    'internal_references',
]

TARGET = 'security_debt_score'

# VIF threshold: 10 is the standard conservative cutoff.
# Values between 5-10 indicate moderate collinearity; above 10 is severe.
VIF_THRESHOLD = 10


# ---------------------------------------------------------------------------
# Data loading and preprocessing
# (mirrors rq1_correlation.py — kept explicit to make each script
#  self-contained and runnable independently)
# ---------------------------------------------------------------------------

def _load_csv(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        print(f"ERROR: Dataset not found at {path}.")
        sys.exit(1)
    try:
        return pd.read_csv(path)
    except pd.errors.ParserError:
        print("WARNING: Standard CSV parser failed. Retrying with python engine.")
        return pd.read_csv(path, sep=',', on_bad_lines='skip', engine='python')


def _load_retained_repos(path: str):
    if not os.path.exists(path):
        print(
            f"WARNING: Trivy-filter file not found at {path}.\n"
            f"         Run validate_sample.py first to generate it.\n"
            f"         Proceeding WITHOUT Trivy filter — results may be\n"
            f"         affected by false-negative repositories."
        )
        return None
    return set(pd.read_csv(path)['repo_name'].tolist())


def load_and_filter(csv_path: str, retained_path: str) -> pd.DataFrame:
    df = _load_csv(csv_path)
    n_raw = len(df)
    print(f"Raw rows loaded            : {n_raw}")

    # Filter 1: unique code states
    if 'analysis_mode' in df.columns:
        df = df[df['analysis_mode'] == 'ANALYZED'].copy()
        print(f"After analysis_mode filter : {len(df)} rows")
    else:
        print("WARNING: 'analysis_mode' column not found. No deduplication applied.")

    # Filter 2: Trivy filter
    retained_repos = _load_retained_repos(retained_path)
    if retained_repos is not None:
        before = df['repo_name'].nunique()
        df = df[df['repo_name'].isin(retained_repos)].copy()
        after = df['repo_name'].nunique()
        print(f"After Trivy filter         : {after} repos "
              f"({before - after} excluded)")

    # Filter 3: basic sanity
    for col in [TARGET, 'loc']:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    before = len(df)
    df = df.dropna(subset=[TARGET, 'loc'])
    df = df[df['loc'] > 0]
    print(f"After sanity filter        : {len(df)} rows "
          f"({before - len(df)} removed)")

    print(f"\nFinal dataset: {len(df)} snapshots across "
          f"{df['repo_name'].nunique()} repositories.\n")
    return df


# ---------------------------------------------------------------------------
# Predictor preparation
# ---------------------------------------------------------------------------

def prepare_predictors(df: pd.DataFrame) -> tuple[pd.DataFrame, list]:
    """
    Converts structural metrics to numeric, removes zero-variance columns,
    and returns the cleaned predictor DataFrame and the list of valid
    predictor names.

    Zero-variance columns (e.g. num_outputs == 0 for every snapshot)
    break both VIF computation and OLS fitting and must be removed first.
    """
    metrics_present = [m for m in STRUCTURAL_METRICS if m in df.columns]
    for col in metrics_present:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df = df.fillna(0)

    # Remove zero-variance predictors
    X = df[metrics_present]
    zero_var = X.columns[X.var() == 0].tolist()
    if zero_var:
        print(f"Removed zero-variance predictors: {zero_var}")
        metrics_present = [m for m in metrics_present if m not in zero_var]

    return df, metrics_present


# ---------------------------------------------------------------------------
# VIF-based feature selection
# ---------------------------------------------------------------------------

def iterative_vif_selection(
    df: pd.DataFrame,
    predictors: list,
    threshold: float = VIF_THRESHOLD,
) -> list:
    """
    Iteratively removes the predictor with the highest VIF until all
    remaining predictors have VIF <= threshold.

    VIF is computed on raw (unnormalised) values because z-score
    normalisation does not affect VIF — it is a function of R² from
    regressing each predictor on the others, which is scale-invariant.

    Returns the list of predictors that survive selection.
    """
    print(f"\n{'=' * 60}")
    print(f"  VIF-BASED FEATURE SELECTION (threshold = {threshold})")
    print(f"{'=' * 60}")

    remaining = predictors.copy()

    iteration = 0
    while True:
        iteration += 1
        X = sm.add_constant(df[remaining].values)
        vif_values = [
            variance_inflation_factor(X, i)
            for i in range(X.shape[1])
        ]
        # Index 0 is the constant — skip it
        vif_series = pd.Series(vif_values[1:], index=remaining)

        print(f"\nIteration {iteration}:")
        print(vif_series.sort_values(ascending=False).round(2).to_string())

        max_vif = vif_series.max()
        if max_vif <= threshold:
            print(f"\nAll remaining predictors have VIF <= {threshold}. "
                  f"Selection complete.")
            break

        worst = vif_series.idxmax()
        print(f"\n  → Removing '{worst}' (VIF = {max_vif:.2f})")
        remaining.remove(worst)

        if len(remaining) < 2:
            print("WARNING: Fewer than 2 predictors remain. Stopping selection.")
            break

    print(f"\nFinal predictor set ({len(remaining)}): {remaining}")
    return remaining


def print_final_vif(df: pd.DataFrame, predictors: list) -> None:
    """Prints and saves the final VIF table after selection."""
    X = sm.add_constant(df[predictors].values)
    vif_values = [variance_inflation_factor(X, i) for i in range(X.shape[1])]
    vif_df = pd.DataFrame({
        'Predictor': ['const'] + predictors,
        'VIF':       [round(v, 4) for v in vif_values],
    })

    print(f"\n{'=' * 60}")
    print("  FINAL VIF TABLE (after selection)")
    print(f"{'=' * 60}")
    print(vif_df.to_string(index=False))

    path = os.path.join(OUTPUT_DIR, 'rq1_vif_final.csv')
    vif_df.to_csv(path, index=False)
    print(f"\nVIF table saved to: {path}")


# ---------------------------------------------------------------------------
# OLS regression
# ---------------------------------------------------------------------------

def run_ols(
    df: pd.DataFrame,
    predictors: list,
) -> sm.regression.linear_model.RegressionResultsWrapper | None:
    """
    Fits an OLS model on z-score normalised predictors.

    Z-score normalisation is applied here (after VIF selection) so that
    OLS coefficients are directly comparable in magnitude across metrics
    with different scales.  The dependent variable (SDI) is kept on its
    original scale to produce interpretable coefficients.
    """
    print(f"\n{'=' * 60}")
    print("  OLS MULTIPLE LINEAR REGRESSION")
    print(f"{'=' * 60}")
    print("  (Predictors z-score normalised for coefficient comparability)")

    y = df[TARGET]

    # Apply z-score normalisation to predictors only
    try:
        X_norm = df[predictors].apply(zscore)
    except Exception as e:
        print(f"ERROR during z-score normalisation: {e}")
        return None

    X_norm = sm.add_constant(X_norm)

    try:
        model = sm.OLS(y, X_norm).fit()
    except Exception as e:
        print(f"ERROR fitting OLS model: {e}")
        return None

    print(model.summary())

    # Save summary
    path = os.path.join(OUTPUT_DIR, 'rq1_ols_summary.txt')
    with open(path, 'w') as fh:
        fh.write(model.summary().as_text())
    print(f"\nOLS summary saved to: {path}")

    # Print significant predictors
    print(f"\nStatistically significant predictors (p < 0.05):")
    sig = model.pvalues[model.pvalues < 0.05].drop('const', errors='ignore')
    if sig.empty:
        print("  None.")
    else:
        for pred, pval in sig.items():
            coef = model.params[pred]
            direction = "↑ increases" if coef > 0 else "↓ decreases"
            print(f"  {pred}: {direction} SDI  (coef={coef:.4f}, p={pval:.4f})")

    return model


# ---------------------------------------------------------------------------
# RLM validation
# ---------------------------------------------------------------------------

def run_rlm(
    df: pd.DataFrame,
    predictors: list,
    ols_model,
) -> None:
    """
    Fits a Robust Linear Model (Huber-T estimator) on the same
    z-score normalised predictors as OLS.

    RLM downweights outliers automatically, which is important here
    because SDI distributions typically have heavy right tails
    (many repos with zero debt, a few with very high debt).

    If OLS and RLM coefficients agree in sign and approximate magnitude,
    the OLS findings are robust to outlier influence.
    """
    print(f"\n{'=' * 60}")
    print("  RLM VALIDATION (Huber-T robust estimator)")
    print(f"{'=' * 60}")

    y = df[TARGET]

    try:
        X_norm = df[predictors].apply(zscore)
    except Exception as e:
        print(f"ERROR during z-score normalisation for RLM: {e}")
        return

    X_norm = sm.add_constant(X_norm)

    try:
        rlm_model = sm.RLM(y, X_norm, M=sm.robust.norms.HuberT()).fit()
    except Exception as e:
        print(f"ERROR fitting RLM model: {e}")
        return

    print(rlm_model.summary())

    path = os.path.join(OUTPUT_DIR, 'rq1_rlm_summary.txt')
    with open(path, 'w') as fh:
        fh.write(rlm_model.summary().as_text())
    print(f"\nRLM summary saved to: {path}")

    # Coefficient comparison table
    if ols_model is not None:
        print(f"\n{'=' * 60}")
        print("  OLS vs RLM COEFFICIENT COMPARISON")
        print(f"{'=' * 60}")
        print("  Large differences in sign or magnitude indicate that")
        print("  OLS coefficients are driven by outliers.\n")

        comparison = pd.DataFrame({
            'OLS coef':   ols_model.params,
            'OLS p':      ols_model.pvalues,
            'RLM coef':   rlm_model.params,
            'RLM p':      rlm_model.pvalues,
        }).round(4)

        # Flag disagreements in sign
        comparison['sign_agrees'] = (
            np.sign(comparison['OLS coef']) == np.sign(comparison['RLM coef'])
        )

        print(comparison.to_string())

        path = os.path.join(OUTPUT_DIR, 'rq1_ols_vs_rlm.csv')
        comparison.to_csv(path)
        print(f"\nComparison table saved to: {path}")

        n_disagree = (~comparison['sign_agrees']).sum()
        if n_disagree > 0:
            print(f"\nWARNING: {n_disagree} predictor(s) have opposite signs "
                  f"in OLS vs RLM — those findings should be interpreted with caution.")
        else:
            print("\nAll predictors agree in sign between OLS and RLM. "
                  "OLS findings are robust to outlier influence.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyze_advanced_rq1() -> None:
    print("=" * 60)
    print("RQ1 — MULTIVARIATE ANALYSIS (VIF + OLS + RLM)")
    print("=" * 60)

    # 1. Load and filter
    df = load_and_filter(INPUT_CSV, RETAINED_CSV)

    # 2. Prepare predictors
    df, predictors = prepare_predictors(df)

    if len(predictors) < 2:
        print("ERROR: Fewer than 2 valid predictors found. Cannot proceed.")
        sys.exit(1)

    print(f"Candidate predictors ({len(predictors)}): {predictors}")
    print(f"Observations for regression: {len(df)}")

    # 3. VIF-based feature selection
    selected_predictors = iterative_vif_selection(df, predictors)
    print_final_vif(df, selected_predictors)

    if len(selected_predictors) < 1:
        print("ERROR: No predictors survived VIF selection.")
        sys.exit(1)

    # 4. OLS regression
    ols_model = run_ols(df, selected_predictors)

    # 5. RLM validation
    run_rlm(df, selected_predictors, ols_model)

    print("\nRQ1 multivariate analysis complete.")


if __name__ == "__main__":
    analyze_advanced_rq1()