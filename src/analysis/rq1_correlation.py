"""
rq1_correlation.py
==================
RQ1 — Association: Does a statistically significant correlation exist
between Structural Quality Debt (measured via individual structural
metrics) and Security Debt (SDI) in Terraform modules?

Analysis pipeline
-----------------
1. Load CSV and apply standard preprocessing filters:
   - analysis_mode == 'ANALYZED'  (unique code states only)
   - Trivy filter                 (repos where Trivy recognised .tf files)
   - loc > 0, security_debt_score not null

2. Compute Spearman rank correlations between each structural metric
   and SDI (absolute and density-normalised).

3. Apply Benjamini-Hochberg FDR correction for multiple comparisons.

4. Save full results table and a Spearman heatmap.

Notes
-----
- Density metrics (e.g. complexity_density) are computed here for the
  heatmap only. They are NOT used as independent predictors in the
  multivariate regression — that is handled in rq1_advanced_stats.py.
- StDI is NOT used here. It is defined in RQ2 via feature importances
  and used in RQ3 for longitudinal analysis.
- Bonferroni is deliberately NOT used: it is too conservative for
  exploratory correlation analysis. BH-FDR controls the expected
  proportion of false discoveries, which is appropriate here.
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import spearmanr
from statsmodels.stats.multitest import multipletests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INPUT_CSV     = os.path.join('data', 'output', 'dataset_final.csv')
RETAINED_CSV  = os.path.join('data', 'output',
                              'retained_repos_after_trivy_filter.csv')
OUTPUT_DIR    = os.path.join('data', 'output', 'figures', 'rq1')

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Structural metrics produced by the miner.
# These are the candidate independent variables for RQ1.
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

# Significance threshold AFTER BH-FDR correction
ALPHA = 0.05


# ---------------------------------------------------------------------------
# Data loading and preprocessing
# ---------------------------------------------------------------------------

def _load_csv(path: str) -> pd.DataFrame:
    """Loads the dataset with a fallback parser for malformed lines."""
    if not os.path.exists(path):
        print(f"ERROR: Dataset not found at {path}.")
        sys.exit(1)
    try:
        return pd.read_csv(path)
    except pd.errors.ParserError:
        print("WARNING: Standard CSV parser failed. Retrying with python engine.")
        return pd.read_csv(path, sep=',', on_bad_lines='skip', engine='python')


def _load_retained_repos(path: str) -> set:
    """
    Loads the set of repository names that passed the Trivy filter
    (produced by validate_sample.py Stage 3).

    If the file does not exist the function warns and returns None,
    which callers interpret as 'no filter applied'.
    """
    if not os.path.exists(path):
        print(
            f"WARNING: Trivy-filter file not found at {path}.\n"
            f"         Run validate_sample.py first to generate it.\n"
            f"         Proceeding WITHOUT Trivy filter — results may be\n"
            f"         affected by false-negative repositories."
        )
        return None
    retained = pd.read_csv(path)['repo_name'].tolist()
    return set(retained)


def load_and_filter(csv_path: str, retained_path: str) -> pd.DataFrame:
    """
    Loads the raw CSV and applies the three standard preprocessing filters
    shared across all RQ scripts:

        1. analysis_mode == 'ANALYZED'
           Keeps only snapshots where the miner detected a genuine code
           change — these are the unique code states.

        2. Trivy filter
           Keeps only repositories where Trivy recognised at least one
           Terraform target across the full history. Repos where
           trivy_terraform_targets == 0 for every snapshot are excluded
           because their SDI is a systematic false negative.

        3. loc > 0 and security_debt_score not null
           Basic sanity check.

    Returns the filtered DataFrame ready for analysis.
    """
    df = _load_csv(csv_path)

    n_raw = len(df)
    print(f"Raw rows loaded          : {n_raw}")

    # --- Filter 1: unique code states ---
    if 'analysis_mode' in df.columns:
        df = df[df['analysis_mode'] == 'ANALYZED'].copy()
        print(f"After analysis_mode filter: {len(df)} rows "
              f"({n_raw - len(df)} SKIPPED_DUPLICATE rows removed)")
    else:
        print("WARNING: 'analysis_mode' column not found. No deduplication applied.")

    # --- Filter 2: Trivy filter ---
    retained_repos = _load_retained_repos(retained_path)
    if retained_repos is not None:
        before = df['repo_name'].nunique()
        df = df[df['repo_name'].isin(retained_repos)].copy()
        after = df['repo_name'].nunique()
        print(f"After Trivy filter        : {after} repos "
              f"({before - after} excluded as Trivy false-negative repos)")

    # --- Filter 3: basic sanity ---
    for col in [TARGET, 'loc']:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    before = len(df)
    df = df.dropna(subset=[TARGET, 'loc'])
    df = df[df['loc'] > 0]
    print(f"After sanity filter       : {len(df)} rows "
          f"({before - len(df)} rows with null/zero LOC or null SDI removed)")

    print(f"\nFinal dataset: {len(df)} snapshots across "
          f"{df['repo_name'].nunique()} repositories.\n")

    return df


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

def engineer_features(df: pd.DataFrame) -> tuple[pd.DataFrame, list, list]:
    """
    Converts structural metric columns to numeric, computes density
    metrics, and returns the enriched DataFrame together with:
        - metrics_present : structural metrics present in the data
        - density_metrics : density metrics successfully computed
    """
    # Convert to numeric
    for col in STRUCTURAL_METRICS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    metrics_present = [m for m in STRUCTURAL_METRICS if m in df.columns]

    # Density metrics — used only for the heatmap, not as regression inputs
    density_metrics = []
    density_map = {
        'iac_mccabe_complexity': 'complexity_density',
        'hard_coded_values':     'hard_coded_density',
        'comment_lines':         'comment_density',
        'num_resources':         'resource_density',
    }
    for raw, density in density_map.items():
        if raw in df.columns:
            df[density] = df[raw] / df['loc']
            df[density] = df[density].replace([np.inf, -np.inf], np.nan).fillna(0)
            density_metrics.append(density)

    # SDI density
    df['sdi_density'] = df[TARGET] / df['loc']
    df['sdi_density'] = df['sdi_density'].replace([np.inf, -np.inf], np.nan).fillna(0)

    return df, metrics_present, density_metrics


# ---------------------------------------------------------------------------
# Spearman correlation with BH-FDR correction
# ---------------------------------------------------------------------------

def compute_correlations(
    df: pd.DataFrame,
    metrics: list,
) -> pd.DataFrame:
    """
    Computes Spearman rank correlations between each structural metric
    and SDI (both absolute and density-normalised).

    Multiple comparison correction is applied via the Benjamini-Hochberg
    False Discovery Rate procedure, which controls the expected proportion
    of false discoveries. This is more appropriate than Bonferroni for
    exploratory correlation studies.

    Returns a DataFrame with one row per (metric, target) pair.
    """
    rows = []

    targets = {
        'SDI (absolute)': TARGET,
        'SDI (density)':  'sdi_density',
    }

    for target_label, target_col in targets.items():
        for metric in metrics:
            # Drop rows where either variable is NaN for this pair
            pair = df[[metric, target_col]].dropna()
            if len(pair) < 10:
                continue

            rho, p = spearmanr(pair[metric], pair[target_col])
            rows.append({
                'target':  target_label,
                'metric':  metric,
                'rho':     round(rho, 4),
                'p_raw':   p,
                'n':       len(pair),
            })

    results = pd.DataFrame(rows)

    if results.empty:
        print("ERROR: No valid metric pairs found for correlation analysis.")
        return results

    # Apply BH-FDR correction separately for each target
    corrected_rows = []
    for target_label, group in results.groupby('target'):
        reject, p_corrected, _, _ = multipletests(
            group['p_raw'].values,
            alpha=ALPHA,
            method='fdr_bh',
        )
        group = group.copy()
        group['p_corrected'] = p_corrected
        group['significant'] = reject
        corrected_rows.append(group)

    results = pd.concat(corrected_rows, ignore_index=True)
    results['significant_label'] = results['significant'].map(
        {True: 'YES', False: 'NO'}
    )

    return results


def print_correlation_summary(results: pd.DataFrame) -> None:
    """Prints a readable summary of the correlation results."""
    for target_label in results['target'].unique():
        print(f"\n{'=' * 60}")
        print(f"  Target: {target_label}")
        print(f"{'=' * 60}")
        subset = (
            results[results['target'] == target_label]
            .sort_values('rho', key=abs, ascending=False)
        )
        print(
            subset[['metric', 'rho', 'p_raw', 'p_corrected', 'significant_label', 'n']]
            .rename(columns={
                'rho':               'Spearman ρ',
                'p_raw':             'p (raw)',
                'p_corrected':       'p (BH-FDR)',
                'significant_label': 'Significant',
                'n':                 'N',
            })
            .to_string(index=False)
        )

    n_sig = results['significant'].sum()
    n_total = len(results)
    print(f"\nSignificant after BH-FDR correction: {n_sig}/{n_total} "
          f"(α={ALPHA})\n")


# ---------------------------------------------------------------------------
# Visualisation
# ---------------------------------------------------------------------------

def plot_heatmap(
    df: pd.DataFrame,
    metrics: list,
    density_metrics: list,
    trivy_filtered: bool = True,
) -> None:
    """
    Saves a Spearman correlation heatmap across all structural metrics,
    density metrics, SDI absolute, and SDI density.
    """
    heatmap_cols = metrics + density_metrics + [TARGET, 'sdi_density']
    heatmap_cols = [c for c in heatmap_cols if c in df.columns]

    if len(heatmap_cols) < 2:
        print("Not enough columns to generate heatmap.")
        return

    corr_matrix = df[heatmap_cols].corr(method='spearman')

    fig, ax = plt.subplots(figsize=(16, 13))
    sns.heatmap(
        corr_matrix,
        annot=True,
        fmt='.2f',
        cmap='coolwarm',
        center=0,
        linewidths=0.5,
        annot_kws={'size': 9},
        ax=ax,
    )
    filter_label = "Trivy-filtered repos" if trivy_filtered else "all repos (no Trivy filter)"
    ax.set_title(
        f'RQ1 — Spearman Correlation Matrix\n'
        f'(ANALYZED snapshots, {filter_label})',
        fontsize=13,
        pad=12,
    )
    plt.tight_layout()

    path = os.path.join(OUTPUT_DIR, 'rq1_spearman_heatmap.png')
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"Heatmap saved to: {path}")


def plot_top_correlations(results: pd.DataFrame) -> None:
    """
    Saves a bar chart of the top 10 Spearman correlations with SDI
    (absolute), annotated by significance after BH-FDR correction.
    """
    subset = (
        results[results['target'] == 'SDI (absolute)']
        .sort_values('rho', key=abs, ascending=False)
        .head(10)
        .copy()
    )

    if subset.empty:
        return

    colours = subset['significant'].map({True: '#2166ac', False: '#d1d1d1'})

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(
        subset['metric'],
        subset['rho'],
        color=colours,
        edgecolor='k',
        linewidth=0.5,
    )

    ax.axvline(0, color='black', linewidth=0.8)
    ax.set_xlabel('Spearman ρ', fontsize=11)
    ax.set_title(
        'RQ1 — Top Correlations with Security Debt (absolute)\n'
        'Blue = significant after BH-FDR correction (α=0.05)',
        fontsize=12,
    )
    ax.invert_yaxis()
    plt.tight_layout()

    path = os.path.join(OUTPUT_DIR, 'rq1_top_correlations.png')
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"Top-correlations chart saved to: {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyze_rq1() -> None:
    print("=" * 60)
    print("RQ1 — ASSOCIATION ANALYSIS (Spearman + BH-FDR)")
    print("=" * 60)

    # 1. Load and filter
    df = load_and_filter(INPUT_CSV, RETAINED_CSV)

    # 2. Feature engineering
    df, metrics_present, density_metrics = engineer_features(df)

    if not metrics_present:
        print("ERROR: No structural metrics found in the dataset.")
        sys.exit(1)

    trivy_filtered = os.path.exists(RETAINED_CSV)
    print(f"Structural metrics available: {metrics_present}")
    print(f"Density metrics computed    : {density_metrics}\n")

    # 3. Spearman correlations with BH-FDR correction
    results = compute_correlations(df, metrics_present)

    if results.empty:
        sys.exit(1)

    print_correlation_summary(results)

    # 4. Save results
    results_path = os.path.join(OUTPUT_DIR, 'rq1_spearman_results.csv')
    results.to_csv(results_path, index=False)
    print(f"Full results saved to: {results_path}")

    # 5. Visualisations
    plot_heatmap(df, metrics_present, density_metrics, trivy_filtered=trivy_filtered)
    plot_top_correlations(results)

    print("\nRQ1 correlation analysis complete.")


if __name__ == "__main__":
    analyze_rq1()