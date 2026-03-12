"""
validate_sample.py
==================
Three-stage statistical validation of the repository sample used in the study.

Stage 1 — Theoretical validation
    Confirms that the *intended* sample (500 repositories drawn with
    random_state=42 from the TerraDS population) is statistically
    representative of the full population via two-sample KS tests on
    four variables: StarCount, SizeInKb, ForkCount, LatestCommitAt.
    This is the standard pre-mining check.

Stage 2 — Empirical validation (post-dropout)
    Confirms that the *actually analysed* repositories (those present in
    the final CSV after cloning failures, timeouts, and empty-LOC
    discards) are still statistically representative of the population.
    This is the stronger, post-hoc claim that reviewers may ask for.

Stage 3 — Post-Trivy-filter validation
    Validates the sample after excluding repositories for which Trivy
    never identified any Terraform-specific targets across their entire
    ANALYZED history (trivy_terraform_targets == 0 for all snapshots).
    This is the sample actually used for RQ1-RQ4 analysis.

All stages use FullName (owner/repo) for matching instead of Name alone,
to avoid false duplicates from repositories with identical short names
owned by different GitHub users.

Each stage produces:
    * KS statistic and p-value printed to stdout for each metric.
    * An overlaid KDE plot saved to DATA_OUTPUT_DIR.
"""

import os
import sys
import sqlite3

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import ks_2samp

# ---------------------------------------------------------------------------
# Configuration bootstrap
# ---------------------------------------------------------------------------
sys.path.append(os.getcwd())

try:
    from src import config

    if not os.path.exists(config.DB_PATH):
        local_db = os.path.join('data', 'input', 'TerraDS.sqlite')
        if os.path.exists(local_db):
            config.DB_PATH = local_db

    DB_PATH     = config.DB_PATH
    OUTPUT_CSV  = config.OUTPUT_CSV_PATH
    OUTPUT_DIR  = config.DATA_OUTPUT_DIR
    MIN_STARS   = config.MIN_STARS
    REPO_LIMIT  = config.REPO_LIMIT
    RANDOM_SEED = 42

except ImportError:
    DB_PATH     = os.path.join('data', 'input', 'TerraDS.sqlite')
    OUTPUT_CSV  = os.path.join('data', 'output', 'dataset_final.csv')
    OUTPUT_DIR  = os.path.join('data', 'output', 'figures')
    MIN_STARS   = 10
    REPO_LIMIT  = 500
    RANDOM_SEED = 42

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Metrics to validate and their human-readable labels.
#
# Four variables are used to maximise confidence in representativeness:
#   StarCount     — proxy for project relevance and community adoption
#   SizeInKb      — proxy for project complexity and scope
#   ForkCount     — proxy for project maturity and contributor base;
#                   projects with more forks tend to have more rigorous
#                   engineering practices, which could bias SDI/StDI
#   LatestCommitAt — proxy for project activity; an imbalanced sample
#                   of abandoned vs active projects would distort the
#                   longitudinal analysis in RQ3
#
# LatestCommitAt is converted to a Unix timestamp (days since epoch) so
# that the KS test operates on a continuous numeric distribution.
# ---------------------------------------------------------------------------
METRICS = {
    'StarCount':          'Popularity (Stars)',
    'SizeInKb':           'Size (KB)',
    'ForkCount':          'Fork Count',
    'LatestCommitAt_days':'Recent Activity (Days since epoch)',
}

PLOT_COLOURS = {
    'StarCount':           ('grey', 'blue'),
    'SizeInKb':            ('grey', 'red'),
    'ForkCount':           ('grey', 'green'),
    'LatestCommitAt_days': ('grey', 'orange'),
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _load_population(conn: sqlite3.Connection) -> pd.DataFrame:
    """
    Loads the full relevant population from TerraDS.

    LatestCommitAt is converted to a numeric representation (days since
    Unix epoch) so it can be used in the KS test and KDE plots.
    """
    query = f"""
        SELECT Name, FullName, StarCount, SizeInKb, ForkCount, LatestCommitAt
        FROM   Repositories
        WHERE  StarCount >= {MIN_STARS}
    """
    df = pd.read_sql_query(query, conn)

    df['LatestCommitAt'] = pd.to_datetime(df['LatestCommitAt'], errors='coerce', utc=True)
    epoch = pd.Timestamp('1970-01-01', tz='UTC')
    df['LatestCommitAt_days'] = (df['LatestCommitAt'] - epoch).dt.days
    df['LatestCommitAt_days'] = df['LatestCommitAt_days'].fillna(0).clip(lower=0)

    return df


def _extract_full_name(git_url: pd.Series) -> pd.Series:
    """
    Extracts owner/repo from a GitHub URL.
    e.g. https://github.com/owner/repo.git -> owner/repo
    """
    return git_url.str.extract(r'github\.com/(.+?)(?:\.git)?$')[0]


def _run_ks_test(
    pop_series: pd.Series,
    sample_series: pd.Series,
    label: str,
) -> tuple:
    """
    Runs a two-sample KS test after removing zeros and NaNs.
    Returns (statistic, p_value).
    """
    pop    = pop_series.dropna()
    pop    = pop[pop > 0]
    sample = sample_series.dropna()
    sample = sample[sample > 0]

    stat, p_value = ks_2samp(pop, sample)
    verdict = "VALIDATED" if p_value > 0.05 else "NOTE: Different distribution"

    print(f"\n  Metric  : {label}")
    print(f"  KS stat : {stat:.4f}")
    print(f"  p-value : {p_value:.4f}")
    print(f"  Result  : {verdict}")

    return stat, p_value


def _kde_subplot(
    ax: plt.Axes,
    pop_series: pd.Series,
    sample_series: pd.Series,
    label: str,
    sample_label: str,
    colours: tuple,
) -> None:
    """Draws an overlaid KDE plot (log scale) on the given axes."""
    pop_colour, sample_colour = colours

    pop    = pop_series.dropna()
    pop    = pop[pop > 0]
    sample = sample_series.dropna()
    sample = sample[sample > 0]

    sns.kdeplot(pop,    fill=True, color=pop_colour,    label='Population',
                log_scale=True, ax=ax)
    sns.kdeplot(sample, fill=True, color=sample_colour, label=sample_label,
                alpha=0.5, log_scale=True, ax=ax)

    ax.set_title(f'{label} Distribution')
    ax.set_xlabel(f'{label} (Log Scale)')
    ax.legend()


def _save_plot(fig: plt.Figure, filename: str) -> None:
    path = os.path.join(OUTPUT_DIR, filename)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  Plot saved to: {path}")


def _run_stage(
    stage_name: str,
    df_pop: pd.DataFrame,
    df_sample_meta: pd.DataFrame,
    plot_filename: str,
    plot_title: str,
) -> None:
    """
    Shared logic for running KS tests and generating KDE plots for a stage.
    df_sample_meta must already be matched to df_pop (inner join on FullName).
    """
    n = len(df_sample_meta)
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(plot_title, fontsize=13)
    axes = axes.flatten()

    all_validated = True
    for ax, (metric, label) in zip(axes, METRICS.items()):
        stat, p = _run_ks_test(df_pop[metric], df_sample_meta[metric], label)
        if p <= 0.05:
            all_validated = False
        _kde_subplot(
            ax,
            df_pop[metric],
            df_sample_meta[metric],
            label,
            sample_label=f'Sample (n={n})',
            colours=PLOT_COLOURS[metric],
        )

    overall = "ALL METRICS VALIDATED" if all_validated else "WARNING: Some metrics differ"
    print(f"\n  Overall result: {overall}")
    _save_plot(fig, plot_filename)


# ---------------------------------------------------------------------------
# Stage 1 — Theoretical validation
# ---------------------------------------------------------------------------

def validate_theoretical(df_pop: pd.DataFrame) -> None:
    """
    Validates the intended sample against the full population.
    Simulates the same random draw used by terrads_loader (random_state=42).
    """
    print("\n" + "=" * 60)
    print("STAGE 1 — THEORETICAL SAMPLE VALIDATION")
    print("=" * 60)
    print(f"  Population size : {len(df_pop)}")

    df_sample = df_pop.sample(n=min(REPO_LIMIT, len(df_pop)), random_state=RANDOM_SEED)
    print(f"  Sample size     : {len(df_sample)}")

    _run_stage(
        stage_name     = "Stage 1",
        df_pop         = df_pop,
        df_sample_meta = df_sample,
        plot_filename  = "stage1_theoretical_validation.png",
        plot_title     = f"Stage 1 — Theoretical Sample (n={len(df_sample)}) vs Population",
    )


# ---------------------------------------------------------------------------
# Stage 2 — Empirical (post-dropout) validation
# ---------------------------------------------------------------------------

def validate_empirical(df_pop: pd.DataFrame) -> None:
    """
    Validates the actually analysed repositories against the full population.

    Uses FullName (owner/repo extracted from git_url) for matching to avoid
    false duplicates from repositories with identical short names.
    """
    print("\n" + "=" * 60)
    print("STAGE 2 — EMPIRICAL (POST-DROPOUT) VALIDATION")
    print("=" * 60)

    if not os.path.exists(OUTPUT_CSV):
        print(f"  WARNING: Final CSV not found at {OUTPUT_CSV}. Skipping.")
        return

    try:
        df_results = pd.read_csv(OUTPUT_CSV, usecols=['repo_name', 'git_url'])
    except Exception as e:
        print(f"  ERROR reading CSV: {e}. Skipping Stage 2.")
        return

    # Extract FullName from git_url for accurate matching
    df_results['full_name'] = _extract_full_name(df_results['git_url'])
    analysed_fullnames = set(df_results['full_name'].dropna().unique())
    n_analysed = df_results['repo_name'].nunique()

    print(f"  Repositories in final CSV : {n_analysed}")

    df_empirical = (
        df_pop[df_pop['FullName'].isin(analysed_fullnames)]
        .drop_duplicates(subset='FullName')
        .copy()
    )
    n_matched = len(df_empirical)
    print(f"  Matched in population DB  : {n_matched}")

    if n_matched == 0:
        print("  ERROR: No overlap between CSV FullNames and TerraDS. Skipping.")
        return

    dropout_pct = 100 * (1 - n_matched / min(REPO_LIMIT, len(df_pop)))
    print(f"  Effective dropout rate    : {dropout_pct:.1f}%")

    _run_stage(
        stage_name     = "Stage 2",
        df_pop         = df_pop,
        df_sample_meta = df_empirical,
        plot_filename  = "stage2_empirical_validation.png",
        plot_title     = (
            f"Stage 2 — Empirical Sample (n={n_matched}, "
            f"dropout={dropout_pct:.1f}%) vs Population"
        ),
    )


# ---------------------------------------------------------------------------
# Stage 3 — Post-Trivy-filter validation
# ---------------------------------------------------------------------------

def validate_post_filter(df_pop: pd.DataFrame) -> None:
    """
    Validates the sample after excluding repositories for which Trivy never
    identified any Terraform-specific targets across their entire ANALYZED
    history (trivy_terraform_targets == 0 for all snapshots).

    Uses FullName matching for consistency with Stage 2.
    """
    print("\n" + "=" * 60)
    print("STAGE 3 — POST-TRIVY-FILTER VALIDATION")
    print("=" * 60)

    if not os.path.exists(OUTPUT_CSV):
        print(f"  WARNING: Final CSV not found at {OUTPUT_CSV}. Skipping.")
        return

    try:
        df = pd.read_csv(OUTPUT_CSV)
    except Exception as e:
        print(f"  ERROR reading CSV: {e}. Skipping Stage 3.")
        return

    if 'trivy_terraform_targets' not in df.columns:
        print(
            "  WARNING: Column 'trivy_terraform_targets' not found.\n"
            "  Re-run mining with the updated security_model.py."
        )
        return

    df_a = df[df['analysis_mode'] == 'ANALYZED'].copy()
    df_a['trivy_terraform_targets'] = pd.to_numeric(
        df_a['trivy_terraform_targets'], errors='coerce'
    ).fillna(0)

    total_repos = df_a['repo_name'].nunique()
    print(f"  Repos in CSV (ANALYZED snapshots): {total_repos}")

    repo_max_targets = df_a.groupby('repo_name')['trivy_terraform_targets'].max()
    excluded_repos   = set(repo_max_targets[repo_max_targets == 0].index)
    retained_repos   = set(repo_max_targets[repo_max_targets > 0].index)

    n_excluded = len(excluded_repos)
    n_retained = len(retained_repos)

    print(f"  Repos excluded (trivy_terraform_targets == 0 always): "
          f"{n_excluded} ({100*n_excluded/total_repos:.1f}%)")
    print(f"  Repos retained for RQ analysis: "
          f"{n_retained} ({100*n_retained/total_repos:.1f}%)")

    if n_retained == 0:
        print("  ERROR: No repos retained after Trivy filter.")
        return

    # Cochran minimum sample size check
    Z, p_prop, e = 1.96, 0.5, 0.05
    n_cochran  = (Z**2 * p_prop * (1 - p_prop)) / (e**2)
    N          = len(df_pop)
    n_adjusted = n_cochran / (1 + (n_cochran - 1) / N)
    verdict    = "ABOVE minimum" if n_retained >= n_adjusted else "BELOW minimum"
    print(f"  Cochran minimum (N={N}, 95% CI, 5% margin): {n_adjusted:.0f}")
    print(f"  Retained sample ({n_retained}): {verdict}")

    # Match using FullName extracted from git_url
    df_retained_urls = df[df['repo_name'].isin(retained_repos)][['repo_name','git_url']].drop_duplicates()
    df_retained_urls['full_name'] = _extract_full_name(df_retained_urls['git_url'])
    retained_fullnames = set(df_retained_urls['full_name'].dropna().unique())

    df_retained_meta = (
        df_pop[df_pop['FullName'].isin(retained_fullnames)]
        .drop_duplicates(subset='FullName')
        .copy()
    )
    n_matched = len(df_retained_meta)
    print(f"  Matched in population DB: {n_matched}")

    if n_matched == 0:
        print("  ERROR: No overlap between retained repos and TerraDS. Skipping.")
        return

    _run_stage(
        stage_name     = "Stage 3",
        df_pop         = df_pop,
        df_sample_meta = df_retained_meta,
        plot_filename  = "stage3_post_trivy_filter_validation.png",
        plot_title     = (
            f"Stage 3 — Post-Trivy-Filter Sample "
            f"(n={n_matched}, excluded={n_excluded}) vs Population"
        ),
    )

    # Save retained repo list for RQ scripts
    retained_path = os.path.join(OUTPUT_DIR, 'retained_repos_after_trivy_filter.csv')
    pd.DataFrame({'repo_name': sorted(retained_repos)}).to_csv(retained_path, index=False)
    print(f"  Retained repo list saved to: {retained_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 60)
    print("SAMPLE REPRESENTATIVENESS VALIDATION")
    print("=" * 60)
    print(f"  Database   : {DB_PATH}")
    print(f"  Output CSV : {OUTPUT_CSV}")
    print(f"  Min stars  : {MIN_STARS}")
    print(f"  Repo limit : {REPO_LIMIT}")

    if not os.path.exists(DB_PATH):
        print(f"\nERROR: Database not found at {DB_PATH}.")
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        df_pop = _load_population(conn)
    except Exception as e:
        print(f"ERROR loading population: {e}")
        conn.close()
        return
    conn.close()

    if df_pop.empty:
        print("ERROR: Population query returned no rows.")
        return

    print(f"\n  Full population size: {len(df_pop)}")

    validate_theoretical(df_pop)
    validate_empirical(df_pop)
    validate_post_filter(df_pop)

    print("\n" + "=" * 60)
    print("VALIDATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()