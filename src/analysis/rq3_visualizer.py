"""
rq3_visualization.py — RQ3 Case Study Plots
============================================
Research Question:
    How do structural debt (StDI) and security debt (SDI) co-evolve during
    the entire lifecycle of an IaC project, and what is the prevalence of
    joint monotonic trends observable in the analysed population?

Pipeline position:
    Requires:
        - data/output/dataset_final.csv
        - data/output/retained_repos_after_trivy_filter.csv
        - data/output/figures/rq2/rq2_feature_importance.csv
        - data/output/figures/rq3/selected_case_studies.json  (rq3_statistics.py)
        - data/output/figures/rq3/rq3_trend_contingency.csv   (rq3_statistics.py)
    Produces (per selected repo, inside data/output/figures/rq3/):
        - <cell>_<repo>_evolution.png    LOC vs Security Debt over time
        - <cell>_<repo>_composition.png  Stacked debt composition over time
        - <cell>_<repo>_covariance.png   StDI vs SDI co-evolution
    Also produces:
        - rq3_contingency_heatmap.png    Heatmap of the 3x3 contingency table

StDI computation:
    Identical to rq3_statistics.py — intra-project z-score normalisation
    weighted by RQ2 feature importances.

Preprocessing:
    Identical to all other RQ scripts:
        1. analysis_mode == 'ANALYZED'
        2. Trivy filter
        3. loc > 0 and security_debt_score not null
"""

import json
import logging
import os
import sys
import warnings

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
import pandas as pd
import seaborn as sns

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
CASES_JSON     = os.path.join(config.DATA_OUTPUT_DIR, "figures", "rq3",
                               "selected_case_studies.json")
CONTINGENCY_CSV = os.path.join(config.DATA_OUTPUT_DIR, "figures", "rq3",
                                "rq3_trend_contingency.csv")
OUTPUT_DIR     = os.path.join(config.DATA_OUTPUT_DIR, "figures", "rq3")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Plot style
# ---------------------------------------------------------------------------
plt.rcParams.update({
    "figure.dpi":        150,
    "font.size":         11,
    "axes.titlesize":    13,
    "axes.labelsize":    11,
    "legend.fontsize":   10,
    "axes.grid":         True,
    "grid.alpha":        0.25,
    "axes.spines.top":   False,
    "axes.spines.right": False,
})

COLOR_SDI   = "#d62728"   # red    — security debt
COLOR_LOC   = "#4878d0"   # blue   — lines of code
COLOR_STDI  = "#9467bd"   # purple — structural debt index
COLOR_INFRA = "#ff9999"
COLOR_DEP   = "#66b3ff"
COLOR_SEC   = "#99ff99"

TREND_LABELS = ["increasing", "no trend", "decreasing"]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _load_and_preprocess(input_csv: str, retained_csv: str) -> pd.DataFrame:
    """Standard three-step preprocessing (consistent with all RQ scripts)."""
    logger.info("Loading dataset...")
    df = pd.read_csv(input_csv, low_memory=False)

    df = df[df["analysis_mode"] == "ANALYZED"].copy()

    retained = pd.read_csv(retained_csv)["repo_name"].unique()
    df = df[df["repo_name"].isin(retained)].copy()

    df["loc"] = pd.to_numeric(df["loc"], errors="coerce")
    df["security_debt_score"] = pd.to_numeric(
        df["security_debt_score"], errors="coerce"
    )
    df = df[(df["loc"] > 0) & df["security_debt_score"].notna()].copy()

    df["author_date"] = pd.to_datetime(
        df["author_date"], errors="coerce", utc=True
    )
    df = df.dropna(subset=["author_date"])
    df = df.sort_values(["repo_name", "author_date"]).reset_index(drop=True)

    for col in ["infrastructure_debt", "dependency_debt", "secret_debt"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    logger.info(f"  Loaded {len(df):,} rows across "
                f"{df['repo_name'].nunique()} repos.")
    return df


def _compute_stdi(group: pd.DataFrame, weights: dict) -> np.ndarray:
    """
    Intra-project z-score StDI — identical to rq3_statistics.py.
    Guarantees consistency between plotted values and statistics.
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


def _safe_name(text: str) -> str:
    """Strips non-alphanumeric characters for use in filenames."""
    return "".join(c if c.isalnum() else "_" for c in text).strip("_")


def _format_axes_dates(ax, date_series: pd.Series = None) -> None:
    """
    Applies a readable, non-duplicating date format to the x-axis.
    Adapts tick granularity to the actual temporal span of the data:
        < 60 days  → daily ticks  (%Y-%m-%d)
        < 180 days → weekly ticks (%Y-%m-%d)
        otherwise  → monthly/auto (%Y-%m), min 4 ticks
    """
    if date_series is not None and len(date_series) >= 2:
        span_days = (date_series.max() - date_series.min()).days
    else:
        span_days = 999  # fallback: use auto

    if span_days < 60:
        ax.xaxis.set_major_locator(mdates.DayLocator(interval=max(1, span_days // 6)))
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
    elif span_days < 180:
        ax.xaxis.set_major_locator(mdates.WeekdayLocator(byweekday=0, interval=2))
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
    else:
        locator = mdates.AutoDateLocator(minticks=4, maxticks=12)
        ax.xaxis.set_major_locator(locator)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))

    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right")


# ---------------------------------------------------------------------------
# Plot: contingency heatmap
# ---------------------------------------------------------------------------

def plot_contingency_heatmap(contingency_csv: str) -> None:
    """
    Heatmap of the 3x3 SDI x StDI joint trend contingency table.
    This is the primary summary figure for RQ3.
    """
    if not os.path.exists(contingency_csv):
        logger.warning("Contingency CSV not found, skipping heatmap.")
        return

    contingency = pd.read_csv(contingency_csv, index_col=0)
    contingency.index.name   = "SDI trend"
    contingency.columns.name = "StDI trend"

    # Reorder axes for readability
    contingency = contingency.reindex(
        index=TREND_LABELS,
        columns=TREND_LABELS,
    )

    # Percentage labels
    total = contingency.values.sum()
    annot = contingency.applymap(
        lambda v: f"{int(v)}\n({v/total*100:.1f}%)" if total > 0 else str(int(v))
    )

    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(
        contingency,
        annot=annot,
        fmt="",
        cmap="Blues",
        linewidths=0.5,
        linecolor="white",
        cbar_kws={"label": "Repository count"},
        ax=ax,
    )
    ax.set_title(
        "RQ3 — Joint Trend Distribution\n"
        "SDI (rows) × StDI (cols) — Mann-Kendall",
        fontsize=13, pad=12,
    )
    ax.set_xlabel("StDI trend", fontsize=11)
    ax.set_ylabel("SDI trend", fontsize=11)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "rq3_contingency_heatmap.png")
    plt.savefig(out, bbox_inches="tight", dpi=300)
    plt.close()
    logger.info(f"Contingency heatmap saved to: {out}")


# ---------------------------------------------------------------------------
# Plot: evolution (LOC vs SDI over time)
# ---------------------------------------------------------------------------

def plot_evolution(
    repo_df: pd.DataFrame,
    repo_name: str,
    cell_label: str,
    prefix: str,
) -> None:
    """LOC (area) vs Security Debt (step line) over time."""
    fig, ax1 = plt.subplots(figsize=(11, 5))
    x = repo_df["author_date"]

    ax1.fill_between(x, repo_df["loc"], color=COLOR_LOC, alpha=0.25,
                     label="Code Size (LOC)")
    ax1.plot(x, repo_df["loc"], color=COLOR_LOC, linewidth=1.2)
    ax1.set_ylabel("Lines of Code (LOC)", color=COLOR_LOC, fontweight="bold")
    ax1.tick_params(axis="y", labelcolor=COLOR_LOC)
    _format_axes_dates(ax1, x)

    ax2 = ax1.twinx()
    ax2.step(x, repo_df["security_debt_score"], color=COLOR_SDI, where="post",
             linewidth=2.2, label="Security Debt (SDI)")
    ax2.set_ylabel("Security Debt Score", color=COLOR_SDI, fontweight="bold")
    ax2.tick_params(axis="y", labelcolor=COLOR_SDI)
    ax2.spines["right"].set_visible(True)

    ax1.set_title(
        f"Evolutionary Dynamics — {repo_name}\n"
        f"Trend cell: {cell_label}",
        pad=10,
    )
    lines  = ax1.get_legend_handles_labels()
    lines2 = ax2.get_legend_handles_labels()
    ax1.legend(lines[0] + lines2[0], lines[1] + lines2[1],
               loc="upper left", framealpha=0.8)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, f"{prefix}_{_safe_name(repo_name)}_evolution.png")
    plt.savefig(out, bbox_inches="tight")
    plt.close()
    logger.info(f"    Saved: {os.path.basename(out)}")


# ---------------------------------------------------------------------------
# Plot: debt composition (stacked area)
# ---------------------------------------------------------------------------

def plot_composition(
    repo_df: pd.DataFrame,
    repo_name: str,
    cell_label: str,
    prefix: str,
) -> None:
    """Stacked area chart of debt composition (infrastructure/dependency/secret)."""
    has_infra = "infrastructure_debt" in repo_df.columns
    has_dep   = "dependency_debt"     in repo_df.columns
    has_sec   = "secret_debt"         in repo_df.columns

    if not (has_infra or has_dep or has_sec):
        logger.warning(f"    No debt composition columns for {repo_name}. Skipping.")
        return

    fig, ax = plt.subplots(figsize=(11, 5))
    x       = repo_df["author_date"]
    stacks, labels, colors = [], [], []

    if has_infra:
        stacks.append(repo_df["infrastructure_debt"].values)
        labels.append("Infrastructure")
        colors.append(COLOR_INFRA)
    if has_dep:
        stacks.append(repo_df["dependency_debt"].values)
        labels.append("Dependency")
        colors.append(COLOR_DEP)
    if has_sec:
        stacks.append(repo_df["secret_debt"].values)
        labels.append("Secret")
        colors.append(COLOR_SEC)

    ax.stackplot(x, *stacks, labels=labels, colors=colors, alpha=0.85)
    ax.set_ylabel("Security Debt Score (Decomposed)")
    ax.set_title(
        f"Debt Composition — {repo_name}\n"
        f"Trend cell: {cell_label}",
        pad=10,
    )
    ax.legend(loc="upper left", framealpha=0.8)
    _format_axes_dates(ax, x)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, f"{prefix}_{_safe_name(repo_name)}_composition.png")
    plt.savefig(out, bbox_inches="tight")
    plt.close()
    logger.info(f"    Saved: {os.path.basename(out)}")


# ---------------------------------------------------------------------------
# Plot: covariance (StDI vs SDI)
# ---------------------------------------------------------------------------

def plot_covariance(
    repo_df: pd.DataFrame,
    repo_name: str,
    cell_label: str,
    prefix: str,
    stdi_series: np.ndarray,
) -> None:
    """
    StDI (dashed purple) vs Security Debt (solid red) co-evolution.
    Primary plot for RQ3 — shows whether structural and security debt
    move together over the project lifecycle.
    """
    fig, ax1 = plt.subplots(figsize=(12, 5))
    x = repo_df["author_date"]

    ax1.step(x, repo_df["security_debt_score"], color=COLOR_SDI, where="post",
             linewidth=2.5, label="Security Debt (SDI)")
    ax1.set_ylabel("Security Debt Score", color=COLOR_SDI, fontweight="bold")
    ax1.tick_params(axis="y", labelcolor=COLOR_SDI)
    _format_axes_dates(ax1, x)

    ax2 = ax1.twinx()
    ax2.step(x, stdi_series, color=COLOR_STDI, where="post", linewidth=2.0,
             linestyle="--", label="Structural Debt Index (StDI)")
    ax2.set_ylabel("Structural Debt Index (intra-project z-score)",
                   color=COLOR_STDI, fontweight="bold")
    ax2.tick_params(axis="y", labelcolor=COLOR_STDI)
    ax2.spines["right"].set_visible(True)

    ax1.set_title(
        f"Structural vs Security Debt Co-evolution — {repo_name}\n"
        f"Trend cell: {cell_label}",
        pad=10,
    )
    lines  = ax1.get_legend_handles_labels()
    lines2 = ax2.get_legend_handles_labels()
    ax1.legend(lines[0] + lines2[0], lines[1] + lines2[1],
               loc="upper left", framealpha=0.8)

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, f"{prefix}_{_safe_name(repo_name)}_covariance.png")
    plt.savefig(out, bbox_inches="tight")
    plt.close()
    logger.info(f"    Saved: {os.path.basename(out)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def analyze_rq3_visualization() -> None:
    logger.info("=" * 60)
    logger.info("RQ3 — Case Study Visualisation")
    logger.info("=" * 60)

    # 1. Validate inputs
    for path, label in [
        (INPUT_CSV,       "dataset_final.csv"),
        (RETAINED_CSV,    "retained_repos_after_trivy_filter.csv"),
        (IMPORTANCE_CSV,  "rq2_feature_importance.csv"),
        (CASES_JSON,      "selected_case_studies.json"),
        (CONTINGENCY_CSV, "rq3_trend_contingency.csv"),
    ]:
        if not os.path.exists(path):
            logger.error(f"Required input not found: {path} ({label})")
            sys.exit(1)

    # 2. Load data
    df = _load_and_preprocess(INPUT_CSV, RETAINED_CSV)

    importance_df = pd.read_csv(IMPORTANCE_CSV)
    importance_df.columns = importance_df.columns.str.lower()
    weights = dict(zip(importance_df["feature"], importance_df["importance"]))

    with open(CASES_JSON) as fh:
        selected_cases = json.load(fh)

    # 3. Contingency heatmap — primary summary figure
    plot_contingency_heatmap(CONTINGENCY_CSV)

    # 4. Per-repo case study plots
    total_plots = 0

    for cell_label, repos in selected_cases.items():
        if not repos:
            logger.warning(f"No repos for cell: {cell_label}")
            continue

        prefix = _safe_name(cell_label).lower()
        logger.info(f"\nCell: {cell_label}")

        for repo_name in repos:
            logger.info(f"  Plotting: {repo_name}")

            repo_df = (
                df[df["repo_name"] == repo_name]
                .copy()
                .reset_index(drop=True)
            )

            if len(repo_df) < 2:
                logger.warning(
                    f"    Insufficient data for {repo_name} "
                    f"({len(repo_df)} snapshots). Skipping."
                )
                continue

            stdi = _compute_stdi(repo_df, weights)

            plot_evolution(repo_df, repo_name, cell_label, prefix)
            plot_composition(repo_df, repo_name, cell_label, prefix)
            plot_covariance(repo_df, repo_name, cell_label, prefix, stdi)
            total_plots += 3

    logger.info(f"\nDone. Generated {total_plots} case study figures "
                f"+ 1 heatmap in: {OUTPUT_DIR}")


if __name__ == "__main__":
    analyze_rq3_visualization()