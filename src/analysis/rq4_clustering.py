"""
rq4_clustering.py — RQ4 Project Profile Clustering
====================================================
Research Question:
    Is it possible to identify distinct clusters of Terraform projects
    with homogeneous profiles of structural and security debt metrics,
    and what distinctive characteristics do they present?

Design rationale
----------------
ITERATION 1 used raw dimensional features (LOC, num_resources, num_modules)
which caused K-Means to produce a trivial large/small split (K=2).

ITERATION 2 introduced debt-ratio features but without outlier control:
ratio features explode when the denominator is near zero, producing
artefactual centroid values in the hundreds of thousands. K was also
fixed at 3 regardless of what the data indicated.

This final version addresses both issues:

1.  DEBT-RATIO FEATURES WITH 95th-PERCENTILE WINSORISATION.
    All ratio features are clipped at their 95th percentile before
    log1p transformation. This preserves legitimate high-intensity
    repos while preventing near-zero-denominator artefacts from
    distorting the scaled feature space. Thresholds are logged for
    reproducibility.

2.  DATA-DRIVEN K SELECTION via silhouette score.
    K is selected automatically as the maximum silhouette over
    K in [K_MIN, K_MAX] on the cleaned, scaled feature space.
    Both elbow and silhouette curves are saved for the paper.

3.  DYNAMIC DESCRIPTIVE NAMING.
    Cluster labels are ranked post-hoc by centroid sdi_per_loc.
    The vocabulary scales with K (Low/Moderate/High for K=3,
    adding Very-Low and Very-High for K=4 and K=5). Labels are
    purely descriptive and population-relative.

Pipeline position:
    Requires:
        - data/output/dataset_final.csv
        - data/output/retained_repos_after_trivy_filter.csv
    Produces:
        - data/output/figures/rq4/rq4_elbow_silhouette.png
        - data/output/figures/rq4/rq4_cluster_scatterplot.png
        - data/output/figures/rq4/rq4_cluster_boxplots.png
        - data/output/figures/rq4/rq4_radar.png
        - data/output/figures/rq4/rq4_cluster_summary.csv
        - data/output/figures/rq4/rq4_numerical_summary.txt

Preprocessing (consistent with all RQ scripts):
    1. analysis_mode == 'ANALYZED'
    2. Trivy filter
    3. loc > 0 and security_debt_score not null
"""

import logging
import os
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

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
    logger.error("Could not import src.config. Run from the project root.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
INPUT_CSV    = os.path.join(config.DATA_OUTPUT_DIR, "dataset_final.csv")
RETAINED_CSV = os.path.join(config.DATA_OUTPUT_DIR,
                             "retained_repos_after_trivy_filter.csv")
OUTPUT_DIR   = os.path.join(config.DATA_OUTPUT_DIR, "figures", "rq4")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Debt-ratio (intensity) features used for clustering.
# Raw dimensional metrics are excluded to prevent size from dominating.
CLUSTERING_FEATURES = [
    "sdi_per_loc",               # security debt density
    "complexity_per_resource",   # structural complexity density
    "hcv_per_loc",               # hard-coded values density
    "infra_share",               # fraction of SDI from infrastructure
    "dep_share",                 # fraction of SDI from dependencies
    "secret_share",              # fraction of SDI from secrets
]

# Supplementary descriptor columns (not used in clustering, used in summary).
DESCRIPTOR_COLS = [
    "loc",
    "num_resources",
    "security_debt_score",
    "iac_mccabe_complexity",
    "hard_coded_values",
]

# Winsorisation percentile for ratio features (clips artefactual outliers
# from near-zero denominators while preserving legitimate high-intensity repos).
WINSOR_PERCENTILE = 95

# K range for silhouette-based automatic selection.
K_MIN        = 2
K_MAX        = 8
RANDOM_STATE = 42
N_INIT       = 20

# Dynamic label vocabulary ordered from lowest to highest debt intensity.
# _name_clusters() selects a centre-anchored slice of length K at runtime:
#   K=2 -> Low-Debt, High-Debt
#   K=3 -> Low-Debt, Moderate-Debt, High-Debt
#   K=4 -> Very-Low-Debt, Low-Debt, Moderate-Debt, High-Debt
#   K=5 -> Very-Low-Debt, Low-Debt, Moderate-Debt, High-Debt, Very-High-Debt
_DEBT_LABELS  = [
    "Very-Low-Debt",
    "Low-Debt",
    "Moderate-Debt",
    "High-Debt",
    "Very-High-Debt",
]
_DEBT_COLOURS = ["#27ae60", "#2ecc71", "#f39c12", "#e74c3c", "#8e1a0e"]

# Plot style
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


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------

def _load_and_preprocess(input_csv: str, retained_csv: str) -> pd.DataFrame:
    """Standard three-step preprocessing consistent with all RQ scripts."""
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

    df["author_date"] = pd.to_datetime(df["author_date"], errors="coerce", utc=True)
    df = df.sort_values(["repo_name", "author_date"]).reset_index(drop=True)
    return df


def _latest_snapshot(df: pd.DataFrame) -> pd.DataFrame:
    """Retains only the most recent snapshot per repository."""
    return (
        df.sort_values("author_date")
          .drop_duplicates("repo_name", keep="last")
          .copy()
          .reset_index(drop=True)
    )


def _engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Derives debt-ratio features from raw metrics with 95th-percentile
    winsorisation.

    Pipeline per ratio feature:
        1. Compute raw ratio (with epsilon denominator guard).
        2. Clip at the 95th percentile of the non-zero distribution.
           This removes artefacts from near-zero denominators (e.g. repos
           with num_resources=1 produce complexity/resource in the millions)
           while preserving legitimate high-intensity repos up to the 95th
           percentile threshold.
        3. log1p + z-score are applied downstream in main().

    Repos with zero SDI receive share values of 0 (not undefined).
    """
    eps = 1e-6
    df  = df.copy()

    for col in ["loc", "num_resources", "security_debt_score",
                "iac_mccabe_complexity", "hard_coded_values",
                "infrastructure_debt", "dependency_debt", "secret_debt"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    loc_safe = df["loc"].clip(lower=eps)
    res_safe = df["num_resources"].clip(lower=eps)
    sdi_safe = df["security_debt_score"].clip(lower=eps)

    # Compute raw ratios
    df["sdi_per_loc"]             = df["security_debt_score"] / loc_safe
    df["complexity_per_resource"] = df["iac_mccabe_complexity"] / res_safe
    df["hcv_per_loc"]             = df["hard_coded_values"] / loc_safe

    # Composition shares (bounded [0,1] by construction)
    df["infra_share"]  = (df["infrastructure_debt"]  / sdi_safe).clip(0.0, 1.0)
    df["dep_share"]    = (df["dependency_debt"]       / sdi_safe).clip(0.0, 1.0)
    df["secret_share"] = (df["secret_debt"]           / sdi_safe).clip(0.0, 1.0)

    zero_sdi = df["security_debt_score"] == 0
    df.loc[zero_sdi, ["infra_share", "dep_share", "secret_share"]] = 0.0

    # Winsorise ratio features at WINSOR_PERCENTILE
    ratio_features = ["sdi_per_loc", "complexity_per_resource", "hcv_per_loc"]
    for feat in ratio_features:
        threshold = np.percentile(df[feat].values, WINSOR_PERCENTILE)
        n_clipped = (df[feat] > threshold).sum()
        df[feat]  = df[feat].clip(upper=threshold)
        logger.info(
            f"  Winsorise {feat}: p{WINSOR_PERCENTILE}={threshold:.4f}, "
            f"clipped {n_clipped} repos ({n_clipped/len(df)*100:.1f}%)"
        )

    return df


# ---------------------------------------------------------------------------
# K diagnostics
# ---------------------------------------------------------------------------

def _compute_k_diagnostics(scaled: np.ndarray) -> tuple:
    """
    Computes inertia and silhouette for K in [K_MIN, K_MAX].
    Returns the K with the maximum silhouette score as optimal_k.
    """
    inertias, silhouettes = [], []
    k_range = list(range(K_MIN, K_MAX + 1))

    for k in k_range:
        km = KMeans(n_clusters=k, random_state=RANDOM_STATE,
                    n_init=N_INIT).fit(scaled)
        inertias.append(km.inertia_)
        sil = silhouette_score(scaled, km.labels_)
        silhouettes.append(sil)
        logger.info(f"  K={k}: inertia={km.inertia_:.1f}, silhouette={sil:.4f}")

    optimal_k = k_range[int(np.argmax(silhouettes))]
    logger.info(
        f"Silhouette-optimal K: {optimal_k} "
        f"(silhouette={max(silhouettes):.4f})"
    )
    return k_range, inertias, silhouettes, optimal_k


# ---------------------------------------------------------------------------
# Cluster naming
# ---------------------------------------------------------------------------

def _name_clusters(df: pd.DataFrame, k: int) -> tuple:
    """
    Assigns descriptive labels by ranking cluster centroids on sdi_per_loc.

    For K=3 the labels are fixed as:
        Rank 1 (lowest)  -> "Low-to-Moderate-Debt"
        Rank 2 (mid)     -> "High-Debt"
        Rank 3 (highest) -> "Very-High-Debt"

    "Low-to-Moderate-Debt" honestly captures that the lowest cluster spans
    the entire lower tail of the debt distribution — including near-zero-SDI
    repos — without implying either that the debt is negligible (Low) or
    meaningful (Moderate) in absolute terms.

    For K != 3 the standard positional vocabulary from _DEBT_LABELS is used.

    Returns (name_map, cluster_order, palette).
    """
    if k == 3:
        labels  = ["Low-to-Moderate-Debt", "High-Debt", "Very-High-Debt"]
        colours = ["#2ecc71",              "#e74c3c",   "#8e1a0e"]
    else:
        n_total = len(_DEBT_LABELS)
        start   = max(0, n_total - k)
        labels  = list(_DEBT_LABELS[start: start + k])
        colours = list(_DEBT_COLOURS[start: start + k])

    centroid_sdi = df.groupby("cluster")["sdi_per_loc"].mean()
    ranked       = centroid_sdi.rank(method="first").astype(int)  # 1=lowest
    label_map    = {1 + i: labels[i] for i in range(k)}
    name_map     = {cid: label_map[r] for cid, r in ranked.items()}
    cluster_order = labels
    palette       = dict(zip(labels, colours))

    return name_map, list(cluster_order), palette


# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------

def _plot_elbow_silhouette(k_range, inertias, silhouettes, optimal_k) -> None:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    ax1.plot(k_range, inertias, marker="o", color="#2c3e50", linewidth=2)
    ax1.axvline(optimal_k, color="#e74c3c", linestyle="--",
                label=f"Selected K={optimal_k}")
    ax1.set_xlabel("Number of Clusters (K)")
    ax1.set_ylabel("Inertia")
    ax1.set_title("Elbow Method")
    ax1.legend(fontsize=9)

    ax2.plot(k_range, silhouettes, marker="s", color="#4878d0", linewidth=2)
    ax2.axvline(optimal_k, color="#e74c3c", linestyle="--",
                label=f"Selected K={optimal_k} (max silhouette)")
    ax2.set_xlabel("Number of Clusters (K)")
    ax2.set_ylabel("Silhouette Score")
    ax2.set_title("Silhouette Score (higher = better)")
    ax2.legend(fontsize=9)

    plt.suptitle(
        "K Selection — Elbow + Silhouette\n"
        "(debt-ratio feature space, 95th-percentile winsorised)",
        fontsize=13, y=1.02,
    )
    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "rq4_elbow_silhouette.png")
    plt.savefig(out, bbox_inches="tight", dpi=200)
    plt.close()
    logger.info(f"Saved: {os.path.basename(out)}")


def _plot_scatterplot(df: pd.DataFrame,
                      cluster_order: list, palette: dict) -> None:
    """LOC vs Security Debt Score, coloured by cluster, sized by complexity."""
    fig, ax = plt.subplots(figsize=(11, 7))

    for archetype in cluster_order:
        grp = df[df["archetype"] == archetype]
        if grp.empty:
            continue
        sizes = np.log1p(grp["iac_mccabe_complexity"].clip(lower=0)) * 15 + 20
        ax.scatter(
            grp["loc"] + 1,
            grp["security_debt_score"] + 1,
            label=archetype,
            color=palette[archetype],
            alpha=0.70,
            edgecolors="k",
            linewidths=0.3,
            s=sizes,
        )

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Lines of Code (LOC) — log scale")
    ax.set_ylabel("Security Debt Score — log scale")
    ax.set_title(
        "RQ4 — Terraform Project Profiles\n"
        "LOC vs Security Debt  |  bubble = log(McCabe complexity)"
    )
    ax.legend(title="Cluster", framealpha=0.85)
    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "rq4_cluster_scatterplot.png")
    plt.savefig(out, bbox_inches="tight", dpi=200)
    plt.close()
    logger.info(f"Saved: {os.path.basename(out)}")


def _plot_boxplots(df: pd.DataFrame,
                   cluster_order: list, palette: dict) -> None:
    """Distribution of key metrics per cluster (log scale)."""
    features_to_plot = [
        ("loc",                     "Lines of Code (LOC)"),
        ("security_debt_score",     "Security Debt Score"),
        ("iac_mccabe_complexity",   "McCabe Complexity"),
        ("hard_coded_values",       "Hard-Coded Values"),
        ("sdi_per_loc",             "SDI per LOC (debt density)"),
        ("complexity_per_resource", "Complexity per Resource (winsorised)"),
    ]
    features_to_plot = [(f, l) for f, l in features_to_plot
                        if f in df.columns]

    ncols = 2
    nrows = (len(features_to_plot) + 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(14, 5 * nrows))
    axes = np.array(axes).flatten()
    order = [c for c in cluster_order if c in df["archetype"].unique()]

    for i, (feature, label) in enumerate(features_to_plot):
        ax = axes[i]
        plot_df = df[["archetype", feature]].copy()
        plot_df[feature] = plot_df[feature] + 1e-6
        sns.boxplot(
            data=plot_df, x="archetype", y=feature,
            hue="archetype", order=order, hue_order=order,
            palette=palette, legend=False, ax=ax,
        )
        ax.set_yscale("log")
        ax.set_title(label)
        ax.set_xlabel("")
        ax.tick_params(axis="x", rotation=15)

    for j in range(len(features_to_plot), len(axes)):
        axes[j].set_visible(False)

    plt.suptitle("RQ4 — Metric Distributions per Cluster", fontsize=13, y=1.01)
    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "rq4_cluster_boxplots.png")
    plt.savefig(out, bbox_inches="tight", dpi=200)
    plt.close()
    logger.info(f"Saved: {os.path.basename(out)}")


def _plot_radar(summary: pd.DataFrame, features: list,
                cluster_order: list, palette: dict) -> None:
    """Radar chart of normalised mean centroid values per cluster."""
    radar_features = [f for f in features if f in summary.columns]
    if len(radar_features) < 3:
        logger.warning("Too few features for radar chart, skipping.")
        return

    norm = summary[radar_features].copy()
    for col in radar_features:
        lo, hi = norm[col].min(), norm[col].max()
        norm[col] = (norm[col] - lo) / (hi - lo) if hi > lo else 0.0

    N      = len(radar_features)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    short = [f.replace("_per_", "/").replace("_", " ")
             for f in radar_features]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

    for archetype in cluster_order:
        if archetype not in norm.index:
            continue
        vals = norm.loc[archetype, radar_features].tolist() + \
               [norm.loc[archetype, radar_features[0]]]
        ax.plot(angles, vals, linewidth=2,
                color=palette[archetype], label=archetype)
        ax.fill(angles, vals, alpha=0.12, color=palette[archetype])

    ax.set_thetagrids(np.degrees(angles[:-1]), short, fontsize=9)
    ax.set_title("RQ4 — Cluster Profiles (normalised centroids)",
                 pad=20, fontsize=13)
    ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.1))

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "rq4_radar.png")
    plt.savefig(out, bbox_inches="tight", dpi=200)
    plt.close()
    logger.info(f"Saved: {os.path.basename(out)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def analyze_rq4_clustering() -> None:
    logger.info("=" * 60)
    logger.info("RQ4 — Project Profile Clustering")
    logger.info("=" * 60)

    # 1. Validate inputs
    for path, label in [
        (INPUT_CSV,    "dataset_final.csv"),
        (RETAINED_CSV, "retained_repos_after_trivy_filter.csv"),
    ]:
        if not os.path.exists(path):
            logger.error(f"Required input not found: {path} ({label})")
            sys.exit(1)

    # 2. Load, filter, latest snapshot
    df        = _load_and_preprocess(INPUT_CSV, RETAINED_CSV)
    df_latest = _latest_snapshot(df)
    logger.info(f"Clustering on {len(df_latest)} projects (latest snapshot).")

    # 3. Feature engineering: debt-ratio features + 95th-pct winsorisation
    logger.info(f"Engineering features (winsorisation at p{WINSOR_PERCENTILE})...")
    df_latest = _engineer_features(df_latest)
    features  = [f for f in CLUSTERING_FEATURES if f in df_latest.columns]
    logger.info(f"Clustering features ({len(features)}): {features}")

    # 4. Preprocessing: log1p + z-score
    X_log    = np.log1p(df_latest[features].values.clip(min=0))
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X_log)

    # 5. Data-driven K selection via silhouette
    logger.info(f"Selecting K via silhouette [{K_MIN}, {K_MAX}]...")
    k_range, inertias, silhouettes, optimal_k = _compute_k_diagnostics(X_scaled)
    _plot_elbow_silhouette(k_range, inertias, silhouettes, optimal_k)

    # 6. Final K-Means with silhouette-optimal K
    logger.info(f"Running final K-Means with K={optimal_k}...")
    kmeans = KMeans(n_clusters=optimal_k, random_state=RANDOM_STATE,
                    n_init=N_INIT).fit(X_scaled)
    df_latest["cluster"] = kmeans.labels_
    final_sil = silhouette_score(X_scaled, kmeans.labels_)
    logger.info(f"Final silhouette score (K={optimal_k}): {final_sil:.4f}")

    # 7. Dynamic descriptive naming
    name_map, cluster_order, palette = _name_clusters(df_latest, optimal_k)
    df_latest["archetype"] = df_latest["cluster"].map(name_map)
    logger.info("Cluster assignments:")
    for cid, name in name_map.items():
        n = (df_latest["cluster"] == cid).sum()
        logger.info(f"  Cluster {cid} -> {name}: {n} repos")

    # 8. Summary statistics
    all_cols = [f for f in features + DESCRIPTOR_COLS if f in df_latest.columns]
    seen = set()
    all_cols = [c for c in all_cols if not (c in seen or seen.add(c))]

    summary = df_latest.groupby("archetype")[all_cols].mean().round(3)
    summary.insert(0, "count", df_latest.groupby("archetype").size())
    summary.index = pd.CategoricalIndex(
        summary.index,
        categories=[c for c in cluster_order if c in summary.index],
        ordered=True,
    )
    summary = summary.sort_index()

    summary_path = os.path.join(OUTPUT_DIR, "rq4_cluster_summary.csv")
    summary.to_csv(summary_path)
    logger.info(f"Cluster summary saved to: {summary_path}")

    logger.info("\n--- Cluster Summary ---")
    for archetype, row in summary.iterrows():
        logger.info(
            f"  {archetype}: n={int(row['count'])}, "
            f"LOC={row.get('loc', 0):.0f}, "
            f"SDI={row.get('security_debt_score', 0):.1f}, "
            f"SDI/LOC={row.get('sdi_per_loc', 0):.4f}, "
            f"Complexity/Res={row.get('complexity_per_resource', 0):.4f}"
        )

    # 9. Numerical summary
    summary_txt = os.path.join(OUTPUT_DIR, "rq4_numerical_summary.txt")
    with open(summary_txt, "w", encoding="utf-8") as fh:
        fh.write("=" * 60 + "\n")
        fh.write("RQ4 — PROJECT PROFILE CLUSTERING — NUMERICAL SUMMARY\n")
        fh.write("=" * 60 + "\n\n")
        fh.write(f"Projects clustered    : {len(df_latest)}\n")
        fh.write(f"Unit of analysis      : latest snapshot per repository\n")
        fh.write(f"Feature space         : debt-ratio (intensity) features\n")
        fh.write(f"Winsorisation         : p{WINSOR_PERCENTILE} per ratio feature\n")
        fh.write(f"Preprocessing         : log1p + z-score\n")
        fh.write(f"Features ({len(features)})         : {', '.join(features)}\n")
        fh.write(f"Algorithm             : K-Means (k-means++, n_init={N_INIT})\n")
        fh.write(f"Random state          : {RANDOM_STATE}\n\n")

        fh.write("--- K selection (silhouette criterion) ---\n")
        for k, sil in zip(k_range, silhouettes):
            marker = " << selected" if k == optimal_k else ""
            fh.write(f"  K={k}: {sil:.4f}{marker}\n")
        fh.write(f"\nSelected K            : {optimal_k}\n")
        fh.write(f"Final silhouette (K={optimal_k}) : {final_sil:.4f}\n\n")

        fh.write("--- Cluster distribution ---\n")
        for archetype, row in summary.iterrows():
            fh.write(
                f"  {archetype}: "
                f"n={int(row['count'])} "
                f"({int(row['count'])/len(df_latest)*100:.1f}%), "
                f"mean LOC={row.get('loc', 0):.0f}, "
                f"mean SDI={row.get('security_debt_score', 0):.1f}, "
                f"mean SDI/LOC={row.get('sdi_per_loc', 0):.4f}, "
                f"mean Complexity/Resource="
                f"{row.get('complexity_per_resource', 0):.4f}\n"
            )

    logger.info(f"Numerical summary saved to: {summary_txt}")

    # 10. Plots
    _plot_scatterplot(df_latest, cluster_order, palette)
    _plot_boxplots(df_latest, cluster_order, palette)
    _plot_radar(summary, features, cluster_order, palette)

    logger.info("\nRQ4 analysis complete.")


if __name__ == "__main__":
    analyze_rq4_clustering()