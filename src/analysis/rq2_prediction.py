"""
rq2_prediction.py
=================
RQ2 — Prediction: Which structural attributes are the most reliable
predictors of security debt (SDI) in Terraform modules?

Analysis pipeline
-----------------
1. Load and preprocess (same filters as RQ1):
   - analysis_mode == 'ANALYZED'
   - Trivy filter
   - loc > 0, security_debt_score not null

2. Feature engineering
   Density metrics are computed to make structural metrics
   comparable across repositories of different sizes.

3. Feature set
   Uses the full candidate set of structural + density metrics.
   Collinear raw/density pairs (e.g. iac_mccabe_complexity and
   complexity_density) are both included because Random Forest
   handles multicollinearity gracefully — unlike OLS, it does not
   require orthogonal predictors. The model will naturally down-weight
   redundant features via feature importance.

4. Log-transform of target (SDI)
   SDI is heavily right-skewed (many zeros, few very high values).
   log1p transform reduces the influence of extreme outliers and
   stabilises variance, leading to better model fit. Predictions are
   back-transformed with expm1 for reporting on the original scale.

5. Group-aware cross-validation (GroupKFold, 5 folds)
   Snapshots from the same repository must NEVER appear in both
   train and test folds — this would constitute data leakage and
   artificially inflate R². GroupKFold splits by repo_name.

6. Group-aware train/test split (GroupShuffleSplit, 80/20)
   Same principle applied to the final held-out evaluation.

7. Feature importance ranking
   Saved as rq2_feature_importance.csv — this file is the direct
   input for StDI construction in rq3_statistics.py.

8. Visualisations
   - Feature importance bar chart
   - Predicted vs actual scatter plot (original scale)

Notes
-----
- R² from GroupKFold CV is the primary metric. R² on the held-out
  test set is reported as a secondary check.
- A suspiciously high R² (> 0.90) is a red flag for data leakage:
  check that GroupKFold and GroupShuffleSplit are correctly applied.
- MAE is reported on the original (back-transformed) scale because
  it is interpretable by practitioners.
- This script produces rq2_feature_importance.csv which is a
  required input for rq3_statistics.py and rq3_visualization.py.
  Always run RQ2 before RQ3.
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, cross_val_score
from sklearn.metrics import r2_score, mean_absolute_error, mean_squared_error

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INPUT_CSV    = os.path.join('data', 'output', 'dataset_final.csv')
RETAINED_CSV = os.path.join('data', 'output', 'retained_repos_after_trivy_filter.csv')
OUTPUT_DIR   = os.path.join('data', 'output', 'figures', 'rq2')

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Candidate structural metrics (raw)
RAW_METRICS = [
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

# Random Forest hyperparameters
RF_N_ESTIMATORS = 2000
RF_RANDOM_STATE = 42
CV_N_SPLITS     = 5
TEST_SIZE       = 0.20


# ---------------------------------------------------------------------------
# Data loading and preprocessing
# (self-contained; mirrors rq1_correlation.py)
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
        print(f"After analysis_mode filter : {len(df)} rows "
              f"({n_raw - len(df)} SKIPPED_DUPLICATE rows removed)")
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
# Feature engineering
# ---------------------------------------------------------------------------

def engineer_features(df: pd.DataFrame) -> tuple[pd.DataFrame, list]:
    """
    Converts raw metrics to numeric, computes density metrics, and
    returns the enriched DataFrame with the final list of features.

    Density metrics normalise structural metrics by LOC, making them
    comparable across repositories of different sizes. Both raw and
    density versions are included as candidate features because Random
    Forest handles correlated features well and will naturally
    down-weight redundant ones.

    Returns (df, features) where features is the list of column names
    to use as predictors.
    """
    # Convert raw metrics
    for col in RAW_METRICS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    # Compute density metrics
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

    # Full candidate feature list
    candidate_features = (
        [m for m in RAW_METRICS if m in df.columns]
        + [d for d in density_map.values() if d in df.columns]
    )

    # Remove zero-variance features (break tree splits)
    zero_var = [f for f in candidate_features if df[f].var() == 0]
    if zero_var:
        print(f"Removed zero-variance features: {zero_var}")
        candidate_features = [f for f in candidate_features if f not in zero_var]

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    return df, candidate_features


# ---------------------------------------------------------------------------
# Model training and evaluation
# ---------------------------------------------------------------------------

def run_cross_validation(
    X: pd.DataFrame,
    y: pd.Series,
    groups: pd.Series,
    rf: RandomForestRegressor,
) -> np.ndarray:
    """
    Runs GroupKFold cross-validation to estimate model generalisation.

    GroupKFold ensures that all snapshots from the same repository land
    in the same fold. Without this, the model can memorise repository-
    specific patterns and report artificially high R² — the primary
    source of data leakage in longitudinal repository studies.

    Returns the array of per-fold R² scores.
    """
    print(f"Running {CV_N_SPLITS}-fold GroupKFold cross-validation "
          f"(grouped by repository)...")

    gkf = GroupKFold(n_splits=CV_N_SPLITS)
    cv_scores = cross_val_score(
        rf, X, y,
        cv=gkf,
        groups=groups,
        scoring='r2',
        n_jobs=-1,
    )

    print(f"R² per fold : {np.round(cv_scores, 4)}")
    print(f"Mean R²     : {cv_scores.mean():.4f}")
    print(f"Std R²      : {cv_scores.std():.4f}  "
          f"(95% CI ≈ ±{cv_scores.std() * 2:.4f})")

    if cv_scores.mean() > 0.90:
        print(
            "\nWARNING: Mean R² > 0.90 is unusually high for this type of study.\n"
            "         Verify that GroupKFold is correctly grouping by repo_name\n"
            "         and that no target-derived features are in the feature set."
        )

    return cv_scores


def run_final_evaluation(
    df: pd.DataFrame,
    X: pd.DataFrame,
    y: pd.Series,
    groups: pd.Series,
    features: list,
    rf: RandomForestRegressor,
    cv_scores: np.ndarray,
) -> None:
    """
    Fits the model on a group-aware 80/20 split, evaluates on the
    held-out test set, saves the performance report, feature importance
    CSV, and visualisations.
    """
    print(f"\nFitting final model on 80/20 GroupShuffleSplit "
          f"(test size = {TEST_SIZE})...")

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=TEST_SIZE,
        random_state=RF_RANDOM_STATE,
    )
    train_idx, test_idx = next(splitter.split(X, y, groups=groups))

    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

    n_train_repos = groups.iloc[train_idx].nunique()
    n_test_repos  = groups.iloc[test_idx].nunique()
    print(f"Train: {len(X_train)} snapshots from {n_train_repos} repos")
    print(f"Test : {len(X_test)} snapshots from {n_test_repos} repos")

    rf.fit(X_train, y_train)

    # Predictions — back-transform from log1p scale
    y_pred_log = rf.predict(X_test)
    y_test_orig = np.expm1(y_test)
    y_pred_orig = np.expm1(y_pred_log)

    r2_test  = r2_score(y_test_orig, y_pred_orig)
    mae_test = mean_absolute_error(y_test_orig, y_pred_orig)
    mse_test = mean_squared_error(y_test_orig, y_pred_orig)
    rmse_test = np.sqrt(mse_test)

    print(f"\nTest set performance (original SDI scale):")
    print(f"  R²   : {r2_test:.4f}")
    print(f"  MAE  : {mae_test:.4f}")
    print(f"  RMSE : {rmse_test:.4f}")

    # Save performance report
    report_path = os.path.join(OUTPUT_DIR, 'rq2_model_performance.txt')
    with open(report_path, 'w') as fh:
        fh.write("RQ2 — RANDOM FOREST MODEL PERFORMANCE\n")
        fh.write("=" * 50 + "\n\n")
        fh.write(f"Features used ({len(features)}):\n")
        for f in features:
            fh.write(f"  - {f}\n")
        fh.write(f"\nTarget transformation: log1p(SDI)\n\n")
        fh.write(f"GROUP-AWARE CROSS-VALIDATION ({CV_N_SPLITS}-fold GroupKFold)\n")
        fh.write("-" * 50 + "\n")
        fh.write(f"R² per fold : {np.round(cv_scores, 4)}\n")
        fh.write(f"Mean R²     : {cv_scores.mean():.4f}\n")
        fh.write(f"Std R²      : {cv_scores.std():.4f}\n")
        fh.write(f"95% CI      : ±{cv_scores.std() * 2:.4f}\n\n")
        fh.write(f"HELD-OUT TEST SET (original SDI scale, 80/20 GroupShuffleSplit)\n")
        fh.write("-" * 50 + "\n")
        fh.write(f"Train repos : {n_train_repos}\n")
        fh.write(f"Test  repos : {n_test_repos}\n")
        fh.write(f"R²          : {r2_test:.4f}\n")
        fh.write(f"MAE         : {mae_test:.4f}\n")
        fh.write(f"RMSE        : {rmse_test:.4f}\n")
    print(f"Performance report saved to: {report_path}")

    # Feature importance
    importances = pd.DataFrame({
        'Feature':    features,
        'Importance': rf.feature_importances_,
    }).sort_values('Importance', ascending=False).reset_index(drop=True)

    importance_path = os.path.join(OUTPUT_DIR, 'rq2_feature_importance.csv')
    importances.to_csv(importance_path, index=False)
    print(f"Feature importance saved to: {importance_path}")
    print(f"\nFeature importance ranking:")
    print(importances.to_string(index=False))

    # Visualisations
    _plot_feature_importance(importances)
    _plot_predicted_vs_actual(y_test_orig, y_pred_orig, r2_test, cv_scores.mean())


# ---------------------------------------------------------------------------
# Visualisations
# ---------------------------------------------------------------------------

def _plot_feature_importance(importances: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(10, 7))
    colours = [
        '#2166ac' if 'density' in f else '#92c5de'
        for f in importances['Feature']
    ]
    ax.barh(
        importances['Feature'],
        importances['Importance'],
        color=colours,
        edgecolor='k',
        linewidth=0.5,
    )
    ax.invert_yaxis()
    ax.set_xlabel('Feature Importance (mean decrease in impurity)', fontsize=11)
    ax.set_title(
        'RQ2 — Predictors of Security Debt\n'
        'Dark blue = density metrics  |  Light blue = raw metrics',
        fontsize=12,
    )
    ax.axvline(0, color='black', linewidth=0.8)
    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, 'rq2_feature_importance.png')
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"Feature importance chart saved to: {path}")


def _plot_predicted_vs_actual(
    y_true: pd.Series,
    y_pred: np.ndarray,
    r2_held_out: float,
    mean_r2_cv: float,
) -> None:
    fig, ax = plt.subplots(figsize=(8, 8))
    ax.scatter(y_true, y_pred, alpha=0.35, color='teal', edgecolors='none', s=20)

    lim_min = min(y_true.min(), y_pred.min())
    lim_max = max(y_true.max(), y_pred.max())
    ax.plot([lim_min, lim_max], [lim_min, lim_max], 'r--', linewidth=1.5,
            label='Perfect prediction')

    ax.set_xlabel('Actual Security Debt Score', fontsize=11)
    ax.set_ylabel('Predicted Security Debt Score', fontsize=11)
    ax.set_title(
        f'RQ2 — Prediction Accuracy (original SDI scale)\n'
        f'Held-out R² = {r2_held_out:.3f}  |  CV Mean R² = {mean_r2_cv:.3f}  |  GroupShuffleSplit 80/20',
        fontsize=12,
    )
    ax.legend()
    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, 'rq2_predicted_vs_actual.png')
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"Predicted vs actual chart saved to: {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyze_rq2() -> None:
    print("=" * 60)
    print("RQ2 — PREDICTION ANALYSIS (Random Forest + GroupKFold CV)")
    print("=" * 60)

    # 1. Load and filter
    df = load_and_filter(INPUT_CSV, RETAINED_CSV)

    # 2. Feature engineering
    df, features = engineer_features(df)

    if not features:
        print("ERROR: No valid features found in the dataset.")
        sys.exit(1)

    print(f"Feature set ({len(features)}): {features}")

    # 3. Prepare X, y, groups
    X      = df[features]
    y      = np.log1p(df[TARGET])   # log1p transform for right-skewed SDI
    groups = df['repo_name']

    n_repos = groups.nunique()
    if n_repos < CV_N_SPLITS:
        print(f"ERROR: Only {n_repos} repositories available — need at least "
              f"{CV_N_SPLITS} for {CV_N_SPLITS}-fold GroupKFold.")
        sys.exit(1)

    print(f"\nObservations : {len(X)}")
    print(f"Repositories : {n_repos}")
    print(f"Target       : log1p(security_debt_score)\n")

    # 4. Instantiate model
    rf = RandomForestRegressor(
        n_estimators=RF_N_ESTIMATORS,
        random_state=RF_RANDOM_STATE,
        n_jobs=-1,
    )

    # 5. Group-aware cross-validation
    cv_scores = run_cross_validation(X, y, groups, rf)

    # 6. Final evaluation on held-out test set
    run_final_evaluation(df, X, y, groups, features, rf, cv_scores)

    print("\nRQ2 prediction analysis complete.")
    print(f"IMPORTANT: rq2_feature_importance.csv is required by rq3_statistics.py")
    print(f"           and rq3_visualization.py. Run RQ2 before RQ3.")


if __name__ == "__main__":
    analyze_rq2()