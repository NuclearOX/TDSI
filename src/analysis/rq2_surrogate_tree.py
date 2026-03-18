"""
rq2_surrogate_tree.py
=====================
Surrogate Decision Tree for RQ2 — interpretability companion.

This module trains a shallow DecisionTreeRegressor to approximate
the Random Forest's predictions, producing a human-readable proxy
model (Global Surrogate Tree) that can be visualised in the paper.

It does NOT modify rq2_prediction.py. It reuses its data loading
and feature engineering functions, then trains the surrogate
independently.

Outputs
-------
- rq2_surrogate_tree_report.txt   : thresholds, leaf values, fidelity R²
- rq2_surrogate_tree.png          : visual plot of the tree
- rq2_surrogate_tree_latex.tex    : ready-to-paste LaTeX tikzpicture

Usage
-----
Run AFTER rq2_prediction.py (requires rq2_feature_importance.csv):

    python rq2_surrogate_tree.py

The script will print the exact threshold values and predicted SDI
per leaf — paste those directly into your LaTeX figure.
"""

import os
import sys
import textwrap
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

from sklearn.tree import DecisionTreeRegressor, plot_tree, export_text
from sklearn.metrics import r2_score

# ---------------------------------------------------------------------------
# Import shared utilities from rq2_prediction.py
# (must be in the same directory or on PYTHONPATH)
# ---------------------------------------------------------------------------
try:
    from rq2_prediction import (
        load_and_filter,
        engineer_features,
        INPUT_CSV,
        RETAINED_CSV,
        TARGET,
        RF_N_ESTIMATORS,
        RF_RANDOM_STATE,
    )
except ImportError as e:
    print(f"ERROR: Could not import from rq2_prediction.py.\n"
          f"       Make sure this file is in the same directory.\n"
          f"       Details: {e}")
    sys.exit(1)

from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import GroupShuffleSplit

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SURROGATE_MAX_DEPTH = 2          # keep it readable in the paper
OUTPUT_DIR = os.path.join('data', 'output', 'figures', 'rq2')
os.makedirs(OUTPUT_DIR, exist_ok=True)

IMPORTANCE_CSV = os.path.join(OUTPUT_DIR, 'rq2_feature_importance.csv')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_importance_ranking() -> list[str]:
    """
    Returns features sorted by importance (descending).
    Used to label the tree nodes with human-readable context.
    """
    if not os.path.exists(IMPORTANCE_CSV):
        print(f"WARNING: {IMPORTANCE_CSV} not found. "
              f"Run rq2_prediction.py first.")
        return []
    return (
        pd.read_csv(IMPORTANCE_CSV)
          .sort_values('Importance', ascending=False)['Feature']
          .tolist()
    )


def _train_random_forest(X_train, y_train) -> RandomForestRegressor:
    print("Training Random Forest on training split...")
    rf = RandomForestRegressor(
        n_estimators=RF_N_ESTIMATORS,
        random_state=RF_RANDOM_STATE,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    return rf


def _train_surrogate(X_train, rf_predictions_train) -> DecisionTreeRegressor:
    """
    Trains the surrogate tree to mimic the RF's predictions
    (not the raw SDI labels — this is the standard surrogate approach).
    """
    print(f"Training surrogate tree (max_depth={SURROGATE_MAX_DEPTH})...")
    surrogate = DecisionTreeRegressor(
        max_depth=SURROGATE_MAX_DEPTH,
        random_state=42,
    )
    surrogate.fit(X_train, rf_predictions_train)
    return surrogate


def _fidelity(surrogate, X_test, rf_predictions_test) -> float:
    """
    Fidelity R²: how well the surrogate approximates the RF
    on unseen data. This is what you report in the paper caption.
    """
    surr_pred = surrogate.predict(X_test)
    return r2_score(rf_predictions_test, surr_pred)


def _extract_node_info(surrogate: DecisionTreeRegressor,
                       feature_names: list) -> dict:
    """
    Extracts threshold values and leaf mean-SDI estimates
    from the surrogate tree for direct use in LaTeX.

    Returns a dict with keys:
        root, left, right,
        ll (left-left leaf), lr (left-right leaf),
        rl (right-left leaf), rr (right-right leaf)
    Each entry has 'feature', 'threshold', and (for leaves) 'value'.
    """
    t   = surrogate.tree_
    fn  = feature_names

    def node(i):
        is_leaf = t.children_left[i] == -1
        info = {
            'index':    i,
            'is_leaf':  is_leaf,
            'feature':  fn[t.feature[i]] if not is_leaf else None,
            'threshold': round(float(t.threshold[i]), 4) if not is_leaf else None,
            # value is in log1p space — back-transform for reporting
            'value_log': float(t.value[i][0][0]) if is_leaf else None,
            'value_sdi': round(float(np.expm1(t.value[i][0][0])), 2)
                         if is_leaf else None,
            'n_samples': int(t.n_node_samples[i]),
        }
        return info

    root  = node(0)
    left  = node(t.children_left[0])
    right = node(t.children_right[0])
    ll    = node(t.children_left[left['index']])
    lr    = node(t.children_right[left['index']])
    rl    = node(t.children_left[right['index']])
    rr    = node(t.children_right[right['index']])

    return dict(root=root, left=left, right=right,
                ll=ll, lr=lr, rl=rl, rr=rr)


def _sdi_label(sdi_value: float, p33: float, p66: float) -> str:
    """Converts a numeric SDI into a risk tier label using dataset percentiles."""
    if sdi_value <= p33:
        return "Low Risk"
    elif sdi_value <= p66:
        return "Moderate Risk"
    else:
        return "High Risk"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _save_report(nodes: dict, fidelity: float,
                 p33: float, p66: float, path: str) -> None:
    lines = [
        "RQ2 — SURROGATE DECISION TREE REPORT",
        "=" * 50,
        "",
        f"Surrogate max depth     : {SURROGATE_MAX_DEPTH}",
        f"Fidelity R² (vs RF)     : {fidelity:.4f}",
        "",
        "SDI percentile thresholds used for leaf labels:",
        f"  p33 = {p33:.2f}   p66 = {p66:.2f}",
        "",
        "NODE DETAILS",
        "-" * 50,
        f"Root  (node 0) : {nodes['root']['feature']} <= {nodes['root']['threshold']}",
        f"Left  (node)   : {nodes['left']['feature']} <= {nodes['left']['threshold']}",
        f"Right (node)   : {nodes['right']['feature']} <= {nodes['right']['threshold']}",
        "",
        "LEAF VALUES (back-transformed to original SDI scale)",
        "-" * 50,
        f"LL (Low-left)   : SDI = {nodes['ll']['value_sdi']}  "
        f"=> {_sdi_label(nodes['ll']['value_sdi'], p33, p66)}",
        f"LR (Low-right)  : SDI = {nodes['lr']['value_sdi']}  "
        f"=> {_sdi_label(nodes['lr']['value_sdi'], p33, p66)}",
        f"RL (High-left)  : SDI = {nodes['rl']['value_sdi']}  "
        f"=> {_sdi_label(nodes['rl']['value_sdi'], p33, p66)}",
        f"RR (High-right) : SDI = {nodes['rr']['value_sdi']}  "
        f"=> {_sdi_label(nodes['rr']['value_sdi'], p33, p66)}",
        "",
        "LATEX PLACEHOLDERS TO USE",
        "-" * 50,
        f"T1 = {nodes['root']['threshold']}  "
        f"({nodes['root']['feature']})",
        f"T2 = {nodes['left']['threshold']}  "
        f"({nodes['left']['feature']})",
        f"T3 = {nodes['right']['threshold']}  "
        f"({nodes['right']['feature']})",
    ]
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines))
    print(f"Report saved to: {path}")


# ---------------------------------------------------------------------------
# LaTeX generation
# ---------------------------------------------------------------------------

def _generate_latex(nodes: dict, fidelity: float,
                    p33: float, p66: float, path: str) -> None:
    """
    Generates a tikzpicture with real threshold values and SDI leaf values.
    Risk tier colours are derived from dataset percentiles, not arbitrary.
    """

    def leaf_style(sdi):
        label = _sdi_label(sdi, p33, p66)
        if label == "Low Risk":
            return "leafgreen"
        elif label == "Moderate Risk":
            return "leaforange"
        else:
            return "leafred"

    def leaf_content(sdi, n):
        label = _sdi_label(sdi, p33, p66)
        return (f"{label}\\\\\n"
                f"             $\\widehat{{\\text{{SDI}}}} = {sdi:.1f}$\\\\\n"
                f"             \\small{{(n={n})}}")

    n  = nodes
    r  = n['root']
    l  = n['left']
    ri = n['right']

    latex = textwrap.dedent(f"""
    % ---------------------------------------------------------------
    % Global Surrogate Decision Tree — generated by rq2_surrogate_tree.py
    % Fidelity R² (surrogate vs RF) = {fidelity:.4f}
    % Risk tiers: Low <= {p33:.1f} < Moderate <= {p66:.1f} < High
    % ---------------------------------------------------------------
    \\begin{{figure}}[!t]
    \\centering
    \\resizebox{{\\columnwidth}}{{!}}{{%
    \\begin{{tikzpicture}}[
        level 1/.style={{sibling distance=9cm, level distance=3.2cm}},
        level 2/.style={{sibling distance=4.5cm, level distance=3.2cm}},
        decision/.style={{
            rectangle, draw=black, fill=blue!10,
            text width=4.0cm, align=center,
            rounded corners, minimum height=1.2cm, font=\\small
        }},
        leafgreen/.style={{
            rectangle, draw=black, fill=green!20,
            text width=3.2cm, align=center,
            rounded corners, font=\\small\\bfseries
        }},
        leaforange/.style={{
            rectangle, draw=black, fill=orange!20,
            text width=3.2cm, align=center,
            rounded corners, font=\\small\\bfseries
        }},
        leafred/.style={{
            rectangle, draw=black, fill=red!20,
            text width=3.2cm, align=center,
            rounded corners, font=\\small\\bfseries
        }},
        edge from parent/.style={{draw, -latex, thick}},
        edgelabel/.style={{font=\\small, fill=white, inner sep=2pt}}
    ]

    \\node[decision]
        {{\\textbf{{Infrastructure scale?}}\\\\[4pt]
         \\texttt{{{r['feature']}}} $\\leq {r['threshold']}$}}
        %% LEFT branch (small scale)
        child {{
            node[decision]
                {{\\textbf{{External dependencies?}}\\\\[4pt]
                 \\texttt{{{l['feature']}}} $\\leq {l['threshold']}$}}
            child {{
                node[{leaf_style(n['ll']['value_sdi'])}]{{
                    {leaf_content(n['ll']['value_sdi'], n['ll']['n_samples'])}
                }}
                edge from parent
                    node[edgelabel, above left]{{True}}
            }}
            child {{
                node[{leaf_style(n['lr']['value_sdi'])}]{{
                    {leaf_content(n['lr']['value_sdi'], n['lr']['n_samples'])}
                }}
                edge from parent
                    node[edgelabel, above right]{{False}}
            }}
            edge from parent
                node[edgelabel, above left]{{True (Small Scale)}}
        }}
        %% RIGHT branch (large scale)
        child {{
            node[decision]
                {{\\textbf{{Logical abstraction?}}\\\\[4pt]
                 \\texttt{{{ri['feature']}}} $\\leq {ri['threshold']}$}}
            child {{
                node[{leaf_style(n['rl']['value_sdi'])}]{{
                    {leaf_content(n['rl']['value_sdi'], n['rl']['n_samples'])}
                }}
                edge from parent
                    node[edgelabel, above left]{{True}}
            }}
            child {{
                node[{leaf_style(n['rr']['value_sdi'])}]{{
                    {leaf_content(n['rr']['value_sdi'], n['rr']['n_samples'])}
                }}
                edge from parent
                    node[edgelabel, above right]{{False}}
            }}
            edge from parent
                node[edgelabel, above right]{{False (Large Scale)}}
        }};

    \\end{{tikzpicture}}
    }}
    \\caption{{Global Surrogate Decision Tree (depth~$= {SURROGATE_MAX_DEPTH}$),
    trained to approximate the Random Forest's predictions on the
    training set (fidelity $R^2 = {fidelity:.3f}$). Thresholds and
    leaf $\\widehat{{\\text{{SDI}}}}$ values are derived directly from the CART
    algorithm. Risk tiers (Low~$\\leq {p33:.0f}$, Moderate~$\\leq {p66:.0f}$,
    High~$> {p66:.0f}$) correspond to the 33rd and 66th percentiles of
    the SDI distribution in the training set.}}
    \\label{{fig:decision_tree}}
    \\end{{figure}}
    """)

    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(latex)
    print(f"LaTeX saved to: {path}")


# ---------------------------------------------------------------------------
# Matplotlib tree plot
# ---------------------------------------------------------------------------

def _plot_tree(surrogate: DecisionTreeRegressor,
               feature_names: list, path: str) -> None:
    fig, ax = plt.subplots(figsize=(16, 7))
    plot_tree(
        surrogate,
        feature_names=feature_names,
        filled=True,
        rounded=True,
        fontsize=11,
        ax=ax,
        impurity=False,
        proportion=False,
    )
    ax.set_title(
        f"Global Surrogate Decision Tree (depth={SURROGATE_MAX_DEPTH})\n"
        "Trained to approximate Random Forest predictions",
        fontsize=13,
    )
    plt.tight_layout()
    fig.savefig(path, dpi=300, bbox_inches='tight')
    plt.close(fig)
    print(f"Tree plot saved to: {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_surrogate() -> None:
    print("=" * 60)
    print("RQ2 — SURROGATE TREE BUILDER")
    print("=" * 60)

    # 1. Load data (same pipeline as rq2_prediction.py)
    df = load_and_filter(INPUT_CSV, RETAINED_CSV)
    df, features = engineer_features(df)

    X      = df[features]
    y      = np.log1p(df[TARGET])
    groups = df['repo_name']

    # 2. Group-aware 80/20 split (same seed as rq2_prediction.py)
    splitter = GroupShuffleSplit(
        n_splits=1, test_size=0.20, random_state=RF_RANDOM_STATE
    )
    train_idx, test_idx = next(splitter.split(X, y, groups=groups))
    X_train = X.iloc[train_idx]
    X_test  = X.iloc[test_idx]
    y_train = y.iloc[train_idx]

    # 3. Train the full Random Forest
    rf = _train_random_forest(X_train, y_train)

    # RF predictions on both splits (log1p scale — surrogate works in same space)
    rf_pred_train = rf.predict(X_train)
    rf_pred_test  = rf.predict(X_test)

    # 4. Train surrogate
    surrogate = _train_surrogate(X_train, rf_pred_train)

    # 5. Fidelity
    fidelity = _fidelity(surrogate, X_test, rf_pred_test)
    print(f"\nSurrogate fidelity R² (vs RF, test set): {fidelity:.4f}")
    if fidelity < 0.60:
        print("WARNING: fidelity < 0.60 — the surrogate may be too shallow "
              "to represent the RF reliably. Consider max_depth=3.")

    # 6. Print text representation
    print("\nSurrogate tree structure (text):")
    print(export_text(surrogate, feature_names=features))

    # 7. Extract node info
    nodes = _extract_node_info(surrogate, features)

    # 8. SDI percentile thresholds for risk labels
    #    Computed on training set original-scale SDI
    sdi_train_orig = np.expm1(y_train)
    p33 = float(np.percentile(sdi_train_orig, 33))
    p66 = float(np.percentile(sdi_train_orig, 66))
    print(f"\nSDI percentiles (training set): p33={p33:.2f}, p66={p66:.2f}")

    # 9. Save outputs
    report_path = os.path.join(OUTPUT_DIR, 'rq2_surrogate_tree_report.txt')
    plot_path   = os.path.join(OUTPUT_DIR, 'rq2_surrogate_tree.png')
    latex_path  = os.path.join(OUTPUT_DIR, 'rq2_surrogate_tree_latex.tex')

    _save_report(nodes, fidelity, p33, p66, report_path)
    _plot_tree(surrogate, features, plot_path)
    _generate_latex(nodes, fidelity, p33, p66, latex_path)

    print("\n" + "=" * 60)
    print("SURROGATE TREE BUILD COMPLETE")
    print("=" * 60)
    print(f"  Report : {report_path}")
    print(f"  Plot   : {plot_path}")
    print(f"  LaTeX  : {latex_path}")
    print("\nCopy the values from the report into your LaTeX figure,")
    print("or use the generated .tex file directly.")


if __name__ == "__main__":
    build_surrogate()