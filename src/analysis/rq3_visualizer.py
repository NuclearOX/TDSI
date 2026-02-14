import pandas as pd
import matplotlib.pyplot as plt
import os
import sys
import json
import numpy as np
from sklearn.preprocessing import StandardScaler

# --- CONFIGURATION ---
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
IMPORTANCE_CSV = os.path.join('data', 'output', 'figures', 'rq2_feature_importance.csv')
SELECTION_FILE = os.path.join('data', 'output', 'reports', 'selected_cases.json')
OUTPUT_DIR = os.path.join('data', 'output', 'figures', 'case_studies')

os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data_robust(filepath):
    if not os.path.exists(filepath):
        print(f"ERROR: File {filepath} not found.")
        sys.exit(1)
    try:
        df = pd.read_csv(filepath)
    except Exception:
        df = pd.read_csv(filepath, sep=',', on_bad_lines='skip', engine='python')
    return df

def analyze_rq3_visualization():
    print("--- RQ3: Visualizing Selected Case Studies (Full Suite) ---")
    
    # 1. Load Data & Weights
    if not os.path.exists(IMPORTANCE_CSV):
        print("ERROR: Missing feature importance file. Run RQ2 first.")
        return

    df = load_data_robust(INPUT_CSV)
    importance_df = pd.read_csv(IMPORTANCE_CSV)
    weights = dict(zip(importance_df['Feature'], importance_df['Importance']))

    # Data Cleanup
    df['author_date'] = pd.to_datetime(df['author_date'], utc=True, errors='coerce')
    df = df.dropna(subset=['author_date'])
    cols = ['loc', 'security_debt_score', 'infrastructure_debt', 'dependency_debt', 'secret_debt']
    for c in cols:
        if c in df.columns: df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)
    
    # Feature Engineering for StDI (Needed for the Quality Plot)
    def safe_div(a, b): return a / b if b > 0 else 0
    if 'iac_mccabe_complexity' in df.columns:
        df['complexity_density'] = df.apply(lambda x: safe_div(x['iac_mccabe_complexity'], x['loc']), axis=1)
    if 'hard_coded_values' in df.columns:
        df['hard_coded_density'] = df.apply(lambda x: safe_div(x['hard_coded_values'], x['loc']), axis=1)
    if 'comment_lines' in df.columns:
        df['comment_density'] = df.apply(lambda x: safe_div(x['comment_lines'], x['loc']), axis=1)
    df.replace([np.inf, -np.inf], 0, inplace=True)
    df.fillna(0, inplace=True)

    # 2. Load Selected Cases
    if not os.path.exists(SELECTION_FILE):
        print(f"ERROR: Selection file not found at {SELECTION_FILE}")
        print("Run 'rq3_statistics.py' first.")
        return

    with open(SELECTION_FILE, 'r') as f:
        selected_cases = json.load(f)

    # 3. Generate Plots
    total_plots = 0
    for pattern, repos in selected_cases.items():
        print(f"\nProcessing pattern: {pattern}")
        for repo in repos:
            print(f"  - Plotting: {repo}")
            repo_df = df[df['repo_name'] == repo].sort_values('author_date')
            
            if repo_df.empty or len(repo_df) < 2:
                print(f"    WARNING: Insufficient data for {repo}")
                continue

            # Calculate StDI for this specific repo (Local Standardization)
            features_to_scale = [f for f in weights.keys() if f in repo_df.columns]
            if features_to_scale:
                scaler = StandardScaler()
                repo_df_scaled = repo_df.copy()
                repo_df_scaled[features_to_scale] = scaler.fit_transform(repo_df[features_to_scale])
                
                repo_df['stdi'] = 0.0
                for feature in features_to_scale:
                    repo_df['stdi'] += repo_df_scaled[feature] * weights.get(feature, 0)
            else:
                repo_df['stdi'] = 0

            # Prefix filename with pattern
            prefix = pattern.replace(' ', '_').lower()
            
            # --- GENERATE THE 3 PLOTS ---
            plot_evolution_step(repo_df, repo, prefix)       # LOC vs SecDebt
            plot_evolution_stacked(repo_df, repo, prefix)    # Debt Composition
            plot_quality_vs_security(repo_df, repo, prefix)  # StDI vs SecDebt (THE CRITICAL ONE)
            
            total_plots += 3

    print(f"\nDone. Generated {total_plots} figures in {OUTPUT_DIR}")

def plot_evolution_step(repo_df, repo_name, prefix):
    safe_name = "".join([c for c in repo_name if c.isalpha() or c.isdigit()]).rstrip()
    fig, ax1 = plt.subplots(figsize=(10, 6))
    x = repo_df['author_date']
    
    ax1.fill_between(x, repo_df['loc'], color="skyblue", alpha=0.3, label='Code Size (LOC)')
    ax1.set_ylabel('Lines of Code (LOC)', color='steelblue', fontweight='bold')
    ax1.tick_params(axis='y', labelcolor='steelblue')
    
    ax2 = ax1.twinx()
    ax2.step(x, repo_df['security_debt_score'], color='#d62728', where='post', linewidth=2, label='Security Debt')
    ax2.set_ylabel('Security Debt Score', color='#d62728', fontweight='bold')
    ax2.tick_params(axis='y', labelcolor='#d62728')

    plt.title(f'Evolutionary Dynamics: {repo_name}\n({prefix.replace("_", " ").title()})', fontsize=14)
    lines, labels = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax2.legend(lines + lines2, labels + labels2, loc='upper left')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, f"{prefix}_{safe_name}_step.png"), dpi=150)
    plt.close()

def plot_evolution_stacked(repo_df, repo_name, prefix):
    safe_name = "".join([c for c in repo_name if c.isalpha() or c.isdigit()]).rstrip()
    fig, ax = plt.subplots(figsize=(10, 6))
    x = repo_df['author_date']
    
    infra = repo_df.get('infrastructure_debt', pd.Series(0, index=repo_df.index))
    deps = repo_df.get('dependency_debt', pd.Series(0, index=repo_df.index))
    secrets = repo_df.get('secret_debt', pd.Series(0, index=repo_df.index))
    
    ax.stackplot(x, infra, deps, secrets, 
                  labels=['Infrastructure', 'Dependency', 'Secret'],
                  colors=['#ff9999', '#66b3ff', '#99ff99'], alpha=0.85)
    
    ax.set_ylabel('Cumulative Security Debt')
    ax.set_title(f'Debt Composition: {repo_name}')
    ax.legend(loc='upper left')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, f"{prefix}_{safe_name}_stacked.png"), dpi=150)
    plt.close()

def plot_quality_vs_security(repo_df, repo_name, prefix):
    """The rigorous covariance plot (StDI vs Security Debt)"""
    safe_name = "".join([c for c in repo_name if c.isalpha() or c.isdigit()]).rstrip()
    fig, ax1 = plt.subplots(figsize=(12, 6))
    dates = repo_df['author_date']

    color1 = '#d62728' # Red for Security
    ax1.set_xlabel('Timeline')
    ax1.set_ylabel('Security Debt Score (Raw)', color=color1, fontweight='bold')
    ax1.step(dates, repo_df['security_debt_score'], color=color1, where='post', linewidth=2.5, label='Security Debt')
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.grid(True, alpha=0.2)

    ax2 = ax1.twinx()
    color2 = '#9467bd' # Purple for Structural Quality
    ax2.set_ylabel('Structural Debt Index (Data-Driven Z-Score)', color=color2, fontweight='bold')
    ax2.step(dates, repo_df['stdi'], color=color2, where='post', linewidth=2, linestyle='--', label='Structural Debt (StDI)')
    ax2.tick_params(axis='y', labelcolor=color2)

    plt.title(f'Quality vs Security Covariance: {repo_name}\n({prefix.replace("_", " ").title()})')
    
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, f"{prefix}_{safe_name}_covariance.png"), dpi=150)
    plt.close()

if __name__ == "__main__":
    analyze_rq3_visualization()