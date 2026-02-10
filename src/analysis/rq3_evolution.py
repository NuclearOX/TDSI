import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import pymannkendall as mk
import os
import sys
import numpy as np

# --- CONFIGURATION ---
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
OUTPUT_DIR = os.path.join('data', 'output', 'figures')
MIN_CHANGES = 2  # Min changes to be considered for trends
TOP_N_CASES = 5  # How many case studies to plot per category

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

def analyze_rq3():
    print("--- RQ3: Evolutionary Analysis (Selective Plotting) ---")
    
    df = load_data_robust(INPUT_CSV)
    
    # 1. Data Pre-processing
    df['author_date'] = pd.to_datetime(df['author_date'], utc=True, errors='coerce')
    df = df.dropna(subset=['author_date'])
    
    numeric_cols = ['loc', 'security_debt_score', 'infrastructure_debt', 'dependency_debt', 'secret_debt', 'iac_mccabe_complexity']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    df = df[df['loc'] > 0]
    
    # Calculate Debt Density
    df['debt_density'] = df['security_debt_score'] / df['loc']

    trend_results = []
    
    unique_repos = df['repo_name'].unique()
    print(f"Calculating trends for {len(unique_repos)} repositories...")
    
    # 2. Statistical Analysis (Run on ALL repos)
    for repo in unique_repos:
        repo_df = df[df['repo_name'] == repo].sort_values('author_date')
        
        # Filter for actual changes
        repo_diff = repo_df[(repo_df['loc'].diff() != 0) | 
                            (repo_df['security_debt_score'].diff() != 0)].copy()
        
        changes_count = len(repo_diff)
        
        if changes_count < MIN_CHANGES:
            continue

        # Mann-Kendall Test
        try:
            mk_res = mk.original_test(repo_df['debt_density'])
            trend_val = mk_res.trend
            p_val = mk_res.p
            slope = mk_res.slope
        except:
            trend_val = 'insufficient_data'
            p_val = 1.0
            slope = 0.0
            
        trend_results.append({
            'repo': repo,
            'debt_density_trend': trend_val,
            'p_value': p_val,
            'slope': slope,
            'changes_count': changes_count
        })

    if not trend_results:
        print("No valid trends found.")
        return

    trends_df = pd.DataFrame(trend_results)
    
    # Save Global Statistics
    print("\n--- Global Trend Summary ---")
    print(trends_df['debt_density_trend'].value_counts())
    trends_df.to_csv(os.path.join(OUTPUT_DIR, 'rq3_trends_summary.csv'), index=False)
    plot_trend_summary(trends_df)

    # 3. Intelligent Selection (Filtering interesting cases)
    print(f"\n--- Selecting Top {TOP_N_CASES} Case Studies per category ---")
    
    selected_repos = set()

    # A. Worst Degradation (Highest positive slope, Significant)
    degrading = trends_df[
        (trends_df['debt_density_trend'] == 'increasing') & 
        (trends_df['p_value'] < 0.05)
    ].sort_values(by='slope', ascending=False).head(TOP_N_CASES)
    selected_repos.update(degrading['repo'].tolist())
    print(f"Degrading Cases: {degrading['repo'].tolist()}")

    # B. Best Improvement (Lowest negative slope, Significant)
    improving = trends_df[
        (trends_df['debt_density_trend'] == 'decreasing') & 
        (trends_df['p_value'] < 0.05)
    ].sort_values(by='slope', ascending=True).head(TOP_N_CASES)
    selected_repos.update(improving['repo'].tolist())
    print(f"Improving Cases: {improving['repo'].tolist()}")

    # C. Most Active (Most changes, regardless of trend)
    active = trends_df.sort_values(by='changes_count', ascending=False).head(TOP_N_CASES)
    selected_repos.update(active['repo'].tolist())
    print(f"Most Active Cases: {active['repo'].tolist()}")

    # 4. Visualization (Plot ONLY selected repos)
    print(f"\nGenerating plots for {len(selected_repos)} selected repositories...")
    
    for repo in selected_repos:
        repo_df = df[df['repo_name'] == repo].sort_values('author_date')
        plot_evolution_step(repo_df, repo)
        plot_evolution_stacked(repo_df, repo)

def plot_evolution_step(repo_df, repo_name):
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

    plt.title(f'Evolutionary Dynamics: {repo_name}\n(Code Growth vs Security Debt)', fontsize=14)
    lines, labels = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax2.legend(lines + lines2, labels + labels2, loc='upper left')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, f"rq3_step_{safe_name}.png"), dpi=150)
    plt.close()

def plot_evolution_stacked(repo_df, repo_name):
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
    ax.set_title(f'Security Debt Composition: {repo_name}')
    ax.legend(loc='upper left')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, f"rq3_stacked_{safe_name}.png"), dpi=150)
    plt.close()

def plot_trend_summary(trends_df):
    if 'debt_density_trend' not in trends_df.columns: return
    counts = trends_df['debt_density_trend'].value_counts()
    colors_map = {'decreasing': '#2ca02c', 'increasing': '#d62728', 'no trend': '#7f7f7f', 'stable': '#c7c7c7'}
    colors = [colors_map.get(x, '#1f77b4') for x in counts.index]
    plt.figure(figsize=(7, 7))
    plt.pie(counts, labels=counts.index, autopct='%1.1f%%', colors=colors, startangle=140)
    plt.title('RQ3: Trend Distribution (Debt Density)')
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq3_trend_distribution_pie.png'))
    plt.close()

if __name__ == "__main__":
    analyze_rq3()