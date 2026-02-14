import pandas as pd
import numpy as np
import os
import json
from scipy.stats import spearmanr
try:
    import pymannkendall as mk
except ImportError:
    print("Please install pymannkendall: pip install pymannkendall")
    mk = None

# --- CONFIGURATION ---
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
IMPORTANCE_CSV = os.path.join('data', 'output', 'figures', 'rq2_feature_importance.csv')
OUTPUT_DIR = os.path.join('data', 'output', 'reports')
os.makedirs(OUTPUT_DIR, exist_ok=True)

def analyze_rq3_statistics():
    print("--- RQ3: Advanced Evolutionary & Statistical Analysis (Pattern Selection) ---")
    
    # 1. Load Data & Weights
    if not os.path.exists(INPUT_CSV) or not os.path.exists(IMPORTANCE_CSV):
        print("ERROR: Missing input files (dataset_final.csv or feature_importance.csv).")
        return

    df = pd.read_csv(INPUT_CSV)
    importance_df = pd.read_csv(IMPORTANCE_CSV)
    weights = dict(zip(importance_df['Feature'], importance_df['Importance']))

    # 2. Feature Engineering (Recreate Densities)
    df['loc'] = pd.to_numeric(df['loc'], errors='coerce').fillna(0)
    
    # Avoid division by zero
    def safe_div(a, b): return a / b if b > 0 else 0

    if 'iac_mccabe_complexity' in df.columns:
        df['complexity_density'] = df.apply(lambda x: safe_div(x['iac_mccabe_complexity'], x['loc']), axis=1)
    if 'hard_coded_values' in df.columns:
        df['hard_coded_density'] = df.apply(lambda x: safe_div(x['hard_coded_values'], x['loc']), axis=1)
    if 'comment_lines' in df.columns:
        df['comment_density'] = df.apply(lambda x: safe_div(x['comment_lines'], x['loc']), axis=1)

    df.replace([np.inf, -np.inf], 0, inplace=True)
    df.fillna(0, inplace=True)

    # 3. Filter: Unique Code States
    metrics = [m for m in weights.keys() if m in df.columns]
    df = df.sort_values(by=['repo_name', 'author_date'])
    df_unique = df.drop_duplicates(subset=['repo_name'] + metrics + ['security_debt_score']).copy()

    results = []
    
    # 4. Analyze per Repository
    for repo, group in df_unique.groupby('repo_name'):
        if group['security_debt_score'].max() == 0:
            continue    
        
        if len(group) < 15: # Strict threshold for case studies (Scientific Rigor)
            continue
            
        # A. Calculate StDI (Structural Debt Index)
        stdi_series = np.zeros(len(group))
        for feature, weight in weights.items():
            if feature in group.columns:
                vals = group[feature].values
                std = vals.std()
                z_score = (vals - vals.mean()) / std if std > 0 else 0
                stdi_series += z_score * weight
        
        # B. Mann-Kendall Trend Test
        sdi_series = group['security_debt_score'].values
        loc_series = group['loc'].values
        
        trend_label = "no trend"
        if mk:
            try:
                trend_res = mk.original_test(sdi_series)
                trend_label = trend_res.trend
            except: pass

        # C. Longitudinal Correlation
        corr, _ = spearmanr(stdi_series, sdi_series)
        if np.isnan(corr): corr = 0

        # D. Pattern Identification 
        pattern = "Indeterminate"
        
        # Virtuous Refactoring: LOC decreases, Security Debt decreases
        if loc_series[-1] < loc_series[0] and sdi_series[-1] < sdi_series[0]:
            pattern = "Virtuous Refactoring"
        # Chaotic Entropy: High variance relative to mean
        elif np.mean(sdi_series) > 0 and (np.std(sdi_series) / np.mean(sdi_series)) > 0.5:
            pattern = "Chaotic Entropy"
        # Latent Risk: LOC grows, Debt explodes (final debt > 3x initial)
        elif loc_series[-1] > loc_series[0] * 1.5 and sdi_series[-1] > sdi_series[0] * 3:
            pattern = "Latent Risk"
        # Industrial Stability: No significant trend
        elif trend_label == "no trend":
            pattern = "Industrial Stability"

        results.append({
            'repo': repo,
            'snapshots': len(group),
            'trend': trend_label,
            'spearman_corr': corr,
            'pattern': pattern,
            'abs_corr': abs(corr) # Helper for sorting
        })

    if not results:
        print("No valid repositories found for analysis.")
        return

    # 5. Save Detailed Results
    res_df = pd.DataFrame(results)
    res_df.to_csv(os.path.join(OUTPUT_DIR, 'rq3_detailed_results.csv'), index=False)
    
    # 6. AUTOMATED SELECTION STRATEGY
    print("\n--- Selecting Case Studies (Stratified Sampling) ---")
    selected_repos = {}
    target_patterns = ['Virtuous Refactoring', 'Latent Risk', 'Chaotic Entropy', 'Industrial Stability']
    
    for p in target_patterns:
        candidates = res_df[res_df['pattern'] == p]
        if p == 'Industrial Stability':
            best = candidates.sort_values(by=['snapshots'], ascending=False).head(2)
        else:
            best = candidates.sort_values(by=['abs_corr', 'snapshots'], ascending=False).head(2)
            
        repo_list = best['repo'].tolist()
        selected_repos[p] = repo_list
        print(f"Selected for {p}: {repo_list}")

    with open(os.path.join(OUTPUT_DIR, 'selected_cases.json'), 'w') as f:
        json.dump(selected_repos, f, indent=4)

    # 7. GENERAZIONE RIASSUNTO NUMERICO (Aggiunto)
    print("\n--- Generating Numerical Summary ---")
    summary_path = os.path.join(OUTPUT_DIR, 'rq3_numerical_summary.txt')
    with open(summary_path, 'w') as f:
        f.write("=== RQ3 EVOLUTIONARY ANALYSIS SUMMARY ===\n\n")
        f.write(f"Repository analizzati (con >15 snapshot e debito > 0): {len(res_df)}\n\n")
        
        f.write("1. DISTRIBUZIONE DEI TREND (Mann-Kendall):\n")
        # Calcolo percentuali trend
        trend_counts = res_df['trend'].value_counts(normalize=True) * 100
        f.write(trend_counts.to_string() + "\n\n")
        
        f.write("2. CORRELAZIONE STRUTTURA-SICUREZZA (Media Spearman):\n")
        f.write(f"Rho medio: {res_df['spearman_corr'].mean():.3f}\n\n")
        
        f.write("3. CLASSIFICAZIONE DEGLI ARCHETIPI EVOLUTIVI:\n")
        pattern_counts = res_df['pattern'].value_counts()
        f.write(pattern_counts.to_string() + "\n")
    
    print(f"Summary saved to: {summary_path}")
    print(f"Selection complete. List saved to: {os.path.join(OUTPUT_DIR, 'selected_cases.json')}")

if __name__ == "__main__":
    analyze_rq3_statistics()