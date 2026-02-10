import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
import os
import sys
import pymannkendall as mk

# --- CONFIGURAZIONE ---
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
IMPORTANCE_CSV = os.path.join('data', 'output', 'figures', 'rq2_feature_importance.csv')
OUTPUT_DIR = os.path.join('data', 'output', 'figures')
MIN_CHANGES = 2
TOP_N_CASES = 5

os.makedirs(OUTPUT_DIR, exist_ok=True)

def analyze_rq3_quality_vs_security():
    print("--- RQ3: Quality Debt vs Security Debt Evolution (Data-Driven) ---")
    
    # 1. Caricamento Dati e Pesi
    if not os.path.exists(IMPORTANCE_CSV):
        print(f"ERRORE: Devi prima eseguire rq2_prediction.py!")
        return
        
    df = pd.read_csv(INPUT_CSV)
    importance_df = pd.read_csv(IMPORTANCE_CSV)
    weights = dict(zip(importance_df['Feature'], importance_df['Importance']))
    
    # 2. Preparazione Dati
    df['author_date'] = pd.to_datetime(df['author_date'], utc=True, errors='coerce')
    df = df.dropna(subset=['author_date', 'loc', 'security_debt_score'])
    df = df[df['loc'] > 0].copy()
    
    # Calcolo densità
    if 'iac_mccabe_complexity' in df.columns:
        df['complexity_density'] = df['iac_mccabe_complexity'] / df['loc']
    if 'hard_coded_values' in df.columns:
        df['hard_coded_density'] = df['hard_coded_values'] / df['loc']
    if 'comment_lines' in df.columns:
        df['comment_density'] = df['comment_lines'] / df['loc']
        
    df.fillna(0, inplace=True)

    # 3. Analisi Per-Repository
    all_repos_data = []
    
    for repo_name in df['repo_name'].unique():
        repo_df = df[df['repo_name'] == repo_name].copy()
        
        # Standardizzazione (Z-score) PER-REPOSITORY
        # Questo è il modo corretto di analizzare l'evoluzione interna
        features_to_scale = [f for f in weights.keys() if f in repo_df.columns]
        
        if len(repo_df) > 1: # StandardScaler ha bisogno di più di un punto
            scaler = StandardScaler()
            repo_df[features_to_scale] = scaler.fit_transform(repo_df[features_to_scale])
        
        # Calcolo StDI
        repo_df['stdi'] = 0.0
        for feature in features_to_scale:
            repo_df['stdi'] += repo_df[feature] * weights.get(feature, 0)
        
        # Salviamo i dati arricchiti
        all_repos_data.append(repo_df)

    if not all_repos_data:
        print("Nessun dato valido da analizzare.")
        return
        
    # Uniamo di nuovo tutto in un unico dataframe
    df_processed = pd.concat(all_repos_data)
    
    # 4. Calcolo Trend e Selezione Casi Studio (come in rq3_evolution.py)
    trend_results = []
    for repo in df_processed['repo_name'].unique():
        repo_df = df_processed[df_processed['repo_name'] == repo]
        if repo_df['stdi'].nunique() < MIN_CHANGES: continue
            
        try:
            # Mann-Kendall sul debito strutturale
            mk_res = mk.original_test(repo_df['stdi'])
            trend_results.append({
                'repo': repo,
                'stdi_trend': mk_res.trend,
                'p_value': mk_res.p,
                'slope': mk_res.slope,
                'changes_count': repo_df['loc'].nunique()
            })
        except: pass
    
    if not trend_results:
        print("Nessun trend calcolabile.")
        return

    trends_df = pd.DataFrame(trend_results)
    
    # 5. Selezione Intelligente dei Grafici da generare
    selected_repos = set()
    degrading = trends_df[(trends_df['stdi_trend'] == 'increasing') & (trends_df['p_value'] < 0.05)].sort_values('slope', ascending=False).head(TOP_N_CASES)
    improving = trends_df[(trends_df['stdi_trend'] == 'decreasing') & (trends_df['p_value'] < 0.05)].sort_values('slope', ascending=True).head(TOP_N_CASES)
    active = trends_df.sort_values('changes_count', ascending=False).head(TOP_N_CASES)
    selected_repos.update(degrading['repo'].tolist() + improving['repo'].tolist() + active['repo'].tolist())

    print(f"\nGenerazione grafici per {len(selected_repos)} casi studio selezionati...")
    
    # 6. Generazione Grafici
    for repo in selected_repos:
        repo_df_to_plot = df_processed[df_processed['repo_name'] == repo].sort_values('author_date')
        plot_rigorous_comparison(repo_df_to_plot, repo)

def plot_rigorous_comparison(repo_df, repo_name):
    """Grafico a doppio asse: Security vs Structural Debt."""
    safe_name = "".join([c for c in repo_name if c.isalpha() or c.isdigit()]).rstrip()
    
    fig, ax1 = plt.subplots(figsize=(12, 6))
    dates = repo_df['author_date']

    color1 = '#d62728'
    ax1.set_xlabel('Timeline')
    ax1.set_ylabel('Security Debt Score (Raw)', color=color1, fontweight='bold')
    ax1.step(dates, repo_df['security_debt_score'], color=color1, where='post', linewidth=2.5, label='Security Debt')
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.grid(True, alpha=0.2)

    ax2 = ax1.twinx()
    color2 = '#9467bd'
    ax2.set_ylabel('Structural Debt Index (Data-Driven Z-Score)', color=color2, fontweight='bold')
    ax2.step(dates, repo_df['stdi'], color=color2, where='post', linewidth=2, linestyle='--', label='Structural Debt')
    ax2.tick_params(axis='y', labelcolor=color2)

    plt.title(f'Evolutionary Covariance: {repo_name}\n(Structural Debt vs. Security Debt)')
    
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, f"rq3_quality_vs_security_{safe_name}.png"), dpi=150)
    plt.close()
    print(f"Grafico generato per: {repo_name}")

if __name__ == "__main__":
    analyze_rq3_quality_vs_security()