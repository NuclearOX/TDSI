import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import pymannkendall as mk
import os
import sys
import numpy as np

# --- CONFIGURAZIONE ---
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
OUTPUT_DIR = os.path.join('data', 'output', 'figures')
MIN_SNAPSHOTS = 5

os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data_robust(filepath):
    if not os.path.exists(filepath):
        sys.exit(1)
    try:
        df = pd.read_csv(filepath)
    except pd.errors.ParserError:
        df = pd.read_csv(filepath, sep=',', on_bad_lines='skip', engine='python')
    return df

def analyze_rq3():
    print("--- RQ3: Advanced Evolution Analysis ---")
    
    df = load_data_robust(INPUT_CSV)
    
    # Pre-processing
    df['author_date'] = pd.to_datetime(df['author_date'], utc=True, errors='coerce')
    df = df.dropna(subset=['author_date'])
    
    numeric_cols = ['loc', 'security_debt_score', 'infrastructure_debt', 'dependency_debt', 'secret_debt']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    df = df[df['loc'] > 0]

    # Calcolo Densità
    df['debt_density'] = df['security_debt_score'] / df['loc']

    # Selezione Top Repo
    repo_counts = df['repo_name'].value_counts()
    valid_repos = repo_counts[repo_counts >= MIN_SNAPSHOTS].index.tolist()
    
    print(f"Analisi su {len(valid_repos)} repository.")

    # Analisi Trend (Mann-Kendall) su Densità (più interessante del valore assoluto)
    trend_results = []
    for repo in valid_repos:
        repo_df = df[df['repo_name'] == repo].sort_values('author_date')
        
        # Test su Densità
        try:
            mk_res = mk.original_test(repo_df['debt_density'])
            trend = mk_res.trend
        except:
            trend = 'error'
            
        trend_results.append({'repo': repo, 'density_trend': trend})
        
        # Generazione Grafici Avanzati
        plot_detailed_evolution(repo_df, repo)

    trends_df = pd.DataFrame(trend_results)
    print("\nTrend della Densità di Debito (Security Debt / LOC):")
    print(trends_df['density_trend'].value_counts())
    trends_df.to_csv(os.path.join(OUTPUT_DIR, 'rq3_density_trends.csv'), index=False)

def plot_detailed_evolution(repo_df, repo_name):
    """Genera 2 grafici: Stacked Area (Composizione Debito) e Density vs LOC."""
    safe_name = "".join([c for c in repo_name if c.isalpha() or c.isdigit() or c==' ']).rstrip()
    
    # --- GRAFICO 1: Composizione del Debito (Stacked Area) ---
    # Questo mostra se il tipo di problemi cambia nel tempo, anche se il totale è piatto
    plt.figure(figsize=(12, 6))
    
    # Creiamo asse temporale
    dates = repo_df['author_date']
    
    # Dati per lo stack
    infra = repo_df.get('infrastructure_debt', pd.Series(0, index=repo_df.index))
    deps = repo_df.get('dependency_debt', pd.Series(0, index=repo_df.index))
    secrets = repo_df.get('secret_debt', pd.Series(0, index=repo_df.index))
    
    plt.stackplot(dates, infra, deps, secrets, 
                  labels=['Infrastructure Debt', 'Dependency Debt', 'Secret Debt'],
                  colors=['#ff9999', '#66b3ff', '#99ff99'], alpha=0.8)
    
    plt.title(f'Evolution of Security Debt Composition: {repo_name}')
    plt.ylabel('Security Debt Score')
    plt.xlabel('Timeline')
    plt.legend(loc='upper left')
    plt.grid(True, alpha=0.3)
    
    plt.savefig(os.path.join(OUTPUT_DIR, f"rq3_composition_{safe_name}.png"))
    plt.close()

    # --- GRAFICO 2: Debito vs Dimensione (Density) ---
    # Questo mostra se il codice migliora (densità scende) mentre cresce
    fig, ax1 = plt.subplots(figsize=(12, 6))
    
    color = 'tab:blue'
    ax1.set_xlabel('Timeline')
    ax1.set_ylabel('Lines of Code (LOC)', color=color, fontweight='bold')
    ax1.plot(dates, repo_df['loc'], color=color, label='LOC', linewidth=2)
    ax1.tick_params(axis='y', labelcolor=color)
    
    ax2 = ax1.twinx()  
    color = 'tab:red'
    ax2.set_ylabel('Security Debt Density (Debt/LOC)', color=color, fontweight='bold')
    # Usa step per evidenziare i cambi di versione
    ax2.step(dates, repo_df['debt_density'], color=color, where='post', label='Debt Density')
    ax2.tick_params(axis='y', labelcolor=color)
    
    plt.title(f'Project Growth vs Security Quality: {repo_name}')
    fig.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, f"rq3_density_{safe_name}.png"))
    plt.close()

    print(f"Grafici generati per {repo_name}")

if __name__ == "__main__":
    analyze_rq3()