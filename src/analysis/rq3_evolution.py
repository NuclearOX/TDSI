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
# Consideriamo repo con almeno 3 cambiamenti reali (non solo 3 snapshot uguali)
MIN_CHANGES = 2 

os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data_robust(filepath):
    if not os.path.exists(filepath):
        print(f"ERRORE: File {filepath} non trovato.")
        sys.exit(1)
    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        df = pd.read_csv(filepath, sep=',', on_bad_lines='skip', engine='python')
    return df

def analyze_rq3():
    print("--- RQ3: Evolutionary Analysis (Step-Change Approach) ---")
    
    df = load_data_robust(INPUT_CSV)
    
    # 1. Preparazione Dati
    df['author_date'] = pd.to_datetime(df['author_date'], utc=True, errors='coerce')
    df = df.dropna(subset=['author_date'])
    
    numeric_cols = ['loc', 'security_debt_score', 'iac_mccabe_complexity', 
                    'infrastructure_debt', 'dependency_debt', 'secret_debt']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    df = df[df['loc'] > 0]
    # Calcolo densità di debito (fondamentale per l'evoluzione)
    df['debt_density'] = df['security_debt_score'] / df['loc']

    trend_results = []
    
    # 2. Analisi per singolo Repository
    for repo in df['repo_name'].unique():
        repo_df = df[df['repo_name'] == repo].sort_values('author_date')
        
        # Filtriamo per "Cambiamenti Reali": teniamo solo le righe dove 
        # LOC o Security Debt sono diversi dalla riga precedente
        repo_diff = repo_df[(repo_df['loc'].diff() != 0) | 
                            (repo_df['security_debt_score'].diff() != 0)].copy()
        
        if len(repo_diff) < MIN_CHANGES:
            print(f"Repo {repo}: Solo {len(repo_diff)} cambiamenti reali. Salto l'analisi del trend.")
            continue

        print(f"Analizzando evoluzione di {repo} ({len(repo_diff)} cambiamenti strutturali)...")

        # 3. Test di Mann-Kendall sulla Densità di Debito
        try:
            # MK test ci dice se la qualità sta migliorando o peggiorando nel tempo
            mk_res = mk.original_test(repo_df['debt_density'])
            trend_results.append({
                'repo': repo,
                'trend': mk_res.trend,
                'p_value': mk_res.p,
                'slope': mk_res.slope,
                'changes_count': len(repo_diff)
            })
        except:
            pass
            
        # 4. Generazione Grafico Evolutivo
        plot_evolution_step(repo_df, repo)

    # 5. Report Finale Trend
    if trend_results:
        trends_df = pd.DataFrame(trend_results)
        print("\n--- Riepilogo Trend Evolutivi (Densità del Debito) ---")
        print(trends_df[['repo', 'trend', 'p_value']].to_string(index=False))
        trends_df.to_csv(os.path.join(OUTPUT_DIR, 'rq3_trends_summary.csv'), index=False)
    else:
        print("\nNessun trend calcolabile con i criteri attuali.")

def plot_evolution_step(repo_df, repo_name):
    """
    Crea un grafico a scalini per mostrare l'evoluzione del debito rispetto alla crescita.
    """
    safe_name = "".join([c for c in repo_name if c.isalpha() or c.isdigit()]).rstrip()
    
    fig, ax1 = plt.subplots(figsize=(12, 6))
    
    # Timeline
    x = repo_df['author_date']
    
    # Asse 1: Crescita (LOC) - Area riempita
    ax1.fill_between(x, repo_df['loc'], color="skyblue", alpha=0.3, label='Lines of Code (Growth)')
    ax1.set_ylabel('Lines of Code (LOC)', color='steelblue', fontweight='bold')
    ax1.tick_params(axis='y', labelcolor='steelblue')
    
    # Asse 2: Debito (Step Plot) - Linea rossa a scalini
    ax2 = ax1.twinx()
    ax2.step(x, repo_df['security_debt_score'], color='red', where='post', linewidth=2, label='Security Debt (Evolution)')
    ax2.set_ylabel('Security Debt Score', color='red', fontweight='bold')
    ax2.tick_params(axis='y', labelcolor='red')

    # Titolo e Legenda
    plt.title(f'Evolutionary Dynamics: {repo_name}\nCode Growth vs. Security Debt accumulation', fontsize=14)
    ax1.grid(True, alpha=0.2)
    
    # Uniamo le legende
    lines, labels = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax2.legend(lines + lines2, labels + labels2, loc='upper left')

    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, f"rq3_step_evolution_{safe_name}.png"), dpi=300)
    plt.close()

if __name__ == "__main__":
    analyze_rq3()