import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from scipy.stats import spearmanr
import os
import sys
import numpy as np

# --- CONFIGURAZIONE ---
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
OUTPUT_DIR = os.path.join('data', 'output', 'figures')

# Creazione cartella output
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data_robust(filepath):
    """Carica il CSV gestendo errori di parsing."""
    if not os.path.exists(filepath):
        print(f"ERRORE: Il file {filepath} non esiste.")
        sys.exit(1)
    try:
        df = pd.read_csv(filepath)
    except pd.errors.ParserError:
        try:
            df = pd.read_csv(filepath, sep=',', on_bad_lines='skip', engine='python')
        except Exception as e:
            print(f"Errore critico lettura CSV: {e}")
            sys.exit(1)
    return df

def analyze_rq1():
    print("--- RQ1: Correlation Analysis (Scientific Version) ---")
    
    # 1. Caricamento
    df = load_data_robust(INPUT_CSV)
    
    # 2. Pulizia e Conversione Numerica
    potential_numeric_cols = [
        'loc', 'num_resources', 'num_modules', 'num_variables', 'num_outputs',
        'num_providers', 'iac_mccabe_complexity', 'hard_coded_values',
        'comment_lines', 'internal_references', 'security_debt_score'
    ]
    
    existing_numeric_cols = [c for c in potential_numeric_cols if c in df.columns]
    for col in existing_numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')
            
    # Rimuoviamo righe con LOC=0 o senza punteggio di sicurezza
    df = df.dropna(subset=['loc', 'security_debt_score'])
    df = df[df['loc'] > 0]

    # ---------------------------------------------------------
    # 3. FILTRO CRUCIALE: Unique Code States per Repository
    # Rimuoviamo i duplicati temporali dove nulla è cambiato.
    # Se il codice è identico, non è una nuova informazione per la correlazione.
    # ---------------------------------------------------------
    subset_for_uniqueness = ['repo_name', 'loc', 'num_resources', 'iac_mccabe_complexity', 'security_debt_score']
    # Aggiungiamo altre colonne se esistono
    if 'num_variables' in df.columns: subset_for_uniqueness.append('num_variables')
    
    df_unique = df.drop_duplicates(subset=subset_for_uniqueness)
    
    print(f"Snapshot totali nel CSV: {len(df)}")
    print(f"Snapshot unici (stati del codice distinti): {len(df_unique)}")
    print(f"Righe ridondanti rimosse: {len(df) - len(df_unique)}")

    # 4. Normalizzazione (Density Metrics)
    # Calcoliamo le densità sul dataset pulito
    df_unique = df_unique.copy() # Evita SettingWithCopyWarning
    df_unique['sec_debt_density'] = df_unique['security_debt_score'] / df_unique['loc']
    
    if 'iac_mccabe_complexity' in df_unique.columns:
        df_unique['complexity_density'] = df_unique['iac_mccabe_complexity'] / df_unique['loc']
        
    if 'hard_coded_values' in df_unique.columns:
        df_unique['hard_coded_density'] = df_unique['hard_coded_values'] / df_unique['loc']

    # 5. Definizione Variabili
    quality_metrics_candidates = [
        'loc', 'num_resources', 'num_modules', 'iac_mccabe_complexity',
        'complexity_density', 'num_providers', 'hard_coded_values',
        'hard_coded_density', 'num_variables', 'num_outputs'
    ]
    quality_metrics = [m for m in quality_metrics_candidates if m in df_unique.columns]
    target = 'security_debt_score'

    # 6. Calcolo Correlazione di Spearman
    results = []
    for metric in quality_metrics:
        # Spearman tra metrica di qualità e debito di sicurezza
        corr, p_value = spearmanr(df_unique[metric], df_unique[target])
        
        results.append({
            'Quality Metric': metric,
            'Spearman Coeff': round(corr, 3),
            'P-Value': p_value,
            'Significant': 'YES' if p_value < 0.05 else 'NO'
        })
        
        # Correlazione anche con la densità (ancora più rigoroso)
        corr_d, p_d = spearmanr(df_unique[metric], df_unique['sec_debt_density'])
        results.append({
            'Quality Metric': f"{metric} (vs Density)",
            'Spearman Coeff': round(corr_d, 3),
            'P-Value': p_d,
            'Significant': 'YES' if p_d < 0.05 else 'NO'
        })

    results_df = pd.DataFrame(results)
    stats_path = os.path.join(OUTPUT_DIR, 'rq1_statistics_clean.csv')
    results_df.to_csv(stats_path, index=False)

    print("\n--- Top Correlations (Unique States Only) ---")
    print(results_df.sort_values(by='Spearman Coeff', ascending=False).head(10).to_string(index=False))

    # 7. Heatmap
    cols_for_heatmap = quality_metrics + [target, 'sec_debt_density']
    plt.figure(figsize=(14, 12))
    # Usiamo solo le colonne esistenti
    cols_present = [c for c in cols_for_heatmap if c in df_unique.columns]
    corr_matrix = df_unique[cols_present].corr(method='spearman')
    
    sns.heatmap(
        corr_matrix, 
        annot=True, 
        cmap='coolwarm', 
        center=0,
        fmt='.2f',
        linewidths=.5,
        annot_kws={"size": 10}
    )
    plt.title('RQ1: Spearman Correlation Matrix (Unique Code States Only)')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq1_heatmap_unique.png'), dpi=300)
    print(f"\nAnalisi completata. Risultati salvati in {OUTPUT_DIR}")

if __name__ == "__main__":
    analyze_rq1()