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

# Creazione cartella output se non esiste
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data_robust(filepath):
    """Carica il CSV gestendo errori di parsing."""
    if not os.path.exists(filepath):
        print(f"ERRORE: Il file {filepath} non esiste.")
        sys.exit(1)

    try:
        df = pd.read_csv(filepath)
    except pd.errors.ParserError:
        print("Errore di parsing standard. Tentativo con engine python e skip bad lines...")
        try:
            df = pd.read_csv(filepath, sep=',', on_bad_lines='skip', engine='python')
        except Exception as e:
            print(f"Errore critico lettura CSV: {e}")
            sys.exit(1)
    return df

def analyze_rq1():
    print("--- RQ1: Correlation Analysis ---")
    
    # 1. Caricamento
    df = load_data_robust(INPUT_CSV)
    print(f"Colonne trovate nel CSV: {list(df.columns)}")
    
    # 2. Pulizia
    # Elenco di TUTTE le possibili colonne numeriche che potremmo voler analizzare
    potential_numeric_cols = [
        'loc', 'num_resources', 'num_modules', 'num_variables', 'num_outputs',
        'num_providers', 'iac_mccabe_complexity', 'hard_coded_values',
        'comment_lines', 'internal_references', 'security_debt_score'
    ]
    
    # Identifichiamo quali esistono davvero nel tuo CSV
    existing_numeric_cols = [c for c in potential_numeric_cols if c in df.columns]
    
    # Convertiamo in numeri
    for col in existing_numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')
            
    # Rimuoviamo righe non valide
    if 'loc' in df.columns and 'security_debt_score' in df.columns:
        df_clean = df.dropna(subset=['loc', 'security_debt_score'])
        df_clean = df_clean[df_clean['loc'] > 0]
    else:
        print("ERRORE: Colonne 'loc' o 'security_debt_score' mancanti. Impossibile procedere.")
        return

    print(f"Snapshot validi: {len(df_clean)}")

    # 3. Normalizzazione (Density Metrics) - Solo se le colonne esistono
    # Calcoliamo le densità solo per le metriche che abbiamo
    if 'security_debt_score' in df_clean.columns:
        df_clean['sec_debt_density'] = df_clean['security_debt_score'] / df_clean['loc']
        
    if 'iac_mccabe_complexity' in df_clean.columns:
        df_clean['complexity_density'] = df_clean['iac_mccabe_complexity'] / df_clean['loc']
        
    if 'hard_coded_values' in df_clean.columns:
        df_clean['hard_coded_density'] = df_clean['hard_coded_values'] / df_clean['loc']
        
    if 'comment_lines' in df_clean.columns:
        df_clean['comment_density'] = df_clean['comment_lines'] / df_clean['loc']

    # 4. Definizione Variabili per Correlazione
    # Costruiamo la lista delle metriche di qualità disponibili
    quality_metrics_candidates = [
        'loc', 'num_resources', 'num_modules', 'iac_mccabe_complexity',
        'complexity_density', 'num_providers', 'hard_coded_values',
        'hard_coded_density', 'comment_density', 'internal_references',
        'num_variables', 'num_outputs'
    ]
    
    # Filtriamo: teniamo solo quelle che esistono nel DataFrame pulito
    quality_metrics = [m for m in quality_metrics_candidates if m in df_clean.columns]
    
    print(f"Metriche di qualità disponibili per l'analisi: {quality_metrics}")

    if not quality_metrics:
        print("Nessuna metrica di qualità trovata. Controlla il CSV.")
        return

    # 5. Calcolo Correlazione
    results = []
    target = 'security_debt_score'
    
    for metric in quality_metrics:
        # Spearman
        corr, p_value = spearmanr(df_clean[metric], df_clean[target])
        
        results.append({
            'Target': 'Security Debt (Abs)',
            'Quality Metric': metric,
            'Spearman Coeff': round(corr, 3),
            'P-Value': p_value,
            'Significativo': 'SÌ' if p_value < 0.05 else 'NO'
        })
        
        # Se abbiamo calcolato la densità di sicurezza, correliamo anche con quella
        if 'sec_debt_density' in df_clean.columns:
             corr_dens, p_value_dens = spearmanr(df_clean[metric], df_clean['sec_debt_density'])
             results.append({
                'Target': 'Security Debt (Density)',
                'Quality Metric': metric,
                'Spearman Coeff': round(corr_dens, 3),
                'P-Value': p_value_dens,
                'Significativo': 'SÌ' if p_value_dens < 0.05 else 'NO'
            })

    # Output Risultati
    results_df = pd.DataFrame(results)
    stats_path = os.path.join(OUTPUT_DIR, 'rq1_statistics.csv')
    results_df.to_csv(stats_path, index=False)
    
    print("\n--- Risultati Principali (Top Correlazioni) ---")
    print(results_df.sort_values(by='Spearman Coeff', ascending=False).head(10).to_string(index=False))

    # 6. Heatmap
    # Selezioniamo per il grafico solo le colonne che esistono davvero
    cols_for_heatmap = quality_metrics + [target]
    if 'sec_debt_density' in df_clean.columns:
        cols_for_heatmap.append('sec_debt_density')
        
    plt.figure(figsize=(12, 10))
    corr_matrix = df_clean[cols_for_heatmap].corr(method='spearman')
    
    sns.heatmap(
        corr_matrix, 
        annot=True, 
        cmap='RdBu_r', 
        center=0,
        fmt='.2f',
        linewidths=.5
    )
    plt.title('RQ1: Spearman Correlation Matrix')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq1_heatmap.png'))
    print(f"\nGrafico salvato in {OUTPUT_DIR}")

if __name__ == "__main__":
    analyze_rq1()