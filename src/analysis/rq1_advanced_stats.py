import pandas as pd
import statsmodels.api as sm
from statsmodels.stats.outliers_influence import variance_inflation_factor
import os
import sys
import numpy as np

# Configurazione
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
OUTPUT_DIR = os.path.join('data', 'output', 'figures')

os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data():
    if not os.path.exists(INPUT_CSV):
        print(f"ERRORE: File {INPUT_CSV} non trovato.")
        sys.exit(1)
    try:
        df = pd.read_csv(INPUT_CSV)
    except:
        # Fallback engine per file con caratteri strani
        df = pd.read_csv(INPUT_CSV, sep=',', on_bad_lines='skip', engine='python')
    return df

def analyze_advanced_rq1():
    print("--- RQ1: Advanced Multivariate Analysis (OLS Regression & VIF) ---")
    
    df = load_data()
    print(f"Righe grezze caricate: {len(df)}")
    
    # 1. Pulizia e Preparazione
    # Includiamo TUTTE le metriche strutturali che il miner estrae ora
    numeric_cols = [
        'loc', 'num_resources', 'num_modules', 'num_providers', 
        'iac_mccabe_complexity', 'hard_coded_values', 'comment_lines',
        'internal_references', 'num_variables', 'num_outputs',
        'security_debt_score'
    ]
    
    # Filtriamo colonne esistenti e convertiamo in numeri
    cols = [c for c in numeric_cols if c in df.columns]
    for c in cols: 
        df[c] = pd.to_numeric(df[c], errors='coerce')
    
    # Rimuoviamo infiniti e NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df = df.dropna(subset=['loc', 'security_debt_score'])
    df = df[df['loc'] > 0].fillna(0)
    
    # Unique States Only (Il nostro standard di rigore)
    # Rimuoviamo duplicati esatti per non gonfiare la statistica
    df_unique = df.drop_duplicates(subset=['repo_name'] + cols).copy()
    
    print(f"Datapoints unici analizzati: {len(df_unique)}")

    if len(df_unique) < 10:
        print("Errore: Troppi pochi dati per la regressione.")
        return

    # 2. Selezione Predittori
    # Escludiamo il target (security_debt)
    predictors = [c for c in cols if c != 'security_debt_score']
    
    # --- CHECK VARIANZA ZERO ---
    # Se una colonna ha tutti i valori uguali (es. tutti 0), rompe la regressione.
    # La rimuoviamo.
    X_temp = df_unique[predictors]
    variance = X_temp.var()
    cols_to_drop = variance[variance == 0].index
    if not cols_to_drop.empty:
        print(f"ATTENZIONE: Rimosse colonne con varianza zero: {list(cols_to_drop)}")
        predictors = [p for p in predictors if p not in cols_to_drop]

    X = df_unique[predictors]
    X = sm.add_constant(X) # Aggiunge l'intercetta (beta0)

    # 3. Analisi VIF (Variance Inflation Factor)
    print("\n--- Analisi Multicollinearità (VIF) ---")
    try:
        vif_data = pd.DataFrame()
        vif_data["Feature"] = X.columns
        vif_data["VIF"] = [variance_inflation_factor(X.values, i) for i in range(X.shape[1])]
        
        print("Se VIF > 5, la variabile è ridondante (spiegata dalle altre).")
        print(vif_data.sort_values(by="VIF", ascending=False).to_string(index=False))
        vif_data.to_csv(os.path.join(OUTPUT_DIR, 'rq1_vif_analysis.csv'), index=False)
    except Exception as e:
        print(f"Impossibile calcolare VIF (possibile colinearità perfetta): {e}")

    # 4. Regressione Lineare Multipla (OLS)
    y = df_unique['security_debt_score']
    
    try:
        model = sm.OLS(y, X).fit()
        
        print("\n--- Risultati Regressione Multipla (OLS) ---")
        print(model.summary())
        
        # Salviamo il summary
        with open(os.path.join(OUTPUT_DIR, 'rq1_ols_regression_summary.txt'), 'w') as f:
            f.write(model.summary().as_text())

        # 5. Interpretazione Automatica
        print("\n--- INTERPRETAZIONE RAPIDA ---")
        print("Variabili statisticamente significative (P < 0.05):")
        significant = model.pvalues[model.pvalues < 0.05].index.tolist()
        for var in significant:
            coef = model.params[var]
            impact = "AUMENTA" if coef > 0 else "DIMINUISCE"
            print(f"  - {var}: {impact} il debito (Coef: {coef:.4f})")
            
    except Exception as e:
        print(f"Errore nel calcolo del modello OLS: {e}")

if __name__ == "__main__":
    analyze_advanced_rq1()