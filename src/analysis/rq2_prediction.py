import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_absolute_error
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

def analyze_rq2():
    print("--- RQ2: Prediction Analysis (Unique States Only) ---")
    
    # 1. Caricamento Dati
    df = load_data_robust(INPUT_CSV)
    
    # 2. Pulizia e Conversione Numerica
    potential_cols = [
        'loc', 'num_resources', 'num_modules', 'num_variables', 'num_outputs',
        'num_providers', 'iac_mccabe_complexity', 'hard_coded_values',
        'comment_lines', 'internal_references', 'security_debt_score'
    ]
    
    existing_cols = [c for c in potential_cols if c in df.columns]
    for col in existing_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    # Rimuoviamo righe non valide (LOC=0 o Security Debt mancante)
    df = df.dropna(subset=['loc', 'security_debt_score'])
    df = df[df['loc'] > 0]

    # 3. FILTRO UNIQUE STATES (Fondamentale per evitare overfitting)
    # Consideriamo solo i commit dove la struttura o la sicurezza sono cambiate realmente
    subset_for_uniqueness = ['repo_name', 'loc', 'num_resources', 'iac_mccabe_complexity', 'security_debt_score']
    # Aggiungiamo altre colonne se presenti
    if 'num_variables' in df.columns: subset_for_uniqueness.append('num_variables')
    
    df_unique = df.drop_duplicates(subset=subset_for_uniqueness).copy()
    
    print(f"Snapshot totali: {len(df)} -> Snapshot unici per il training: {len(df_unique)}")
    
    if len(df_unique) < 20:
        print("ERRORE: Dati insufficienti per il modello di Machine Learning.")
        return

    # 4. Feature Engineering (Densità)
    # Le densità sono predittori migliori dei valori assoluti
    if 'iac_mccabe_complexity' in df_unique.columns:
        df_unique['complexity_density'] = df_unique['iac_mccabe_complexity'] / df_unique['loc']
    if 'hard_coded_values' in df_unique.columns:
        df_unique['hard_coded_density'] = df_unique['hard_coded_values'] / df_unique['loc']
    if 'comment_lines' in df_unique.columns:
        df_unique['comment_density'] = df_unique['comment_lines'] / df_unique['loc']

    # 5. Selezione Feature (X) e Target (y)
    candidate_features = [
        'loc', 'num_resources', 'num_modules', 'num_variables',
        'num_outputs', 'num_providers', 'iac_mccabe_complexity', 
        'complexity_density', 'hard_coded_density', 'comment_density',
        'internal_references'
    ]
    features = [f for f in candidate_features if f in df_unique.columns]
    
    X = df_unique[features].fillna(0)
    y = df_unique['security_debt_score']

    # 6. Split Train/Test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 7. Addestramento Random Forest
    print(f"Addestramento modello sulle feature: {features}")
    rf = RandomForestRegressor(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)

    # 8. Valutazione e Performance
    y_pred = rf.predict(X_test)
    r2 = r2_score(y_test, y_pred)
    mae = mean_absolute_error(y_test, y_pred)
    
    print("\n--- Model Performance ---")
    print(f"R² Score: {r2:.3f}")
    print(f"MAE: {mae:.3f}")

    # 9. Feature Importance (Risposta alla RQ2)
    importances = pd.DataFrame({
        'Feature': features,
        'Importance': rf.feature_importances_
    }).sort_values(by='Importance', ascending=False)

    print("\n--- Feature Importance Ranking ---")
    print(importances.to_string(index=False))
    importances.to_csv(os.path.join(OUTPUT_DIR, 'rq2_feature_importance.csv'), index=False)

    # 10. Visualizzazione Importanza
    plt.figure(figsize=(10, 6))
    sns.barplot(x='Importance', y='Feature', data=importances, palette='magma', hue='Feature', legend=False)
    plt.title('RQ2: Best Predictors for Security Debt\n(Random Forest Importance)')
    plt.xlabel('Importance Score (0-1)')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq2_importance.png'), dpi=300)

    # 11. Plot Actual vs Predicted
    plt.figure(figsize=(8, 8))
    plt.scatter(y_test, y_pred, alpha=0.6, edgecolors='w')
    plt.plot([y.min(), y.max()], [y.min(), y.max()], 'r--', lw=2)
    plt.xlabel('Actual Security Debt')
    plt.ylabel('Predicted Security Debt')
    plt.title('Model Accuracy: Actual vs Predicted')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq2_accuracy_scatter.png'), dpi=300)

    print(f"\nAnalisi completata. Grafici salvati in {OUTPUT_DIR}")

if __name__ == "__main__":
    analyze_rq2()