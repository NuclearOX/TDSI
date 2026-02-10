import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_absolute_error, mean_squared_error
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
        print("Errore di parsing standard. Tentativo con engine python...")
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
    print(f"Snapshot totali caricati: {len(df)}")

    # 2. Pulizia e Conversione Numerica
    potential_cols = [
        'loc', 'num_resources', 'num_modules', 'num_variables', 'num_outputs',
        'num_providers', 'iac_mccabe_complexity', 'hard_coded_values',
        'comment_lines', 'internal_references', 'security_debt_score'
    ]
    
    existing_cols = [c for c in potential_cols if c in df.columns]
    for col in existing_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    # Rimuoviamo righe inutilizzabili (NaN o LOC=0)
    df = df.dropna(subset=['loc', 'security_debt_score'])
    df = df[df['loc'] > 0]
    
    # Pulizia extra: Rimuoviamo infiniti (sicurezza matematica)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df = df.dropna(subset=existing_cols)

    # 3. FILTRO UNIQUE STATES (Cruciale per validità scientifica)
    # Evita il Data Leakage dovuto a snapshot identici consecutivi
    subset_for_uniqueness = ['repo_name', 'loc', 'num_resources', 'iac_mccabe_complexity', 'security_debt_score']
    if 'num_variables' in df.columns: subset_for_uniqueness.append('num_variables')
    
    df_unique = df.drop_duplicates(subset=subset_for_uniqueness).copy()
    
    print(f"Snapshot totali: {len(df)} -> Snapshot unici per il training: {len(df_unique)}")
    
    if len(df_unique) < 20:
        print("ERRORE: Dati insufficienti per il modello di Machine Learning.")
        return

    # 4. Feature Engineering (Densità)
    # Normalizziamo le metriche sulla dimensione del file (LOC)
    if 'iac_mccabe_complexity' in df_unique.columns:
        df_unique['complexity_density'] = df_unique['iac_mccabe_complexity'] / df_unique['loc']
    if 'hard_coded_values' in df_unique.columns:
        df_unique['hard_coded_density'] = df_unique['hard_coded_values'] / df_unique['loc']
    if 'comment_lines' in df_unique.columns:
        df_unique['comment_density'] = df_unique['comment_lines'] / df_unique['loc']
        
    # Ripuliamo eventuali NaN/Inf generati dalle divisioni
    df_unique.replace([np.inf, -np.inf], 0, inplace=True)
    df_unique.fillna(0, inplace=True)

    # 5. Selezione Feature (X) e Target (y)
    candidate_features = [
        'loc', 'num_resources', 'num_modules', 'num_variables',
        'num_outputs', 'num_providers', 'iac_mccabe_complexity', 
        'complexity_density', 'hard_coded_density', 'comment_density',
        'internal_references', 'hard_coded_values' # Includiamo anche il valore assoluto
    ]
    features = [f for f in candidate_features if f in df_unique.columns]
    
    print(f"Feature utilizzate ({len(features)}): {features}")
    
    X = df_unique[features]
    y = df_unique['security_debt_score']

    # 6. Split Train/Test
    # Random State 42 garantisce riproducibilità
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 7. Addestramento Random Forest
    print("Addestramento modello Random Forest...")
    rf = RandomForestRegressor(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)

    # 8. Valutazione e Performance
    y_pred = rf.predict(X_test)
    
    r2 = r2_score(y_test, y_pred)
    mae = mean_absolute_error(y_test, y_pred)
    mse = mean_squared_error(y_test, y_pred)
    
    print("\n--- Model Performance ---")
    print(f"R² Score: {r2:.3f} (Varianza spiegata dal modello)")
    print(f"MAE: {mae:.3f} (Errore Medio Assoluto)")
    print(f"MSE: {mse:.3f} (Errore Quadratico Medio)")

    # Salva performance su file
    with open(os.path.join(OUTPUT_DIR, 'rq2_model_performance.txt'), 'w') as f:
        f.write(f"R2 Score: {r2}\n")
        f.write(f"MAE: {mae}\n")
        f.write(f"MSE: {mse}\n")
        f.write(f"Features used: {features}\n")

    # 9. Feature Importance (Risposta alla RQ2)
    importances = pd.DataFrame({
        'Feature': features,
        'Importance': rf.feature_importances_
    }).sort_values(by='Importance', ascending=False)

    print("\n--- Feature Importance Ranking ---")
    print(importances.to_string(index=False))
    
    # Salvataggio CSV importanza (Cruciale per RQ3 Rigorous)
    importances.to_csv(os.path.join(OUTPUT_DIR, 'rq2_feature_importance.csv'), index=False)

    # 10. Visualizzazione Importanza
    plt.figure(figsize=(12, 6))
    sns.barplot(x='Importance', y='Feature', data=importances, palette='viridis', hue='Feature', legend=False)
    plt.title('RQ2: Best Predictors for Security Debt\n(Random Forest Feature Importance)')
    plt.xlabel('Importance Score (0-1)')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq2_importance.png'), dpi=300)

    # 11. Plot Actual vs Predicted (Validazione Visiva)
    plt.figure(figsize=(8, 8))
    plt.scatter(y_test, y_pred, alpha=0.5, edgecolor='k', s=30)
    
    # Linea di perfezione
    min_val = min(y_test.min(), y_pred.min())
    max_val = max(y_test.max(), y_pred.max())
    plt.plot([min_val, max_val], [min_val, max_val], 'r--', lw=2, label='Perfect Prediction')
    
    plt.xlabel('Actual Security Debt')
    plt.ylabel('Predicted Security Debt')
    plt.title('Model Accuracy: Actual vs Predicted')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq2_accuracy_scatter.png'), dpi=300)

    print(f"\nAnalisi completata. Grafici salvati in {OUTPUT_DIR}")

if __name__ == "__main__":
    analyze_rq2()