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
    """Carica il CSV gestendo errori di parsing (copiato da RQ1 per coerenza)."""
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
    print("--- RQ2: Prediction Analysis (Random Forest) ---")
    
    # 1. Caricamento Dati
    df = load_data_robust(INPUT_CSV)
    print(f"Snapshot totali caricati: {len(df)}")

    # 2. Pulizia e Conversione Numerica
    # Definiamo tutte le colonne che ci potrebbero servire
    potential_cols = [
        'loc', 'num_resources', 'num_modules', 'num_variables', 'num_outputs',
        'num_providers', 'iac_mccabe_complexity', 'hard_coded_values',
        'comment_lines', 'internal_references', 'security_debt_score'
    ]
    
    # Convertiamo in numeri solo quelle presenti
    existing_cols = [c for c in potential_cols if c in df.columns]
    for col in existing_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    # Rimuoviamo righe inutilizzabili (NaN o LOC=0)
    if 'loc' not in df.columns or 'security_debt_score' not in df.columns:
        print("ERRORE: Colonne fondamentali mancanti (loc o security_debt_score).")
        return

    df_clean = df.dropna(subset=existing_cols)
    df_clean = df_clean[df_clean['loc'] > 0]
    
    print(f"Dati validi per il training: {len(df_clean)}")
    
    if len(df_clean) < 50:
        print("ATTENZIONE: Pochi dati per un modello ML affidabile (<50). I risultati potrebbero essere instabili.")

    # 3. Feature Engineering (Creazione Metriche Derivate)
    # Creiamo le densità se le colonne base esistono
    
    # Complexity Density
    if 'iac_mccabe_complexity' in df_clean.columns:
        df_clean['complexity_density'] = df_clean['iac_mccabe_complexity'] / df_clean['loc']
    
    # Hard-coded Density
    if 'hard_coded_values' in df_clean.columns:
        df_clean['hard_coded_density'] = df_clean['hard_coded_values'] / df_clean['loc']
        
    # Comment Density
    if 'comment_lines' in df_clean.columns:
        df_clean['comment_density'] = df_clean['comment_lines'] / df_clean['loc']

    # 4. Selezione delle Feature (X) e del Target (y)
    # Elenco di possibili predittori (sia grezzi che densità)
    candidate_features = [
        'loc', 
        'num_resources', 
        'num_modules', 
        'num_variables',
        'num_outputs',
        'num_providers', 
        'iac_mccabe_complexity', 
        'complexity_density',
        'hard_coded_values',
        'hard_coded_density',
        'comment_density',
        'internal_references'
    ]
    
    # Selezioniamo solo le feature che esistono davvero nel dataframe
    features = [f for f in candidate_features if f in df_clean.columns]
    
    print(f"Feature utilizzate per la predizione: {features}")
    
    if not features:
        print("Nessuna feature valida trovata.")
        return

    X = df_clean[features]
    y = df_clean['security_debt_score']

    # 5. Split Train/Test
    # Usiamo random_state fisso per riproducibilità (importante per la tesi)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 6. Addestramento Modello
    print("Addestramento Random Forest...")
    rf = RandomForestRegressor(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)

    # 7. Valutazione
    y_pred = rf.predict(X_test)
    
    r2 = r2_score(y_test, y_pred)
    mae = mean_absolute_error(y_test, y_pred)
    mse = mean_squared_error(y_test, y_pred)
    
    print("\n--- Performance del Modello ---")
    print(f"R² Score: {r2:.3f}")
    print(f"  -> Interpretazione: Il modello spiega il {r2*100:.1f}% della varianza del Security Debt.")
    print(f"MAE (Mean Absolute Error): {mae:.3f}")
    print(f"  -> Interpretazione: In media, il modello sbaglia la previsione del debito di {mae:.3f} punti.")

    # Salva performance su file
    with open(os.path.join(OUTPUT_DIR, 'rq2_model_performance.txt'), 'w') as f:
        f.write(f"R2 Score: {r2}\n")
        f.write(f"MAE: {mae}\n")
        f.write(f"MSE: {mse}\n")
        f.write(f"Features used: {features}\n")

    # 8. Feature Importance (Il cuore della RQ2)
    importances = pd.DataFrame({
        'Feature': features,
        'Importance': rf.feature_importances_
    }).sort_values(by='Importance', ascending=False)

    print("\n--- Feature Importance (Top Predictors) ---")
    print(importances.to_string(index=False))
    
    # Salvataggio CSV importanza
    importances.to_csv(os.path.join(OUTPUT_DIR, 'rq2_feature_importance.csv'), index=False)

    # 9. Visualizzazione
    plt.figure(figsize=(10, 6))
    sns.barplot(x='Importance', y='Feature', data=importances, palette='viridis', hue='Feature', legend=False)
    plt.title('RQ2: Feature Importance for Predicting Security Debt\n(Random Forest)')
    plt.xlabel('Importance (0-1)')
    plt.ylabel('Structural Quality Metric')
    plt.tight_layout()
    
    img_path = os.path.join(OUTPUT_DIR, 'rq2_feature_importance.png')
    plt.savefig(img_path, dpi=300)
    print(f"\nGrafico salvato in: {img_path}")

    # 10. Scatter Plot: Actual vs Predicted (Per vedere quanto è bravo il modello)
    plt.figure(figsize=(8, 8))
    plt.scatter(y_test, y_pred, alpha=0.5)
    
    # Linea di perfezione
    max_val = max(y_test.max(), y_pred.max())
    plt.plot([0, max_val], [0, max_val], color='red', linestyle='--')
    
    plt.xlabel('Actual Security Debt')
    plt.ylabel('Predicted Security Debt')
    plt.title('Model Accuracy: Actual vs Predicted')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq2_prediction_scatter.png'))

if __name__ == "__main__":
    analyze_rq2()