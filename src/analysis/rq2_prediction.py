import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split, cross_val_score, KFold
from sklearn.metrics import r2_score, mean_absolute_error, mean_squared_error
import os
import sys
import numpy as np

# --- CONFIGURAZIONE ---
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
OUTPUT_DIR = os.path.join('data', 'output', 'figures')

os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data_robust(filepath):
    if not os.path.exists(filepath):
        print(f"ERRORE: Il file {filepath} non esiste.")
        sys.exit(1)
    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        df = pd.read_csv(filepath, sep=',', on_bad_lines='skip', engine='python')
    return df

def analyze_rq2():
    print("--- RQ2: Advanced Prediction Analysis (Cross-Validation Enabled) ---")
    
    # 1. Caricamento e Pulizia
    df = load_data_robust(INPUT_CSV)
    
    potential_cols = [
        'loc', 'num_resources', 'num_modules', 'num_variables', 'num_outputs',
        'num_providers', 'iac_mccabe_complexity', 'hard_coded_values',
        'comment_lines', 'internal_references', 'security_debt_score'
    ]
    
    existing_cols = [c for c in potential_cols if c in df.columns]
    for col in existing_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df = df.dropna(subset=['loc', 'security_debt_score'])
    df = df[df['loc'] > 0]
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df = df.dropna(subset=existing_cols)

    # 2. FILTRO UNIQUE STATES (Prevenzione Data Leakage)
    subset_for_uniqueness = ['repo_name', 'loc', 'num_resources', 'iac_mccabe_complexity', 'security_debt_score']
    if 'num_variables' in df.columns: subset_for_uniqueness.append('num_variables')
    df_unique = df.drop_duplicates(subset=subset_for_uniqueness).copy()
    
    print(f"Snapshot caricati: {len(df)} -> Stati unici per ML: {len(df_unique)}")

    # 3. Feature Engineering (Densità)
    # Calcoliamo le densità per rendere le metriche indipendenti dalla dimensione del file
    if 'iac_mccabe_complexity' in df_unique.columns:
        df_unique['complexity_density'] = df_unique['iac_mccabe_complexity'] / df_unique['loc']
    if 'hard_coded_values' in df_unique.columns:
        df_unique['hard_coded_density'] = df_unique['hard_coded_values'] / df_unique['loc']
    if 'comment_lines' in df_unique.columns:
        df_unique['comment_density'] = df_unique['comment_lines'] / df_unique['loc']
        
    df_unique.replace([np.inf, -np.inf], 0, inplace=True)
    df_unique.fillna(0, inplace=True)

    # 4. Selezione Feature (X) e Target (y)
    candidate_features = [
        'loc', 'num_resources', 'num_modules', 'num_variables',
        'num_outputs', 'num_providers', 'iac_mccabe_complexity', 
        'complexity_density', 'hard_coded_density', 'comment_density',
        'internal_references', 'hard_coded_values'
    ]
    features = [f for f in candidate_features if f in df_unique.columns]
    
    X = df_unique[features]
    y = df_unique['security_debt_score']

    # 5. CROSS-VALIDATION (Il cuore della modifica)
    print(f"Esecuzione 5-Fold Cross-Validation...")
    rf = RandomForestRegressor(n_estimators=100, random_state=42, n_jobs=-1)
    
    # Utilizziamo K-Fold per calcolare la stabilità del modello
    kf = KFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(rf, X, y, cv=kf, scoring='r2')
    
    print(f"R² Scores per ogni Fold: {cv_scores}")
    print(f"R² Medio (CV): {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")

    # 6. Training Finale e Valutazione Classica (per i grafici)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)

    # 7. Salvataggio Performance Arricchito
    with open(os.path.join(OUTPUT_DIR, 'rq2_model_performance.txt'), 'w') as f:
        f.write("--- CROSS-VALIDATION RESULTS (5-FOLD) ---\n")
        f.write(f"R2 Mean: {cv_scores.mean()}\n")
        f.write(f"R2 Std Dev: {cv_scores.std()}\n")
        f.write("\n--- TEST SET EVALUATION ---\n")
        f.write(f"MAE: {mean_absolute_error(y_test, y_pred)}\n")
        f.write(f"MSE: {mean_squared_error(y_test, y_pred)}\n")

    # 8. Feature Importance (Fondamentale per la RQ3)
    importances = pd.DataFrame({
        'Feature': features,
        'Importance': rf.feature_importances_
    }).sort_values(by='Importance', ascending=False)
    
    importances.to_csv(os.path.join(OUTPUT_DIR, 'rq2_feature_importance.csv'), index=False)
    print("\nRanking Importanza Metriche salvato.")

    # 9. Visualizzazioni
    # Grafico Importanza
    plt.figure(figsize=(12, 6))
    sns.barplot(x='Importance', y='Feature', data=importances, palette='magma', hue='Feature', legend=False)
    plt.title('RQ2: Predictors of Security Debt (Feature Importance)')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq2_importance.png'), dpi=300)

    # Grafico Accuracy
    plt.figure(figsize=(8, 8))
    plt.scatter(y_test, y_pred, alpha=0.4, color='teal')
    plt.plot([y.min(), y.max()], [y.min(), y.max()], 'r--', lw=2)
    plt.xlabel('Actual Security Debt')
    plt.ylabel('Predicted Security Debt')
    plt.title(f'Prediction Accuracy (R² CV: {cv_scores.mean():.2f})')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq2_accuracy_scatter.png'), dpi=300)

if __name__ == "__main__":
    analyze_rq2()