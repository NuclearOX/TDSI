# src/analysis/generate_animation_data.py
import pandas as pd
import os
import json
import logging

# Configurazione
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
OUTPUT_DIR = os.path.join('data', 'output')
OUTPUT_JSON = os.path.join(OUTPUT_DIR, 'animation_data.json')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def create_animation_data():
    """
    Prepares the dataset for the animated bubble chart.
    Groups data by year and prepares a JSON structure for Chart.js.
    """
    print("--- Generating Data for Animated Visualization ---")
    try:
        df = pd.read_csv(INPUT_CSV)
    except FileNotFoundError:
        print(f"ERROR: Dataset not found at {INPUT_CSV}. Run the mining process first.")
        return

    # 1. Pulizia e preparazione
    df['author_date'] = pd.to_datetime(df['author_date'], utc=True, errors='coerce')
    df.dropna(subset=['author_date', 'security_debt_score', 'loc'], inplace=True)
    df = df[df['loc'] > 0].copy()

    # Creiamo una colonna 'year'
    df['year'] = df['author_date'].dt.year

    # Creiamo lo Structural Debt Index (usando la formula rigorosa che avevamo discusso)
    features_for_stdi = [c for c in ['iac_mccabe_complexity', 'hard_coded_values', 'internal_references'] if c in df.columns]
    for col in features_for_stdi:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    
    # Pesi semplificati ma logici (puoi sostituirli con quelli del RF se vuoi)
    df['structural_debt_score'] = (
        df.get('iac_mccabe_complexity', 0) * 1.0 + 
        df.get('hard_coded_values', 0) * 5.0 + 
        df.get('internal_references', 0) * 0.5
    )

    # 2. Aggregazione: prendiamo l'ultimo stato di ogni repo per ogni anno
    # Questo evita di avere 100 punti per lo stesso repo nello stesso anno
    df_yearly = df.loc[df.groupby(['repo_name', 'year'])['author_date'].idxmax()]
    
    # 3. Preparazione JSON per Chart.js
    animation_data = {}
    
    # Normalizziamo la dimensione dei pallini (LOC) per una migliore visualizzazione
    min_loc, max_loc = df_yearly['loc'].min(), df_yearly['loc'].max()
    
    for year in sorted(df_yearly['year'].unique()):
        year_data = df_yearly[df_yearly['year'] == year]
        
        datasets = []
        # Ogni repo è un "dataset" diverso nel grafico
        for repo_name in year_data['repo_name'].unique():
            repo_snapshot = year_data[year_data['repo_name'] == repo_name]
            
            # Calcolo dimensione del pallino (radius)
            # Mappiamo LOC su una scala da 5 a 30 pixel
            radius = 5 + 25 * (repo_snapshot.iloc[0]['loc'] - min_loc) / (max_loc - min_loc)
            
            datasets.append({
                'label': repo_name,
                'data': [{
                    'x': repo_snapshot.iloc[0]['structural_debt_score'],
                    'y': repo_snapshot.iloc[0]['security_debt_score'],
                    'r': radius
                }]
            })
        
        animation_data[str(int(year))] = datasets

    # 4. Salvataggio
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(animation_data, f, indent=2)
        
    print(f"✅ Dati per l'animazione salvati in {OUTPUT_JSON}")

if __name__ == "__main__":
    create_animation_data()