import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import os
import sys

# --- CONFIGURAZIONE ---
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
OUTPUT_DIR = os.path.join('data', 'output', 'figures')

os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data_robust(filepath):
    """Carica il CSV gestendo errori di parsing."""
    if not os.path.exists(filepath):
        print(f"ERRORE: File {filepath} non trovato.")
        sys.exit(1)
    try:
        df = pd.read_csv(filepath)
    except Exception:
        df = pd.read_csv(filepath, sep=',', on_bad_lines='skip', engine='python')
    return df

def analyze_rq4_clustering():
    print("--- Unsupervised Analysis: Discovering Terraform Project Archetypes (K-Means) ---")
    
    # 1. Caricamento e Pulizia Dati
    df = load_data_robust(INPUT_CSV)
    
    # Definiamo le feature per il clustering
    features_for_clustering = [
        'loc', 'num_resources', 'num_modules', 'iac_mccabe_complexity',
        'hard_coded_values', 'security_debt_score', 'infrastructure_debt'
    ]
    features_exist = [f for f in features_for_clustering if f in df.columns]
    
    # Pulizia
    df = df.dropna(subset=features_exist)
    df = df[df['loc'] > 0]
    
    # Prendiamo solo l'ultimo snapshot per repo per clusterizzare i PROGETTI
    df['author_date'] = pd.to_datetime(df['author_date'], utc=True, errors='coerce')
    df_latest = df.sort_values('author_date').drop_duplicates('repo_name', keep='last')

    print(f"Clusterizzazione su {len(df_latest)} progetti unici.")
    
    if len(df_latest) < 10:
        print("Dati insufficienti per il clustering.")
        return

    # 2. Standardizzazione (Z-Score) - Fondamentale per K-Means
    scaler = StandardScaler()
    df_scaled = scaler.fit_transform(df_latest[features_exist])
    
    # 3. Trovare il K ottimale (Elbow Method)
    print("Calcolo K ottimale con Metodo del Gomito...")
    inertias = []
    k_range = range(1, 11)
    for k in k_range:
        kmeans = KMeans(n_clusters=k, random_state=42, n_init='auto').fit(df_scaled)
        inertias.append(kmeans.inertia_)
        
    plt.figure(figsize=(8, 5))
    plt.plot(k_range, inertias, marker='o', linestyle='--')
    plt.xlabel('Numero di Cluster (K)')
    plt.ylabel('Inerzia (Within-Cluster Sum of Squares)')
    plt.title('Metodo del Gomito per la Scelta del K Ottimale')
    plt.grid(True, alpha=0.5)
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq4_elbow_method.png'))
    plt.close()
    print(f"Grafico del gomito salvato. Guarda il grafico per scegliere K dove la curva si 'piega'.")
    
    # 4. Esecuzione Clustering (solitamente K=3 o 4 è un buon compromesso)
    OPTIMAL_K = 3
    print(f"Esecuzione K-Means con K={OPTIMAL_K}...")
    kmeans = KMeans(n_clusters=OPTIMAL_K, random_state=42, n_init='auto').fit(df_scaled)
    df_latest['cluster'] = kmeans.labels_
    
    # 5. Analisi e Interpretazione dei Cluster
    print("\n--- Analisi degli Archetipi Scoperti ---")
    cluster_summary = df_latest.groupby('cluster')[features_exist].mean()
    cluster_summary['count'] = df_latest['cluster'].value_counts()
    
    # Rinominiamo i cluster in base alle loro caratteristiche per renderli comprensibili
    # Es: Il cluster con più LOC e Debt è "Large & Complex"
    mean_debt = df_latest['security_debt_score'].mean()
    mean_loc = df_latest['loc'].mean()
    
    def name_cluster(row):
        if row['security_debt_score'] > mean_debt and row['loc'] > mean_loc:
            return "Large & High-Debt"
        elif row['security_debt_score'] > mean_debt:
            return "Small & High-Debt (Risky)"
        else:
            return "Small & Low-Debt (Healthy)"

    # Applichiamo la rinomina
    cluster_names = cluster_summary.apply(name_cluster, axis=1)
    cluster_summary['Archetype'] = cluster_names
    
    print(cluster_summary.round(2))
    cluster_summary.to_csv(os.path.join(OUTPUT_DIR, 'rq4_cluster_summary.csv'))

    # Mappiamo i nomi anche nel dataframe principale
    df_latest['cluster_name'] = df_latest['cluster'].map(cluster_names)

    # 6. Visualizzazione
    plt.figure(figsize=(12, 8))
    sns.scatterplot(
        data=df_latest,
        x='loc',
        y='security_debt_score',
        hue='cluster_name', # Usiamo i nomi parlanti
        size='num_resources',
        sizes=(50, 500),
        palette='viridis',
        alpha=0.8,
        edgecolor='black'
    )
    plt.xscale('log')
    plt.yscale('log')
    plt.title('Archetipi di Progetti Terraform Scoperti con K-Means', fontsize=16)
    plt.xlabel('Dimensione (LOC, Scala Log)', fontsize=12)
    plt.ylabel('Debito di Sicurezza (Scala Log)', fontsize=12)
    plt.legend(title='Archetipo di Progetto', title_fontsize='13')
    plt.grid(True, which="both", ls="--", alpha=0.3)
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq4_cluster_scatterplot.png'), dpi=300)
    print("\nGrafico dei cluster salvato.")

if __name__ == "__main__":
    analyze_rq4_clustering()