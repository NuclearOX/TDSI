import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import os
import sys

# --- CONFIGURATION ---
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
OUTPUT_DIR = os.path.join('data', 'output', 'figures')

os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data_robust(filepath):
    """Robust CSV loader handling parsing errors."""
    if not os.path.exists(filepath):
        print(f"ERROR: File {filepath} not found.")
        sys.exit(1)
    try:
        df = pd.read_csv(filepath)
    except Exception:
        df = pd.read_csv(filepath, sep=',', on_bad_lines='skip', engine='python')
    return df

def analyze_rq4_clustering():
    print("--- RQ4: Unsupervised Analysis (Project Archetypes Discovery) ---")
    
    # 1. Load & Clean Data
    df = load_data_robust(INPUT_CSV)
    
    features_candidates = [
        'loc', 'num_resources', 'num_modules', 'iac_mccabe_complexity',
        'hard_coded_values', 'security_debt_score', 'infrastructure_debt'
    ]
    features_exist = [f for f in features_candidates if f in df.columns]
    
    df = df.dropna(subset=features_exist)
    df = df[df['loc'] > 0]
    
    # Filter for LAST SNAPSHOT per repo
    df['author_date'] = pd.to_datetime(df['author_date'], utc=True, errors='coerce')
    df_latest = df.sort_values('author_date').drop_duplicates('repo_name', keep='last').copy()

    print(f"Clustering performed on {len(df_latest)} unique projects (latest state).")
    
    if len(df_latest) < 10:
        print("Insufficient data for clustering.")
        return

    # 2. Standardization
    scaler = StandardScaler()
    df_scaled = scaler.fit_transform(df_latest[features_exist])
    
    # 3. Elbow Method
    inertias = []
    k_range = range(1, 11)
    for k in k_range:
        kmeans = KMeans(n_clusters=k, random_state=42, n_init='auto').fit(df_scaled)
        inertias.append(kmeans.inertia_)
        
    plt.figure(figsize=(8, 5))
    plt.plot(k_range, inertias, marker='o', linestyle='--', color='#2c3e50')
    plt.xlabel('Number of Clusters (K)')
    plt.ylabel('Inertia')
    plt.title('Elbow Method for Optimal K')
    plt.grid(True, alpha=0.3)
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq4_elbow_method.png'))
    plt.close()
    
    # 4. Execute Clustering
    OPTIMAL_K = 3 
    kmeans = KMeans(n_clusters=OPTIMAL_K, random_state=42, n_init='auto').fit(df_scaled)
    df_latest['cluster'] = kmeans.labels_
    
    # 5. Advanced Archetype Naming
    # Calcoliamo i centroidi per dare nomi basati sui dati reali emersi
    cluster_summary = df_latest.groupby('cluster')[features_exist].mean()
    
    def define_archetype(c_id):
        row = cluster_summary.loc[c_id]
        # Logica basata sui risultati del tuo ultimo run:
        if row['loc'] < df_latest['loc'].mean():
            return "Small & Low-Risk (Healthy)"
        elif row['security_debt_score'] > 5000: # Soglia per il Cluster "Tossico"
            return "Critical Risk (Debt-Heavy)"
        else:
            return "Large Monoliths (Managed)"

    # Creazione mappa nomi
    id_to_name = {i: define_archetype(i) for i in range(OPTIMAL_K)}
    df_latest['cluster_name'] = df_latest['cluster'].map(id_to_name)
    
    # Aggiorniamo il summary per il CSV
    cluster_summary['Archetype'] = cluster_summary.index.map(id_to_name)
    cluster_summary['count'] = df_latest['cluster'].value_counts()
    
    print("\n--- Final Archetype Summary ---")
    print(cluster_summary[['Archetype', 'count', 'loc', 'security_debt_score']].round(2))
    cluster_summary.to_csv(os.path.join(OUTPUT_DIR, 'rq4_cluster_summary.csv'))

    # 6. Scatter Plot
    plt.figure(figsize=(12, 8))
    sns.scatterplot(
        data=df_latest,
        x='loc',
        y='security_debt_score',
        hue='cluster_name',
        style='cluster_name',
        size='num_resources',
        sizes=(50, 500),
        palette='viridis',
        alpha=0.7,
        edgecolor='k'
    )
    plt.xscale('log')
    plt.yscale('log')
    plt.title('Terraform Project Archetypes: Size vs Security Debt', fontsize=15)
    plt.xlabel('Lines of Code (Log Scale)', fontsize=12)
    plt.ylabel('Security Debt Score (Log Scale)', fontsize=12)
    plt.legend(title='Archetype', bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, which="both", ls="--", alpha=0.2)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq4_cluster_scatterplot.png'), dpi=300)
    plt.close()

    # 7. Boxplots (Corretti per evitare FutureWarnings)
    print("Generating distribution boxplots...")
    features_to_plot = ['loc', 'security_debt_score', 'iac_mccabe_complexity', 'num_resources']
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    axes = axes.flatten()

    for i, feature in enumerate(features_to_plot):
        if feature in df_latest.columns:
            sns.boxplot(
                x='cluster_name', 
                y=feature, 
                data=df_latest, 
                ax=axes[i], 
                hue='cluster_name', # Risolve il FutureWarning
                palette='viridis',
                legend=False
            )
            axes[i].set_title(f'Distribution of {feature}', fontsize=12)
            axes[i].set_yscale('log')
            axes[i].tick_params(axis='x', rotation=20)
            axes[i].set_xlabel('')
            
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq4_cluster_boxplots.png'), dpi=300)
    plt.close()
    print(f"Analysis complete. Files saved in {OUTPUT_DIR}")

if __name__ == "__main__":
    analyze_rq4_clustering()