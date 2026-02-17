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
OPTIMAL_K = 3  # Fixed based on Elbow Method results

# Create output directory if it doesn't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data_robust(filepath):
    """
    Robust CSV loader handling parsing errors and different separators.
    """
    if not os.path.exists(filepath):
        print(f"ERROR: File {filepath} not found.")
        sys.exit(1)
    try:
        df = pd.read_csv(filepath)
    except Exception:
        print("Warning: Standard parsing failed. Trying python engine with error skipping...")
        df = pd.read_csv(filepath, sep=',', on_bad_lines='skip', engine='python')
    return df

def analyze_rq4_clustering():
    print("--- RQ4: Unsupervised Analysis (Project Archetypes Discovery) ---")
    
    # 1. Load Data
    df = load_data_robust(INPUT_CSV)
    
    # Define features for clustering (Structural & Security metrics)
    features_candidates = [
        'loc', 'num_resources', 'num_modules', 'iac_mccabe_complexity',
        'hard_coded_values', 'security_debt_score', 'infrastructure_debt'
    ]
    
    # Keep only columns that actually exist in the CSV
    features_exist = [f for f in features_candidates if f in df.columns]
    
    # Cleaning: Remove rows with NaN in critical features and 0 LOC
    df = df.dropna(subset=features_exist)
    df = df[df['loc'] > 0]
    
    # 2. Filter for LAST SNAPSHOT per repository
    # We want to cluster the *current state* of projects, not their history.
    if 'author_date' in df.columns:
        df['author_date'] = pd.to_datetime(df['author_date'], utc=True, errors='coerce')
        df_latest = df.sort_values('author_date').drop_duplicates('repo_name', keep='last').copy()
    else:
        # Fallback if no date: assume last entry is latest
        df_latest = df.drop_duplicates('repo_name', keep='last').copy()

    print(f"Clustering performed on {len(df_latest)} unique projects (latest snapshot).")
    
    if len(df_latest) < 10:
        print("Insufficient data for clustering analysis.")
        return

    # 3. Standardization (Z-Score Normalization)
    # Essential for K-Means to treat all features with equal weight
    scaler = StandardScaler()
    df_scaled = scaler.fit_transform(df_latest[features_exist])
    
    # 4. Execute K-Means Clustering
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
    
    print(f"Executing K-Means with K={OPTIMAL_K}...")
    kmeans = KMeans(n_clusters=OPTIMAL_K, random_state=42, n_init='auto').fit(df_scaled)
    df_latest['cluster'] = kmeans.labels_
    
    # 5. Data-Driven Archetype Naming (Relative Centroid Analysis)
    # Instead of using hardcoded thresholds (e.g., > 5000), we compare clusters relatively.
    
    # Calculate mean values for each cluster (Centroids)
    cluster_means = df_latest.groupby('cluster')[features_exist].mean()
    
    archetype_map = {}
    
    # A. Identify "Critical Risk (Debt-Heavy)"
    # Logic: The cluster with the highest average Security Debt Score
    id_critical = cluster_means['security_debt_score'].idxmax()
    archetype_map[id_critical] = "Critical Risk (Debt-Heavy)"
    
    # B. Identify "Large Monoliths (Managed)" 
    # Logic: Exclude the Critical cluster. Between the remaining two, the one with higher LOC is the Monolith.
    remaining_ids = [i for i in range(OPTIMAL_K) if i != id_critical]
    
    if len(remaining_ids) > 0:
        # Filter means for remaining clusters
        remaining_means = cluster_means.loc[remaining_ids]
        
        # Find the one with max LOC among the remaining
        id_monolith = remaining_means['loc'].idxmax()
        archetype_map[id_monolith] = "Large Monoliths (Managed)"
        
        # C. The last one is "Small-Scale Baseline"
        for i in remaining_ids:
            if i != id_monolith:
                archetype_map[i] = "Small-Scale Baseline"
    
    # Apply names to the dataframe
    df_latest['archetype'] = df_latest['cluster'].map(archetype_map)
    
    # 6. Save Summary Statistics
    summary = df_latest.groupby('archetype')[features_exist].mean()
    summary['count'] = df_latest['archetype'].value_counts()
    
    print("\n--- Final Archetype Summary ---")
    print(summary[['count', 'loc', 'security_debt_score']].round(2))
    summary.to_csv(os.path.join(OUTPUT_DIR, 'rq4_cluster_summary.csv'))
    
    # 7. Visualization: Scatter Plot (Size vs Risk)
    plt.figure(figsize=(10, 7))
    sns.scatterplot(
        data=df_latest,
        x='loc',
        y='security_debt_score',
        hue='archetype',
        style='archetype',
        size='num_resources',
        sizes=(50, 400),
        palette='viridis',
        alpha=0.8,
        edgecolor='k'
    )
    
    # Log scale is crucial for LOC and Debt distribution visualization
    plt.xscale('log')
    plt.yscale('log')
    
    plt.title('RQ4: Terraform Project Archetypes (Size vs. Security Debt)', fontsize=14)
    plt.xlabel('Lines of Code (LOC) - Log Scale', fontsize=12)
    plt.ylabel('Security Debt Score - Log Scale', fontsize=12)
    plt.legend(title='Archetype', bbox_to_anchor=(1.02, 1), loc='upper left')
    plt.grid(True, which="both", ls="--", alpha=0.3)
    plt.tight_layout()
    
    plot_path = os.path.join(OUTPUT_DIR, 'rq4_cluster_scatterplot.png')
    plt.savefig(plot_path, dpi=300)
    print(f"Scatter plot saved to {plot_path}")
    plt.close()

    # 8. Visualization: Boxplots for Distribution Analysis
    print("Generating distribution boxplots...")
    features_to_plot = ['loc', 'security_debt_score', 'iac_mccabe_complexity', 'hard_coded_values']
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    axes = axes.flatten()

    for i, feature in enumerate(features_to_plot):
        if feature in df_latest.columns:
            sns.boxplot(
                x='archetype', 
                y=feature, 
                data=df_latest, 
                ax=axes[i], 
                hue='archetype',
                palette='viridis',
                legend=False
            )
            axes[i].set_title(f'Distribution of {feature}', fontsize=12)
            axes[i].set_yscale('log') # Log scale for better visibility of outliers
            axes[i].set_xlabel('')
            axes[i].tick_params(axis='x', rotation=15)
            
    plt.tight_layout()
    boxplot_path = os.path.join(OUTPUT_DIR, 'rq4_cluster_boxplots.png')
    plt.savefig(boxplot_path, dpi=300)
    print(f"Boxplots saved to {boxplot_path}")
    plt.close()

    print("--- RQ4 Analysis Complete ---")

if __name__ == "__main__":
    analyze_rq4_clustering()