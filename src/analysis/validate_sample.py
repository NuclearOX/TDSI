import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import sys
import numpy as np
from scipy.stats import ks_2samp

# Try to import configuration, managing the path
sys.path.append(os.getcwd())
try:
    from src import config
    # Overwrite settings for local testing if necessary
    # Check if DB path from config exists, otherwise use local fallback
    if not os.path.exists(config.DB_PATH):
        # Fallback for local execution (Windows/Linux) outside Docker
        local_db = os.path.join('data', 'input', 'TerraDS.sqlite')
        if os.path.exists(local_db):
            config.DB_PATH = local_db
except ImportError:
    # Fallback configuration if the import fails
    class Config:
        DB_PATH = os.path.join('data', 'input', 'TerraDS.sqlite')
        DATA_OUTPUT_DIR = os.path.join('data', 'output', 'figures')
        MIN_STARS = 15
        REPO_LIMIT = 200
    config = Config()

os.makedirs(config.DATA_OUTPUT_DIR, exist_ok=True)

def validate():
    print("--- MATHEMATICAL VALIDATION OF THE SAMPLE (KS-TEST) ---")
    print(f"Database: {config.DB_PATH}")
    
    if not os.path.exists(config.DB_PATH):
        print(f"ERROR: Database not found at {config.DB_PATH}")
        return

    conn = sqlite3.connect(config.DB_PATH)
    
    # 1. Load the entire relevant population
    print("Loading total population...")
    query_pop = f"SELECT StarCount, SizeInKb FROM Repositories WHERE StarCount >= {config.MIN_STARS}"
    
    try:
        df_pop = pd.read_sql_query(query_pop, conn)
    except Exception as e:
        print(f"SQL Query Error: {e}")
        conn.close()
        return
    
    # 2. Simulate random sampling
    print("Extracting random sample (simulation)...")
    # If the population is smaller than the limit, take all records
    sample_n = min(config.REPO_LIMIT, len(df_pop))
    df_sample = df_pop.sample(n=sample_n, random_state=42)
    
    conn.close()
    
    print(f"Relevant Population: {len(df_pop)}")
    print(f"Simulated Sample: {len(df_sample)}")
    
    # 3. Kolmogorov-Smirnov Test
    # Compare the distribution of Stars and Size (KB)
    print("\n--- KS Test Results (P-Value > 0.05 indicates statistical similarity) ---")
    
    # Map technical names to readable labels for the graph
    metrics_map = {
        'StarCount': 'Popularity (Stars)', 
        'SizeInKb': 'Size (KB)'
    }
    
    for metric, label in metrics_map.items():
        # Remove any zeros or NaNs to avoid errors in log scales
        pop_data = df_pop[metric].dropna()
        pop_data = pop_data[pop_data > 0]
        
        sample_data = df_sample[metric].dropna()
        sample_data = sample_data[sample_data > 0]
        
        stat, p_value = ks_2samp(pop_data, sample_data)
        
        print(f"\nMetric: {label}")
        print(f"  KS Statistic: {stat:.4f}")
        print(f"  P-Value: {p_value:.4f}")
        
        if p_value > 0.05:
            print("  VALIDATED: The sample represents the population.")
        else:
            print("  NOTE: Different distribution (common with extreme Power Laws).")

    # 4. Overlaid Density Plot
    plt.figure(figsize=(12, 6))
    
    # Plot Popularity (Stars)
    plt.subplot(1, 2, 1)
    sns.kdeplot(df_pop['StarCount'], fill=True, color="grey", label='Population', log_scale=True)
    sns.kdeplot(df_sample['StarCount'], fill=True, color="blue", alpha=0.5, label='Sample', log_scale=True)
    plt.title('Popularity Distribution (Stars)')
    plt.xlabel('Stars (Log Scale)')
    plt.legend()

    # Plot Size (KB)
    plt.subplot(1, 2, 2)
    sns.kdeplot(df_pop['SizeInKb'], fill=True, color="grey", label='Population', log_scale=True)
    sns.kdeplot(df_sample['SizeInKb'], fill=True, color="red", alpha=0.5, label='Sample', log_scale=True)
    plt.title('Size Distribution (KB)')
    plt.xlabel('Size KB (Log Scale)')
    plt.legend()
    
    output_path = os.path.join(config.DATA_OUTPUT_DIR, 'sample_validation.png')
    plt.tight_layout()
    plt.savefig(output_path)
    print(f"\nGraph saved to: {output_path}")

if __name__ == "__main__":
    validate()