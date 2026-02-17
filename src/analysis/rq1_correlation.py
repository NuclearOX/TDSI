import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from scipy.stats import spearmanr
import os
import sys
import numpy as np

# --- CONFIGURATION ---
INPUT_CSV = os.path.join('data', 'output', 'dataset_final.csv')
OUTPUT_DIR = os.path.join('data', 'output', 'figures')

# Create output directory
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data_robust(filepath):
    """Loads the CSV handling potential parsing errors."""
    if not os.path.exists(filepath):
        print(f"ERROR: The file {filepath} does not exist.")
        sys.exit(1)
    try:
        df = pd.read_csv(filepath)
    except pd.errors.ParserError:
        try:
            # Fallback for files with inconsistent line lengths
            df = pd.read_csv(filepath, sep=',', on_bad_lines='skip', engine='python')
        except Exception as e:
            print(f"Critical error reading CSV: {e}")
            sys.exit(1)
    return df

def analyze_rq1():
    print("--- RQ1: Correlation Analysis (Scientific Version) ---")
    
    # 1. Loading
    df = load_data_robust(INPUT_CSV)
    
    # 2. Cleaning and Numerical Conversion
    potential_numeric_cols = [
        'loc', 'num_resources', 'num_modules', 'num_variables', 'num_outputs',
        'num_providers', 'iac_mccabe_complexity', 'hard_coded_values',
        'comment_lines', 'internal_references', 'security_debt_score'
    ]
    
    existing_numeric_cols = [c for c in potential_numeric_cols if c in df.columns]
    for col in existing_numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')
            
    # Remove rows with LOC=0 or missing security score
    df = df.dropna(subset=['loc', 'security_debt_score'])
    df = df[df['loc'] > 0]

    # ---------------------------------------------------------
    # 3. CRITICAL FILTER: Unique Code States per Repository
    # We remove temporal duplicates where no code changes occurred.
    # ---------------------------------------------------------
    subset_for_uniqueness = ['repo_name', 'loc', 'num_resources', 'iac_mccabe_complexity', 'security_debt_score']
    # Add other columns if they exist to refine uniqueness check
    for optional_col in ['num_variables', 'hard_coded_values']:
        if optional_col in df.columns:
            subset_for_uniqueness.append(optional_col)
    
    df_unique = df.drop_duplicates(subset=subset_for_uniqueness)
    
    print(f"Total snapshots in CSV: {len(df)}")
    print(f"Unique snapshots (distinct code states): {len(df_unique)}")
    print(f"Redundant rows removed: {len(df) - len(df_unique)}")

    # 4. Normalization (Density Metrics)
    # Calculate densities on the cleaned dataset
    df_unique = df_unique.copy() # Prevent SettingWithCopyWarning
    
    # Security Debt Density
    df_unique['sec_debt_density'] = df_unique['security_debt_score'] / df_unique['loc']
    
    # Normalized Structural Metrics
    if 'iac_mccabe_complexity' in df_unique.columns:
        df_unique['complexity_density'] = df_unique['iac_mccabe_complexity'] / df_unique['loc']
        
    if 'hard_coded_values' in df_unique.columns:
        df_unique['hard_coded_density'] = df_unique['hard_coded_values'] / df_unique['loc']
    
    # Calculate comment density
    if 'comment_lines' in df_unique.columns:
        df_unique['comment_density'] = df_unique['comment_lines'] / df_unique['loc']

    # 5. Define Variables
    quality_metrics_candidates = [
        'loc', 'num_resources', 'num_modules', 'iac_mccabe_complexity',
        'complexity_density', 'num_providers', 'hard_coded_values',
        'hard_coded_density', 'comment_density', 'internal_references',
        'num_variables', 'num_outputs'
    ]
    quality_metrics = [m for m in quality_metrics_candidates if m in df_unique.columns]
    target = 'security_debt_score'

    # 6. Spearman Correlation Calculation
    results = []
    for metric in quality_metrics:
        # Spearman between quality metric and ABSOLUTE security debt
        corr, p_value = spearmanr(df_unique[metric], df_unique[target])
        
        results.append({
            'Target': 'Security Debt (Abs)',
            'Quality Metric': metric,
            'Spearman Coeff': round(corr, 3),
            'P-Value': p_value,
            'Significant': 'YES' if p_value < 0.05 else 'NO'
        })
        
        # Correlation with DENSITY (rigorous for comparing projects of different sizes)
        corr_d, p_d = spearmanr(df_unique[metric], df_unique['sec_debt_density'])
        results.append({
            'Target': 'Security Debt (Density)',
            'Quality Metric': f"{metric} (vs Density)",
            'Spearman Coeff': round(corr_d, 3),
            'P-Value': p_d,
            'Significant': 'YES' if p_d < 0.05 else 'NO'
        })

    results_df = pd.DataFrame(results)
    stats_path = os.path.join(OUTPUT_DIR, 'rq1_statistics_clean.csv')
    results_df.to_csv(stats_path, index=False)

    print("\n--- Top Correlations (Unique States Only) ---")
    # Show only correlations with absolute debt for brevity
    display_df = results_df[results_df['Target'] == 'Security Debt (Abs)']
    print(display_df.sort_values(by='Spearman Coeff', ascending=False).head(10).to_string(index=False))

    # 7. Heatmap Generation
    cols_for_heatmap = quality_metrics + [target, 'sec_debt_density']
    plt.figure(figsize=(14, 12))
    # Use only columns present in the dataframe
    cols_present = [c for c in cols_for_heatmap if c in df_unique.columns]
    
    if len(cols_present) > 1:
        corr_matrix = df_unique[cols_present].corr(method='spearman')
        
        sns.heatmap(
            corr_matrix, 
            annot=True, 
            cmap='coolwarm', 
            center=0,
            fmt='.2f',
            linewidths=.5,
            annot_kws={"size": 10}
        )
        plt.title('RQ1: Spearman Correlation Matrix (Unique Code States Only)')
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, 'rq1_heatmap_unique.png'), dpi=300)
        print(f"\nAnalysis complete. Results saved in {OUTPUT_DIR}")
    else:
        print("Not enough columns to generate the heatmap.")

if __name__ == "__main__":
    analyze_rq1()