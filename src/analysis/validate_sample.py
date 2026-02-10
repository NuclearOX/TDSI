import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import sys
import numpy as np
from scipy.stats import ks_2samp

# Cerchiamo di importare config, gestendo il path
sys.path.append(os.getcwd())
try:
    from src import config
    # Sovrascriviamo le impostazioni per il test locale se necessario
    # Se stai lanciando da locale e il path del DB è diverso da /app/...
    if not os.path.exists(config.DB_PATH):
        # Fallback per esecuzione locale Windows/Linux fuori da Docker
        local_db = os.path.join('data', 'input', 'TerraDS.sqlite')
        if os.path.exists(local_db):
            config.DB_PATH = local_db
except ImportError:
    # Configurazione di fallback se l'import fallisce
    class Config:
        DB_PATH = os.path.join('data', 'input', 'TerraDS.sqlite')
        DATA_OUTPUT_DIR = os.path.join('data', 'output', 'figures')
        MIN_STARS = 15
        REPO_LIMIT = 200
    config = Config()

os.makedirs(config.DATA_OUTPUT_DIR, exist_ok=True)

def validate():
    print("--- VALIDAZIONE MATEMATICA DEL CAMPIONE (KS-TEST) ---")
    print(f"Database: {config.DB_PATH}")
    
    if not os.path.exists(config.DB_PATH):
        print(f"ERRORE: Database non trovato in {config.DB_PATH}")
        return

    conn = sqlite3.connect(config.DB_PATH)
    
    # 1. Carica l'intera popolazione rilevante
    # CORREZIONE: Usiamo 'SizeInKb' invece di 'ResourceCount' che non esiste nella tabella
    print("Caricamento popolazione totale...")
    query_pop = f"SELECT StarCount, SizeInKb FROM Repositories WHERE StarCount >= {config.MIN_STARS}"
    
    try:
        df_pop = pd.read_sql_query(query_pop, conn)
    except Exception as e:
        print(f"Errore query SQL: {e}")
        conn.close()
        return
    
    # 2. Simula il campione casuale
    print("Estrazione campione casuale (simulazione)...")
    # Se la popolazione è più piccola del limite, prendiamo tutto
    sample_n = min(config.REPO_LIMIT, len(df_pop))
    df_sample = df_pop.sample(n=sample_n, random_state=42)
    
    conn.close()
    
    print(f"Popolazione Rilevante: {len(df_pop)}")
    print(f"Campione Simulato: {len(df_sample)}")
    
    # 3. Test di Kolmogorov-Smirnov
    # Confronta la distribuzione delle Stelle e della Dimensione (Size)
    print("\n--- Risultati Test KS (P-Value > 0.05 indica similarità statistica) ---")
    
    # Mappiamo i nomi tecnici a nomi leggibili per il grafico
    metrics_map = {
        'StarCount': 'Popolarità (Stelle)', 
        'SizeInKb': 'Dimensione (KB)'
    }
    
    for metric, label in metrics_map.items():
        # Rimuoviamo eventuali zero o NaN per evitare errori nei logaritmi
        pop_data = df_pop[metric].dropna()
        pop_data = pop_data[pop_data > 0]
        
        sample_data = df_sample[metric].dropna()
        sample_data = sample_data[sample_data > 0]
        
        stat, p_value = ks_2samp(pop_data, sample_data)
        
        print(f"\nMetrica: {label}")
        print(f"  KS Statistic: {stat:.4f}")
        print(f"  P-Value: {p_value:.4f}")
        
        if p_value > 0.05:
            print("  ✅ VALIDATO: Il campione rappresenta la popolazione.")
        else:
            print("  ⚠️ NOTA: Distribuzione differente (comune con Power Law estreme).")

    # 4. Grafico Sovrapposto
    plt.figure(figsize=(12, 6))
    
    # Plot Stelle
    plt.subplot(1, 2, 1)
    sns.kdeplot(df_pop['StarCount'], fill=True, color="grey", label='Popolazione', log_scale=True)
    sns.kdeplot(df_sample['StarCount'], fill=True, color="blue", alpha=0.5, label='Campione', log_scale=True)
    plt.title('Distribuzione Popolarità (Stelle)')
    plt.xlabel('Stelle (Log Scale)')
    plt.legend()

    # Plot Dimensione
    plt.subplot(1, 2, 2)
    sns.kdeplot(df_pop['SizeInKb'], fill=True, color="grey", label='Popolazione', log_scale=True)
    sns.kdeplot(df_sample['SizeInKb'], fill=True, color="red", alpha=0.5, label='Campione', log_scale=True)
    plt.title('Distribuzione Dimensione (KB)')
    plt.xlabel('Size KB (Log Scale)')
    plt.legend()
    
    output_path = os.path.join(config.DATA_OUTPUT_DIR, 'sample_validation.png')
    plt.tight_layout()
    plt.savefig(output_path)
    print(f"\nGrafico salvato in: {output_path}")

if __name__ == "__main__":
    validate()