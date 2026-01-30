import sqlite3
import os

# Percorso del DB dentro il container
DB_PATH = 'data/input/TerraDS.sqlite' # Assicurati che il nome del file coincida (case-sensitive su Linux!)

def inspect():
    if not os.path.exists(DB_PATH):
        print(f"ERRORE: Il file {DB_PATH} non esiste.")
        # Proviamo a cercare nella cartella per vedere come si chiama
        print("File presenti in data/input/:")
        print(os.listdir("data/input"))
        return

    print(f"--- Ispezione Database: {DB_PATH} ---")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 1. Trova i nomi delle tabelle
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tabelle trovate: {tables}")
        
        # 2. Per ogni tabella, stampa le colonne
        for table in tables:
            table_name = table[0]
            print(f"\nSchema della tabella '{table_name}':")
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            for col in columns:
                # col[1] è il nome della colonna, col[2] è il tipo
                print(f"  - {col[1]} ({col[2]})")
                
        conn.close()
    except Exception as e:
        print(f"Errore: {e}")

if __name__ == "__main__":
    inspect()