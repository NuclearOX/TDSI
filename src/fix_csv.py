import csv
import os
import sys

# Percorsi (assumiamo di lanciarlo dalla root del progetto)
INPUT_FILE = os.path.join('data', 'output', 'dataset_final.csv')
OUTPUT_FILE = os.path.join('data', 'output', 'dataset_final_FIXED.csv')

def fix_dataset():
    print(f"Avvio riparazione CSV...")
    print(f"Input: {INPUT_FILE}")
    print(f"Output: {OUTPUT_FILE}")

    if not os.path.exists(INPUT_FILE):
        print("Errore: File di input non trovato.")
        return

    # Colonne attese: 17
    # 0: repo_name
    # 1: git_url
    # 2: commit_hash
    # 3: tag (IL COLPEVOLE: qui ci sono virgole extra)
    # 4: author_date
    # 5: committer_date
    # 6-16: Metriche numeriche (11 colonne)
    EXPECTED_COLS = 17
    METRICS_AND_DATES_COUNT = 13 # Dalla colonna 4 alla 16 sono date e numeri

    fixed_rows = 0
    total_rows = 0
    skipped_rows = 0

    try:
        with open(INPUT_FILE, 'r', encoding='utf-8', errors='replace') as infile, \
             open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as outfile:
            
            # Usiamo il lettore CSV base, ma se fallisce faremo fallback manuale
            reader = csv.reader(infile)
            writer = csv.writer(outfile, quoting=csv.QUOTE_MINIMAL)

            try:
                header = next(reader)
                writer.writerow(header)
            except StopIteration:
                print("File vuoto!")
                return

            for row in reader:
                total_rows += 1
                
                if len(row) == EXPECTED_COLS:
                    # Riga perfetta, la scriviamo così com'è
                    writer.writerow(row)
                
                elif len(row) > EXPECTED_COLS:
                    # Riga rotta: ci sono troppe colonne.
                    # Sappiamo che le prime 3 sono sicure (repo, url, hash)
                    # Sappiamo che le ultime 13 sono sicure (date + numeri)
                    # Tutto quello che c'è in mezzo è il TAG che si è spezzato.
                    
                    # Ricostruzione:
                    # Parte 1: Primi 3 campi
                    part1 = row[:3]
                    
                    # Parte 3: Ultimi 13 campi
                    part3 = row[-METRICS_AND_DATES_COUNT:]
                    
                    # Parte 2: Tutto ciò che sta in mezzo, unito da spazio o virgola
                    # Indice inizio parte centrale: 3
                    # Indice fine parte centrale: len(row) - 13
                    middle_content = ", ".join(row[3 : len(row) - METRICS_AND_DATES_COUNT])
                    
                    # Puliamo il tag da "a capo" o caratteri strani che rompono i CSV
                    middle_content = middle_content.replace('\n', ' ').replace('\r', '').replace('"', "'")
                    
                    new_row = part1 + [middle_content] + part3
                    
                    writer.writerow(new_row)
                    fixed_rows += 1
                
                else:
                    # Meno colonne del previsto? Riga corrotta irrecuperabile
                    print(f"Riga {total_rows} saltata: troppe poche colonne ({len(row)})")
                    skipped_rows += 1

        print("-" * 30)
        print(f"COMPLETATO.")
        print(f"Totale righe processate: {total_rows}")
        print(f"Righe corrette (erano rotte): {fixed_rows}")
        print(f"Righe saltate (irrecuperabili): {skipped_rows}")
        print(f"Nuovo file creato: {OUTPUT_FILE}")
        print("-" * 30)

    except Exception as e:
        print(f"Errore critico durante la riparazione: {e}")

if __name__ == "__main__":
    fix_dataset()