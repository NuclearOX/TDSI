# qds_terraform_calculator.py (VERSIONE PER DOCKER)
import subprocess
import json
import sys
import os
import shutil # <-- MODIFICA 1: Aggiungiamo questa libreria standard di Python

# La nostra tabella dei pesi è ancora valida
SEVERITY_WEIGHTS = {
    'error': 10,
    'warning': 5,
    'notice': 2
}
DEFAULT_WEIGHT = 1

def run_tflint_analysis(path_to_scan):
    """Esegue TFLint affidandosi al PATH di sistema."""
    
    # <-- MODIFICA 2: Rimuoviamo "./". Ora cerchiamo il comando nel PATH di sistema.
    tflint_executable = "tflint.exe" if sys.platform == "win32" else "tflint"

    # <-- MODIFICA 3: Usiamo shutil.which per verificare se il comando esiste nel PATH.
    # Questo è il modo corretto e moderno di fare questo controllo.
    if not shutil.which(tflint_executable):
        print(f"ERRORE: Comando '{tflint_executable}' non trovato nel PATH di sistema.")
        return None

    # Il comando corretto per le nuove versioni di TFLint
    command = [
        tflint_executable,
        "--format=json",
        "--chdir",
        path_to_scan
    ]
    
    print(f"🔍 Esecuzione di TFLint sulla cartella: {path_to_scan}")

    # Eseguiamo l'init per sicurezza
    subprocess.run([tflint_executable, "--init"], capture_output=True, cwd=path_to_scan)

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        # Piccolo controllo per output vuoto o non JSON
        if not result.stdout.strip():
            print("Attenzione: TFLint non ha prodotto nessun output JSON. Forse non ci sono file .tf validi?")
            return {"issues": []}
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Errore critico durante l'esecuzione di TFLint: {e}")
        # Stampa l'errore di tflint se c'è
        if result and result.stderr:
            print(f"Output di errore da TFLint:\n{result.stderr}")
        return None

def calculate_qds_terraform(tflint_output):
    """Calcola il QDS in base all'output JSON."""
    if tflint_output is None or 'issues' not in tflint_output:
        return 0

    total_score = 0
    issues = tflint_output['issues']
    
    if not issues:
        print("\n--- Nessun Debito di Qualità Terraform Trovato ---")
        return 0
        
    print("\n--- Dettaglio dei Debiti di Qualità Terraform Trovati ---")
    
    for issue in issues:
        severity = issue['rule']['severity']
        weight = SEVERITY_WEIGHTS.get(severity, DEFAULT_WEIGHT)
        total_score += weight
        
        print(f"  - [{severity}] {issue['message']} (Regola: {issue['rule']['name']}, Peso: {weight})")
        
    return total_score

if __name__ == "__main__":
    # <-- MODIFICA 4: Allineiamo il nome della cartella a quello usato nel Dockerfile.
    path_to_analyze = "./codici_terraform"
    
    if not os.path.isdir(path_to_analyze):
        print(f"ERRORE FINALE: La cartella da analizzare '{path_to_analyze}' non esiste all'interno del container!")
    else:
        tflint_results = run_tflint_analysis(path_to_analyze)
        
        if tflint_results is not None:
            qds_score = calculate_qds_terraform(tflint_results)
            print("\n-----------------------------------------")
            print(f"✅ QDS Terraform Calcolato: {qds_score}")
            print("-----------------------------------------")
            if qds_score == 0:
                print("🎉 Ottimo lavoro! Nessun debito di qualità rilevato.")