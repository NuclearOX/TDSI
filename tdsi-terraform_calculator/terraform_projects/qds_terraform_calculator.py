# qds_terraform_calculator.py (VERSIONE COMPLETA E CORRETTA)
import subprocess
import json
import sys
import os

# La nostra tabella dei pesi è ancora valida
SEVERITY_WEIGHTS = {
    'error': 10,
    'warning': 5,
    'notice': 2
}
DEFAULT_WEIGHT = 2

def run_tflint_analysis(path_to_scan):
    """Esegue TFLint con la sintassi --chdir corretta."""
    
    tflint_executable = "./tflint.exe" if sys.platform == "win32" else "./tflint"

    if not os.path.exists(tflint_executable):
        print(f"ERRORE: Eseguibile '{tflint_executable}' non trovato.")
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
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Errore critico durante l'esecuzione di TFLint: {e}")
        return None

def calculate_qds_terraform(tflint_output):
    """Calcola il QDS in base all'output JSON."""
    if tflint_output is None or 'issues' not in tflint_output:
        return 0

    total_score = 0
    issues = tflint_output['issues']
    
    print("\n--- Dettaglio dei Debiti di Qualità Terraform Trovati ---")
    
    for issue in issues:
        severity = issue['rule']['severity']
        weight = SEVERITY_WEIGHTS.get(severity, DEFAULT_WEIGHT)
        total_score += weight
        
        print(f"  - [{severity}] {issue['message']} (Regola: {issue['rule']['name']}, Peso: {weight})")
        
    return total_score

# QUESTA PARTE FINALE ERA INCOMPLETA NELLA RISPOSTA PRECEDENTE
if __name__ == "__main__":
    # Il nome corretto della tua cartella (con la "s")
    path_to_analyze = "./terraform_projects"
    
    tflint_results = run_tflint_analysis(path_to_analyze)
    
    if tflint_results is not None:
        qds_score = calculate_qds_terraform(tflint_results)
        print("\n-----------------------------------------")
        print(f"✅ QDS Terraform Calcolato: {qds_score}")
        print("-----------------------------------------")
        if qds_score == 0:
            print("🎉 Ottimo lavoro! Nessun debito di qualità rilevato.")