import hcl2
import os
import logging
import re
from typing import Dict, Any

logger = logging.getLogger(__name__)

class QualityAnalyzer:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        # Mapping rigoroso con Konala et al. (2025) e Dalla Palma et al. (2020)
        self.metrics = {
            # --- SIZE (Dimensione) ---
            'loc': 0,                  # Lines of Code (esclusi commenti/vuoti)
            'num_resources': 0,        # Numero risorse gestite
            
            # --- COMPLEXITY (Sofisticazione) ---
            'iac_mccabe_complexity': 0,# Punti di decisione (count, for_each, dynamic)
            
            # --- COUPLING (Integrazione) ---
            'num_modules': 0,          # Dipendenze da moduli esterni
            'num_providers': 0,        # Dipendenze da provider (AWS, Azure...)
            'internal_references': 0,  # Accoppiamento interno (uso di var., local., module.)
            
            # --- INTERFACE (Coesione) ---
            'num_variables': 0,        # Punti di input
            'num_outputs': 0,          # Punti di output
            
            # --- MAINTAINABILITY (Manutenibilità) ---
            'hard_coded_values': 0,    # Stringhe non parametrizzate (Code Smell)
            'comment_lines': 0         # Documentazione (Metadata category)
        }
        self._unique_providers = set()

    def analyze(self) -> Dict[str, Any]:
        """Scansiona la cartella del repo e calcola le metriche aggregate."""
        # Reset metriche
        for k in self.metrics: 
            if isinstance(self.metrics[k], int): self.metrics[k] = 0
        self._unique_providers = set()

        for root, dirs, files in os.walk(self.repo_path):
            # --- MODIFICA: Esclusione cartelle "sporche" ---
            # Modifichiamo la lista 'dirs' in-place per dire a os.walk di non entrare qui
            dirs[:] = [d for d in dirs if d not in ['.git', '.terraform', '.idea', '.vscode', 'vendor', 'node_modules']]
            
            for file in files:
                if file.endswith('.tf'):
                    file_path = os.path.join(root, file)
                    self._analyze_file(file_path)
        
        self.metrics['num_providers'] = len(self._unique_providers)
        return self.metrics

    def _analyze_file(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
                # 1. Analisi Testuale (LOC e Commenti)
                for line in lines:
                    stripped = line.strip()
                    if not stripped:
                        continue # Linea vuota
                    if stripped.startswith('#') or stripped.startswith('//'):
                        self.metrics['comment_lines'] += 1
                    else:
                        self.metrics['loc'] += 1
                
                content_str = "".join(lines)

            # 2. Parsing HCL (Analisi Strutturale)
            try:
                data = hcl2.loads(content_str)
            except Exception:
                # Se il parsing fallisce, manteniamo almeno LOC e Commenti
                return 

            # --- Estrazione Metriche dall'AST ---
            
            # Size & Structure
            self.metrics['num_resources'] += len(data.get('resource', []))
            self.metrics['num_modules'] += len(data.get('module', []))
            self.metrics['num_variables'] += len(data.get('variable', []))
            self.metrics['num_outputs'] += len(data.get('output', []))

            # Providers (Coupling Esterno)
            for provider in data.get('provider', []):
                for name in provider.keys():
                    self._unique_providers.add(name)

            # Complexity, Internal Coupling & Maintainability (Ricorsivo)
            self._scan_dict_recursive(data)

        except Exception as e:
            logger.warning(f"Errore analisi file {file_path}: {e}")

    def _scan_dict_recursive(self, data: Any):
        """Esplora l'AST per metriche profonde."""
        if isinstance(data, dict):
            for key, value in data.items():
                # A. Complexity (IaC-McCabe)
                # Ogni struttura di controllo aumenta la complessità
                if key in ['count', 'for_each', 'dynamic']:
                    self.metrics['iac_mccabe_complexity'] += 1
                
                # B. Maintainability (Hard-coded values) & Coupling (References)
                if isinstance(value, str):
                    self._analyze_string_value(key, value)

                # Ricorsione
                self._scan_dict_recursive(value)
                
        elif isinstance(data, list):
            for item in data:
                self._scan_dict_recursive(item)

    def _analyze_string_value(self, key: str, value: str):
        """Analizza una stringa per capire se è un riferimento o un valore hard-coded."""
        
        # 1. Internal Coupling (Riferimenti)
        # Se la stringa contiene riferimenti a variabili, locals o altri moduli
        if any(ref in value for ref in ['var.', 'local.', 'module.', 'data.', 'resource.']):
            self.metrics['internal_references'] += 1
            return # Se è un riferimento, non è hard-coded

        # 2. Hard-coded Values
        # Ignoriamo chiavi strutturali che richiedono stringhe
        ignored_keys = [
            'description', 'type', 'source', 'version', 'required_version', 
            'backend', 'alias', 'provider'
        ]
        
        # Se non è un riferimento (${...}), non è una chiave ignorata, ed è una stringa "significativa"
        if key not in ignored_keys and len(value) > 1:
            # Euristica: se non contiene interpolazione ${} è un valore statico
            if "${" not in value:
                self.metrics['hard_coded_values'] += 1