import subprocess
import json
import logging
import os
from typing import Dict, Any
from src import config

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.severity_weights = config.SEVERITY_WEIGHTS
        
        self.metrics = {
            'critical_count': 0, 'high_count': 0, 'medium_count': 0, 'low_count': 0,
            'security_debt_score': 0.0,
            'infrastructure_debt': 0.0, 'dependency_debt': 0.0, 'secret_debt': 0.0
        }

    def analyze(self) -> Dict[str, Any]:
        # Reset metriche
        for k in self.metrics: self.metrics[k] = 0.0 if isinstance(self.metrics[k], float) else 0

        json_output = self._run_trivy()
        if not json_output:
            return self.metrics

        return self._calculate_debt(json_output)

    def _run_trivy(self) -> Dict:
        if not os.path.exists(self.repo_path):
            return {}

        # Cartelle da ignorare
        dirs_to_skip = ".terraform,.git,.idea,.vscode,node_modules"

        TRIVY_CLI_TIMEOUT = "30m"  # 30 minuti per Trivy interno
        PYTHON_TIMEOUT = 2000      # 2000 secondi (~33 minuti) per il processo Python

        cmd = [
            "trivy", "fs", 
            "--scanners", "vuln,misconfig,secret",
            "--format", "json", 
            "--quiet",
            "--skip-db-update",
            "--offline-scan",
            "--timeout", TRIVY_CLI_TIMEOUT,            # <--- MODIFICA 1: Diamo 15 minuti a Trivy
            "--skip-dirs", dirs_to_skip,
            self.repo_path
        ]
        
        try:
            # <--- MODIFICA 2: Timeout Python aumentato a 20 minuti (1200s)
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=PYTHON_TIMEOUT)
            
            if not result.stdout:
                if result.stderr:
                    # Logghiamo l'errore per capire cosa succede
                    logger.warning(f"Trivy error output: {result.stderr[:300]}...")
                return {}
            
            return json.loads(result.stdout)
            
        except subprocess.TimeoutExpired:
            logger.error(f"Trivy TIMEOUT (Python killed it) su {self.repo_path}")
            return {}
        except json.JSONDecodeError:
            logger.error("Errore parsing JSON Trivy")
            return {}
        except Exception as e:
            logger.error(f"Errore esecuzione Trivy: {e}")
            return {}

    def _calculate_debt(self, data: Dict) -> Dict[str, Any]:
        results = data.get('Results', [])
        if not results:
            return self.metrics

        for res in results:
            # Gestione sicura delle liste che potrebbero essere None
            misconfs = res.get('Misconfigurations') or []
            vulns = res.get('Vulnerabilities') or []
            secrets = res.get('Secrets') or []

            # 1. Misconfigurazioni (Infrastructure Debt)
            for issue in misconfs:
                if issue.get('Status') == 'FAIL':
                    self._add_issue(issue, category='infrastructure')

            # 2. Vulnerabilità (Dependency Debt)
            for issue in vulns:
                self._add_issue(issue, category='dependency')

            # 3. Segreti (Secret Debt)
            for issue in secrets:
                self._add_issue(issue, category='secret')

        return self.metrics

    def _add_issue(self, issue: Dict, category: str):
        severity = issue.get('Severity', 'UNKNOWN')
        weight = self.severity_weights.get(severity, 0.0)
        
        if severity == 'CRITICAL': self.metrics['critical_count'] += 1
        elif severity == 'HIGH': self.metrics['high_count'] += 1
        elif severity == 'MEDIUM': self.metrics['medium_count'] += 1
        elif severity == 'LOW': self.metrics['low_count'] += 1
        
        self.metrics['security_debt_score'] += weight
        
        if category == 'infrastructure': self.metrics['infrastructure_debt'] += weight
        elif category == 'dependency': self.metrics['dependency_debt'] += weight
        elif category == 'secret': self.metrics['secret_debt'] += weight