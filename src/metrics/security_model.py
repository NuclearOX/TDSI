import subprocess
import json
import logging
import os
from typing import Dict, Any
from src import config

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    """
    Analyzes a directory using Trivy to identify security vulnerabilities,
    misconfigurations, and hard-coded secrets.
    """
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.severity_weights = config.SEVERITY_WEIGHTS
        
        self.metrics = {
            'critical_count': 0, 'high_count': 0, 'medium_count': 0, 'low_count': 0,
            'security_debt_score': 0.0,
            'infrastructure_debt': 0.0, 'dependency_debt': 0.0, 'secret_debt': 0.0
        }

    def analyze(self) -> Dict[str, Any] | None: # Can now return None
        """
        Executes the security scan. Returns a dictionary of metrics on success,
        or None on failure (e.g., timeout).
        """
        # Reset metrics for each analysis
        for k in self.metrics: self.metrics[k] = 0.0 if isinstance(self.metrics[k], float) else 0

        json_output = self._run_trivy()
        
        # --- CRITICAL LOGIC CHANGE ---
        # If Trivy failed (returned None), we propagate the failure
        if json_output is None:
            logger.error(f"Security analysis failed for path: {self.repo_path}. This snapshot will be discarded.")
            return None

        return self._calculate_debt(json_output)

    def _run_trivy(self) -> Dict | None:
        """
        Triggers the Trivy CLI process. Returns a parsed JSON dict on success,
        or None on any critical failure.
        """
        if not os.path.exists(self.repo_path):
            return None

        dirs_to_skip = ".terraform,.git,.idea,.vscode,node_modules,examples,example,tests,test,fixtures,modules_override,vendor"
        
        # Calculate Python timeout to be greater than Trivy's internal timeout
        trivy_minutes = int(config.TRIVY_CLI_TIMEOUT.replace('m', ''))
        python_timeout = (trivy_minutes * 60) + 300 # Add a 5-minute buffer

        cmd = [
            "trivy", "fs", 
            "--scanners", "vuln,misconfig,secret",
            "--format", "json", 
            "--quiet",
            "--skip-db-update",
            "--offline-scan",
            "--timeout", config.TRIVY_CLI_TIMEOUT,
            "--skip-dirs", dirs_to_skip,
            self.repo_path
        ]
        
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False, timeout=python_timeout
            )
            
            # If stdout is empty but stderr has a fatal error, it's a failure
            if not result.stdout:
                if result.stderr and ("fatal" in result.stderr.lower() or "error" in result.stderr.lower()):
                    logger.warning(f"Trivy fatal error: {result.stderr[:300]}...")
                return {} # Return empty dict instead of None for non-fatal empty output
            
            return json.loads(result.stdout)
            
        except subprocess.TimeoutExpired:
            logger.error(f"Trivy TIMEOUT (Python process killed it after {python_timeout}s) on {self.repo_path}")
            return None
        except Exception as e:
            logger.error(f"Critical error during Trivy execution: {e}")
            return None
    
    # --- The rest of the class remains the same ---

    def _calculate_debt(self, data: Dict) -> Dict[str, Any]:
        results = data.get('Results', [])
        for res in results:
            misconfs = res.get('Misconfigurations') or []
            vulns = res.get('Vulnerabilities') or []
            secrets = res.get('Secrets') or []
            
            for issue in misconfs:
                if issue.get('Status') == 'FAIL':
                    self._add_issue(issue, category='infrastructure')

            for issue in vulns:
                self._add_issue(issue, category='dependency')

            for issue in secrets:
                self._add_issue(issue, category='secret')

        return self.metrics

    def _add_issue(self, issue: Dict, category: str):
        severity = issue.get('Severity', 'UNKNOWN').upper()
        weight = self.severity_weights.get(severity, 0.0)
        
        if severity == 'CRITICAL': self.metrics['critical_count'] += 1
        elif severity == 'HIGH': self.metrics['high_count'] += 1
        elif severity == 'MEDIUM': self.metrics['medium_count'] += 1
        elif severity == 'LOW': self.metrics['low_count'] += 1
        
        self.metrics['security_debt_score'] += weight
        
        if category == 'infrastructure': self.metrics['infrastructure_debt'] += weight
        elif category == 'dependency': self.metrics['dependency_debt'] += weight
        elif category == 'secret': self.metrics['secret_debt'] += weight