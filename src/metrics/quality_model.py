import hcl2
import os
import logging
import re
from typing import Dict, Any

logger = logging.getLogger(__name__)

class QualityAnalyzer:
    """
    Analyzes Terraform files to extract structural quality metrics based on
    Dalla Palma et al. (2020) and the framework by Konala et al. (2025).
    Maps raw metrics to ISO/IEC 25010 quality characteristics.
    """
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        
        # Dictionary to store aggregated metrics for the entire repository
        self.metrics = {
            # --- SIZE & STRUCTURE (ISO: Functional Suitability) ---
            'loc': 0,                  # Lines of Code (excluding comments and empty lines)
            'num_resources': 0,        # Total number of managed resources
            
            # --- COMPLEXITY (ISO: Maintainability / Analysability) ---
            'iac_mccabe_complexity': 0, # Decision points: count, for_each, dynamic blocks
            
            # --- COUPLING & INTEGRATION (ISO: Modularity / Compatibility) ---
            'num_modules': 0,          # External module calls
            'num_providers': 0,        # Distinct infrastructure providers used
            'internal_references': 0,  # Degree of internal coupling (use of var., local., data.)
            
            # --- INTERFACE (ISO: Reusability) ---
            'num_variables': 0,        # Input parameters
            'num_outputs': 0,          # Output values
            
            # --- MAINTAINABILITY (ISO: Modifiability / Documentation) ---
            'hard_coded_values': 0,    # Use of non-parameterized strings (Code Smell)
            'comment_lines': 0         # Level of documentation
        }
        self._unique_providers = set()

    def analyze(self) -> Dict[str, Any]:
        """
        Walks through the repository, analyzes each .tf file, and aggregates metrics.
        """
        # Reset metrics for each analysis execution
        for k in self.metrics: 
            if isinstance(self.metrics[k], int): self.metrics[k] = 0
        self._unique_providers = set()

        for root, dirs, files in os.walk(self.repo_path):
            # Prune "dirty" directories to ensure we only analyze source code.
            # This is critical for scientific validity (avoiding measuring artifacts).
            dirs[:] = [d for d in dirs if d not in [
                '.git', '.terraform', '.idea', '.vscode', 'vendor', 'node_modules', 'tests'
            ]]
            
            for file in files:
                if file.endswith('.tf'):
                    file_path = os.path.join(root, file)
                    self._analyze_file(file_path)
        
        # Finalize coupling metrics
        self.metrics['num_providers'] = len(self._unique_providers)
        return self.metrics

    def _analyze_file(self, file_path: str):
        """
        Parses and extracts metrics from a single Terraform file.
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
                # 1. Text-level Analysis (LOC and Comments)
                for line in lines:
                    stripped = line.strip()
                    if not stripped:
                        continue 
                    if stripped.startswith('#') or stripped.startswith('//'):
                        self.metrics['comment_lines'] += 1
                    elif stripped.startswith('/*') or stripped.endswith('*/'):
                        self.metrics['comment_lines'] += 1 # Basic block comment handling
                    else:
                        self.metrics['loc'] += 1
                
                content_str = "".join(lines)

            # 2. Structural Analysis (HCL Parsing)
            try:
                # Use hcl2 library to build an Abstract Syntax Tree (AST)
                data = hcl2.loads(content_str)
            except Exception:
                # If parsing fails (e.g. invalid syntax), we still keep LOC/Comments
                return 

            # --- Metrics Extraction from AST ---
            
            # Top-level counts
            self.metrics['num_resources'] += len(data.get('resource', []))
            self.metrics['num_modules'] += len(data.get('module', []))
            self.metrics['num_variables'] += len(data.get('variable', []))
            self.metrics['num_outputs'] += len(data.get('output', []))

            # Provider analysis (External Coupling)
            for provider_block in data.get('provider', []):
                if isinstance(provider_block, dict):
                    for p_name in provider_block.keys():
                        self._unique_providers.add(p_name)

            # Recursive deep-scan for Complexity and Code Smells
            self._scan_dict_recursive(data)

        except Exception as e:
            logger.debug(f"Could not analyze file {file_path}: {e}")

    def _scan_dict_recursive(self, data: Any):
        """
        Recursively explores the HCL dictionary to find complexity markers 
        and hard-coded values deep within the resource blocks.
        """
        if isinstance(data, dict):
            for key, value in data.items():
                # A. Complexity Analysis (IaC-McCabe approximation)
                # Any control flow or dynamic block increases logical complexity
                if key in ['count', 'for_each', 'dynamic']:
                    self.metrics['iac_mccabe_complexity'] += 1
                
                # B. Maintainability & Internal Coupling
                if isinstance(value, str):
                    self._analyze_string_value(key, value)

                self._scan_dict_recursive(value)
                
        elif isinstance(data, list):
            for item in data:
                self._scan_dict_recursive(item)

    def _analyze_string_value(self, key: str, value: str):
        """
        Analyzes a string to distinguish between parameterized references 
        (Good Quality) and hard-coded values (Technical Debt).
        """
        # 1. Internal Coupling Detection
        # Checks if the value refers to other internal components
        ref_patterns = ['var.', 'local.', 'module.', 'data.', 'resource.', 'aws_']
        if any(ref in value for ref in ref_patterns):
            self.metrics['internal_references'] += 1
            return 

        # 2. Hard-coded Values Detection (Code Smell)
        # We ignore keys that naturally expect static strings (e.g., metadata)
        ignored_keys = [
            'description', 'type', 'source', 'version', 'required_version', 
            'backend', 'alias', 'provider', 'name'
        ]
        
        # Criteria: Not in ignored keys, longer than 1 char, and no interpolation symbols
        if key not in ignored_keys and len(value) > 1:
            if "${" not in value:
                self.metrics['hard_coded_values'] += 1