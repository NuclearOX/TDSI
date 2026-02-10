import hcl2
import os
import logging
import re
from typing import Dict, Any

logger = logging.getLogger(__name__)

class QualityAnalyzer:
    """
    Advanced structural analyzer for Terraform, based on Dalla Palma et al. (2020),
    Konala et al. (2025), and inspired by the TerraMetrics AST approach (Begoug et al., 2024).
    This class extracts multi-dimensional metrics to quantify Structural Quality Debt.
    """
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        
        # Initialize metrics dictionary covering the main ISO/IEC 25010 characteristics
        self.metrics = {
            # --- SIZE & STRUCTURE (ISO: Functional Suitability) ---
            'loc': 0,                  # Lines of Code (clean source)
            'num_resources': 0,        # Total managed resources and data sources
            'files_analyzed': 0,       # Total .tf files successfully processed
            
            # --- COMPLEXITY (ISO: Maintainability / Analysability) ---
            # Approximated McCabe Complexity: loops (count/for_each), 
            # dynamic blocks, and ternary operators (condition ? a : b)
            'iac_mccabe_complexity': 0, 
            
            # --- COUPLING & INTEGRATION (ISO: Modularity / Compatibility) ---
            'num_modules': 0,          # External module calls (reusability/coupling)
            'num_providers': 0,        # Distinct infrastructure providers (agility debt)
            'internal_references': 0,  # Internal connectivity (links between resources)
            
            # --- INTERFACE (ISO: Reusability) ---
            'num_variables': 0,        # Module input surface
            'num_outputs': 0,          # Module output surface
            
            # --- MAINTAINABILITY (ISO: Modifiability / Documentation) ---
            'hard_coded_values': 0,    # Lack of parameterization (Code Smell)
            'comment_lines': 0         # Self-documentation level
        }
        self._unique_providers = set()

    def analyze(self) -> Dict[str, Any]:
        """
        Recursively scans the repository, prunes non-production directories, 
        and aggregates structural metrics.
        """
        # Reset counters for fresh execution
        for k in self.metrics: 
            if isinstance(self.metrics[k], int): self.metrics[k] = 0
        self._unique_providers = set()

        for root, dirs, files in os.walk(self.repo_path):
            # Prune non-production directories to ensure scientific validity.
            # We exclude examples, tests, and technical metadata.
            dirs_to_exclude = [
                '.git', '.terraform', '.idea', '.vscode', 'vendor', 'node_modules',
                'examples', 'example', 'tests', 'test', 'fixtures', 'modules_override'
            ]
            dirs[:] = [d for d in dirs if d not in dirs_to_exclude]
            
            for file in files:
                if file.endswith('.tf'):
                    file_path = os.path.join(root, file)
                    self._analyze_file(file_path)
        
        # Finalize providers count and base complexity
        self.metrics['num_providers'] = len(self._unique_providers)
        
        # Base complexity is at least 1 if the module contains code
        if self.metrics['loc'] > 0:
            self.metrics['iac_mccabe_complexity'] += 1
            
        return self.metrics

    def _analyze_file(self, file_path: str):
        """
        Performs dual-level analysis: textual (regex/lines) and structural (HCL2 AST).
        """
        try:
            # Use 'ignore' errors to handle non-UTF8 characters in old/binary files
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()
                self.metrics['files_analyzed'] += 1
                
                # 1. Text-level Analysis (LOC, Comments, and Ternaries)
                for line in lines:
                    stripped = line.strip()
                    if not stripped: continue 
                    if stripped.startswith(('#', '//')):
                        self.metrics['comment_lines'] += 1
                    else:
                        self.metrics['loc'] += 1
                
                # Detect Ternary Operators (decision points) using Regex
                # This is a key complexity metric from Begoug et al. (2024)
                ternaries = len(re.findall(r'\?\s*.*\s*:', content))
                self.metrics['iac_mccabe_complexity'] += ternaries

            # 2. Structural Analysis using HCL2 Parser (AST representation)
            try:
                data = hcl2.loads(content)
            except Exception:
                # If parsing fails, we still kept textual metrics (LOC/Comments)
                return 

            # Extract high-level structural counts
            self.metrics['num_resources'] += len(data.get('resource', []))
            self.metrics['num_resources'] += len(data.get('data', [])) # Include data sources
            self.metrics['num_modules'] += len(data.get('module', []))
            self.metrics['num_variables'] += len(data.get('variable', []))
            self.metrics['num_outputs'] += len(data.get('output', []))

            # Aggregate unique providers
            for provider_block in data.get('provider', []):
                if isinstance(provider_block, dict):
                    for p_name in provider_block.keys():
                        self._unique_providers.add(p_name)

            # Deep recursive scan for Meta-arguments and connectivity
            self._scan_dict_recursive(data)

        except Exception as e:
            logger.debug(f"Error analyzing {file_path}: {e}")

    def _scan_dict_recursive(self, data: Any):
        """
        Deeply explores the HCL tree to find meta-arguments and string-based debt.
        """
        if isinstance(data, dict):
            for key, value in data.items():
                # Complexity: Meta-arguments for loops and dynamic blocks
                if key in ['count', 'for_each', 'dynamic']:
                    self.metrics['iac_mccabe_complexity'] += 1
                
                # Connectivity and Hard-coding analysis
                if isinstance(value, str):
                    self._analyze_string_value(key, value)

                self._scan_dict_recursive(value)
                
        elif isinstance(data, list):
            for item in data:
                self._scan_dict_recursive(item)

    def _analyze_string_value(self, key: str, value: str):
        """
        Distinguishes between internal connectivity (Quality) and 
        hard-coded values (Technical Debt).
        """
        # 1. Internal Coupling (Connectivity)
        # We look for references to variables, locals, or other resources
        ref_patterns = ['var.', 'local.', 'module.', 'data.', 'aws_', 'google_', 'azurerm_']
        if any(ref in value for ref in ref_patterns):
            self.metrics['internal_references'] += 1
            return 

        # 2. Hard-coded Values (Structural Debt)
        # We ignore structural HCL keys that naturally require static strings
        ignored_keys = [
            'description', 'type', 'source', 'version', 'required_version', 
            'backend', 'alias', 'provider', 'name', 'key'
        ]
        
        # Criteria: Not an ignored key, long enough to be significant, and not interpolated
        if key not in ignored_keys and len(value) > 1:
            if "${" not in value: # If it's a simple string without interpolation
                self.metrics['hard_coded_values'] += 1