import os
import re
import logging
import hashlib
import sys
from typing import Dict, List, Any

# Configure Logger to stderr
logger = logging.getLogger("CustomSmells")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('[%(asctime)s] [SMELLS] %(message)s'))
    logger.addHandler(handler)

# Metric Thresholds (Definable in thesis methodology)
MONOLITH_THRESHOLD = 20  # Resources per file
DUPLICATION_MIN_LINES = 3 # Minimum size of block to check

def check_custom_smells(directory: str) -> Dict[str, int]:
    """
    Scans a directory for thesis-specific maintainability smells:
    1. Missing Documentation (Variables/Outputs)
    2. Monolithic Modules (Files with too many resources)
    3. Code Duplication (Identical resource blocks)
    """
    logger.info(f"Scanning for custom smells in: {directory}")
    
    metrics = {
        "missing_descriptions": 0,
        "monolithic_modules": 0,
        "duplicated_blocks": 0
    }

    tf_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".tf"):
                tf_files.append(os.path.join(root, file))

    # 1. Analyze File Structure (Docs & Monoliths)
    _analyze_structure(tf_files, metrics)
    
    # 2. Analyze Duplication
    _analyze_duplication(tf_files, metrics)
    
    logger.info(f"Custom Smell Detection Complete: {metrics}")
    return metrics

def _analyze_structure(files: List[str], metrics: Dict[str, int]):
    """Checks for Missing Descriptions and Monolithic Files."""
    # Regex to capture variable/output declarations
    block_header_regex = re.compile(r'^\s*(variable|output)\s+"([^"]+)"', re.MULTILINE)
    # Regex to count resources
    resource_regex = re.compile(r'^\s*(resource|module)\s+"', re.MULTILINE)

    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # --- CHECK 1: Monolithic Files ---
                resource_count = len(resource_regex.findall(content))
                if resource_count > MONOLITH_THRESHOLD:
                    metrics["monolithic_modules"] += 1
                    logger.debug(f"Monolith detected: {os.path.basename(file_path)} ({resource_count} resources)")

                # --- CHECK 2: Missing Documentation ---
                # We iterate line by line for context
                lines = content.splitlines()
                for i, line in enumerate(lines):
                    match = block_header_regex.match(line)
                    if match:
                        # Look ahead for 'description' in the next few lines
                        has_desc = False
                        for j in range(1, 25): # Look ahead window
                            if i + j >= len(lines): break
                            target_line = lines[i+j]
                            
                            # Stop if we hit the closing brace of the block
                            if target_line.strip() == "}": 
                                break
                            
                            if "description" in target_line and "=" in target_line:
                                has_desc = True
                                break
                        
                        if not has_desc:
                            metrics["missing_descriptions"] += 1
                            
        except Exception as e:
            logger.warning(f"Error reading {file_path}: {e}")

def _analyze_duplication(files: List[str], metrics: Dict[str, int]):
    """
    Detects structural duplication by hashing resource blocks.
    Normalizes content (removes names) to find 'Copy-Paste-Modify' patterns.
    """
    block_hashes = {}
    
    # Regex to find start of resource/module
    block_start = re.compile(r'^\s*(resource|module)\s+"')
    
    all_normalized_blocks = []

    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            current_block = []
            in_block = False
            brace_balance = 0
            
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"): continue
                
                if not in_block:
                    if block_start.match(line):
                        in_block = True
                        current_block = [stripped]
                        # Count braces to find end of block
                        brace_balance = line.count("{") - line.count("}")
                else:
                    current_block.append(stripped)
                    brace_balance += line.count("{") - line.count("}")
                    
                    if brace_balance == 0:
                        # Block End
                        in_block = False
                        
                        # Normalization: Join and remove specific names/strings 
                        # to detect "Logic Duplication" rather than exact text matches
                        full_text = "".join(current_block)
                        # Remove content inside quotes to treat 'resource "aws_s3" "A"' same as 'resource "aws_s3" "B"'
                        normalized = re.sub(r'"[^"]+"', '""', full_text)
                        
                        all_normalized_blocks.append(normalized)
                        
        except Exception:
            continue

    # Hash and Count
    for block in all_normalized_blocks:
        # MD5 is fast and sufficient for this
        h = hashlib.md5(block.encode('utf-8')).hexdigest()
        block_hashes[h] = block_hashes.get(h, 0) + 1
        
    # Calculate Debt: (Count - 1) for every collision
    duplicates = 0
    for h, count in block_hashes.items():
        if count > 1:
            duplicates += (count - 1)
            
    metrics["duplicated_blocks"] = duplicates
    if duplicates > 0:
        logger.info(f"Found {duplicates} duplicated configuration blocks.")