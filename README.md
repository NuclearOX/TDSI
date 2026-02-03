# TerraPulse

**TerraPulse** is an automated research framework designed to analyze the co-evolution of **Structural Quality Debt** and **Security Debt** in Terraform-based Infrastructure as Code (IaC). 

This project serves as the replication package for the empirical study conducted for the "Software Evolution and Quality" course at the University of Sannio (Benevento, Italy).

---

## Research Overview

The goal of this study is to determine if the structural way code is written (Complexity, Coupling, and Code Smells) serves as a leading indicator for security vulnerabilities. We answer three key Research Questions:

- **RQ1 - Association:** Is there a statistically significant correlation between Structural Quality Debt and Security Debt?
- **RQ2 - Prediction:** Which structural attributes (e.g., Variable Count, Resource Density) serve as the best predictors for Security Debt?
- **RQ3 - Evolution:** How do Quality and Security Debt change reciprocally as a Terraform module matures over time?

## Key Features

- **Adaptive History Mining:** Uses `PyDriller` and a custom "Smart Sampling" strategy to extract snapshots from either official Git Tags (Releases) or significant commits across the entire project history.
- **Forced State Analysis:** Implements a robust `git checkout -f` logic to ensure every analysis is performed on the exact historical state of the files.
- **Multi-vocal Quality Model:** Integrates metrics from **Dalla Palma et al. (2020)** and **Konala et al. (2025)**, mapping Terraform attributes to the ISO/IEC 25010 standard.
- **Deep Security Scanning:** Wraps **AquaSecurity Trivy** to categorize debt into Infrastructure Misconfigurations, Dependency Vulnerabilities (CVEs), and Hard-coded Secrets.
- **Resilient Execution:** Features a multiprocessing-based hard-timeout (1 hour per repo) and incremental resume logic to survive system crashes.

---

## Project Structure

```text
TerraPulse/
├── data/
│   ├── input/              # Source database (TerraDS.sqlite)
│   └── output/             # CSV datasets and generated figures
├── src/
│   ├── main.py             # Orchestrates the mining and analysis
│   ├── config.py           # Global settings, weights, and thresholds
│   ├── mining/             # Repository mining and sampling logic
│   ├── metrics/            # Quality (HCL2) and Security (Trivy) models
│   └── analysis/           # Statistical analysis (Spearman, Random Forest)
├── Dockerfile              # Reproducible containerized environment
└── requirements.txt        # Python dependencies
```

---

## Usage Guide

### 1. Build the Environment
Ensure Docker is installed, then build the research image:
```bash
docker build -t terrapulse .
```

### 2. Data Collection (Mining)
Run the main mining pipeline. This will clone repositories, travel through history, and generate the dataset:
```bash
docker run --rm -v ${PWD}:/app terrapulse
```
*The tool will automatically skip already processed repositories found in `dataset_final.csv`.*

### 3. Statistical Analysis
Once mining is complete, generate the results for the paper:
```bash
# RQ1 & RQ2: Correlation and Prediction
docker run --rm --entrypoint "" -v ${PWD}:/app terrapulse python src/analysis/rq1_correlation.py
docker run --rm --entrypoint "" -v ${PWD}:/app terrapulse python src/analysis/rq2_prediction.py

# RQ3: Evolutionary Analysis & Step-Plots
docker run --rm --entrypoint "" -v ${PWD}:/app terrapulse python src/analysis/rq3_evolution.py
```

---

## Methodology & Main References

The metrics and methodologies used in this tool are grounded in the following academic works:

1.  **Konala et al. (2025)** - *A Framework for Measuring the Quality of Infrastructure-as-Code Scripts.* (Quality Mapping Framework).
2.  **Dalla Palma et al. (2020)** - *Toward a catalogue of software quality metrics for infrastructure code.* (Structural Metrics).
3.  **Rahman et al. (2019)** - *The Seven Sins: Security Smells in Infrastructure as Code Scripts.* (Security Debt Weights).
4.  **Spadini et al. (2018)** - *PyDriller: Python framework for mining software repositories.* (Mining Engine).

---

## Academic Context
- **Course:** Software Evolution and Quality [39939]
- **Institution:** Università degli Studi del Sannio, Benevento
- **Professor:** Damian Andrew Tamburri

---
