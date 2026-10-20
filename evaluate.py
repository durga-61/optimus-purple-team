#!/usr/bin/env python3
"""Evaluation CLI runner for Optimus Industrial Cybersecurity Platform.

Executes deterministic benchmarks across 12,000 normal and 12,000 attack observations,
computes overall classification metrics, per-class breakdown, detection latencies,
and exports publication-quality CSVs and PNG charts.
"""

import sys
from pathlib import Path

# Ensure repo root is on Python module search path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.evaluation.cli import run_evaluation

if __name__ == "__main__":
    sys.exit(run_evaluation())
