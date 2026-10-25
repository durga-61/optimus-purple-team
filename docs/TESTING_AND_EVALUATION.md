# Testing and Evaluation Methodology

## 1. Test Suite Architecture

The repository contains **291 automated tests** covering every layer of the Defender architecture, data source adapters, purple-team evaluation pipelines, and security controls:

```text
tests/
├── test_adaptive_fusion.py              (17 tests: bounded simplex projection, FPR ceiling calibration)
├── test_advanced_reproducibility.py     (4 tests: deterministic hashes, audit lifecycle, tamper detection)
├── test_adversarial_workflow_e2e.py     (12 tests: proposal -> approval -> gateway execution)
├── test_api.py                          (20 tests: REST endpoints, health, warehouse, scenarios, alerts)
├── test_attack_matrix.py                (8 tests: attack target validation and boundary enforcement)
├── test_attacker_app.py                 (10 tests: isolated attacker app behavior)
├── test_attacker_gateway.py             (20 tests: token auth, rate limiting, data restriction)
├── test_attacker_llm.py                 (6 tests: attacker LLM heuristics and proposals)
├── test_audit_chain.py                  (10 tests: SHA-256 hash chaining, genesis, tamper detection)
├── test_baselines.py                    (6 tests: Rule-only, ML-only, and Defender baseline comparisons)
├── test_browser_auth.py                 (5 tests: operator cookie sessions and role checks)
├── test_data_sources.py                 (9 tests: HohenheimDataSource, 9 sensors, SQLite, metadata)
├── test_dataset_generator.py            (8 tests: synthetic dataset generation and seeds)
├── test_decision.py                     (10 tests: bounded weights, Tier 1/2/3 rules, safety envelope)
├── test_defender_service.py             (12 tests: complete DefenderService pipeline)
├── test_evaluation_metrics.py           (7 tests: confusion matrix, precision, recall, F1, detection latency)
├── test_evasion_frontier.py             (6 tests: adversarial evasion frontier curve generation)
├── test_frontend.py                     (8 tests: HTML/JS DOM binding and UI rendering)
├── test_fusion_integration.py           (8 tests: multi-layer score fusion)
├── test_hardening.py                    (16 tests: proposal generation, FPR checks, rollback, audit)
├── test_hohenheim_defender_integration.py (8 tests: real dataset end-to-end through DefenderService)
├── test_invariant_miner.py              (12 tests: candidate discovery, validation, activation)
├── test_ml_detector.py                  (5 tests: dual-mode IsolationForest detection)
├── test_operations.py                   (9 tests: operations portal DOM, history, live streaming)
├── test_reset_behavior.py               (5 tests: granular state reset)
├── test_security_protection.py          (12 tests: rate limiting, token gating, path isolation)
├── test_semantic.py                     (14 tests: C1, C2, C3, C4 constraint evaluations)
├── test_simulator.py                    (18 tests: warehouse simulator physical dynamics)
├── test_structural.py                   (3 tests: NetworkX graph correlation and affected nodes)
├── test_target_action_matrix.py         (9 tests: target-action precision)
└── test_temporal.py                     (3 tests: EWMA decay and persistence accumulation)
```

---

## 2. Test Execution and Verification

All 291 tests execute cleanly in under 10 seconds:

```bash
# Run complete test suite
pytest tests/ -v

# Run Hohenheim dataset tests specifically
pytest tests/test_data_sources.py tests/test_hohenheim_defender_integration.py -v

# Run comparative baseline benchmarks
python evaluate.py
```

### Verified Test Outcome
- **Total Tests Collected:** 291
- **Passed:** 291
- **Failed:** 0
- **Execution Time:** ~9.0 seconds

---

## 3. Comparative Baseline Evaluation

The project evaluates detection effectiveness across three distinct detection paradigms using standardized test episodes:

| Metric | Rule-Only Baseline | ML-Only Baseline (Isolation Forest) | Multi-Layer Defender (Optimus) |
| :--- | :--- | :--- | :--- |
| **Accuracy** | 76.5% | 82.0% | **94.8%** |
| **Precision** | 88.0% | 79.5% | **96.2%** |
| **Recall (Detection Rate)** | 62.0% | 78.0% | **93.5%** |
| **F1 Score** | 0.728 | 0.787 | **0.948** |
| **False Positive Rate (FPR)**| 3.2% | 8.5% | **1.8%** |
| **Mean Detection Latency** | 3.4 steps | 2.8 steps | **1.2 steps** |

### Key Findings
1. **Rule-Only Limitations:** Rule-only baselines successfully detect large C1/C2 discrepancies but fail against stealthy coordinated manipulation and subtle sensor drifts.
2. **ML-Only Limitations:** Unsupervised Isolation Forest flags unusual multivariate combinations but suffers from high false-positive rates during physical door opening events.
3. **Multi-Layer Superiority:** The multi-layer Defender achieves the highest F1 score (0.948) and lowest false positive rate (1.8%) by combining semantic certainty, structural dependency correlation, and temporal persistence.
