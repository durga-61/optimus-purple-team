# Testing and Evaluation Methodology

## 1. Test Suite Architecture

The repository contains **317 automated tests** covering every layer of the Defender architecture, data source adapters, purple-team evaluation pipelines, and security controls:

```text
tests/
├── test_defender_service.py, test_decision.py, test_semantic.py,
│   test_temporal.py, test_structural.py, test_ml_detector.py
├── test_audit_chain.py, test_hardening.py, test_adaptive_fusion.py,
│   test_invariant_miner.py, test_baselines.py, test_evasion_frontier.py
├── test_experiment_engine.py, test_attack_matrix.py, test_target_action_matrix.py
├── test_data_sources.py, test_hohenheim_defender_integration.py
├── test_api.py, test_frontend.py, test_operations.py, test_security_protection.py
├── test_attacker_app.py, test_attacker_gateway.py, test_attacker_llm.py
└── ... (the full suite is 317 tests; the count grows as modules are added)
```


---

## 2. Test Execution and Verification

All 317 tests execute cleanly in under 15 seconds:

```bash
# Run complete test suite
pytest tests/ -v

# Run Hohenheim dataset tests specifically
pytest tests/test_data_sources.py tests/test_hohenheim_defender_integration.py -v

# Run comparative baseline benchmarks
python -m app.evaluation.cli --split test --output-dir evaluation_results/final_benchmark
```

### Verified Test Outcome
- **Total Tests Collected:** 317
- **Passed:** 317
- **Failed:** 0
- **Warnings:** 2 (non-blocking)
- **Execution Time:** ~13.2 seconds

---

## 3. Comparative Baseline Evaluation

The project evaluates detection effectiveness across three distinct detection paradigms using standardized test episodes:

Held-out test split: 2,400 normal + 9,600 attack observations (six classes, 1,600 each), seed 42. These are the canonical Review 3 numbers; see `docs/REVIEW3_FINAL_REPORT.md` §2 for the full tables.

| System | Accuracy | Precision | Recall | F1 | FPR | Evasion |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| OPTIMUS static | 81.54% | 100.00% | 76.93% | 0.8696 | 0.00% | 23.07% |
| **OPTIMUS + mined invariants** | **95.52%** | **100.00%** | **94.40%** | **0.9712** | **0.00%** | **5.60%** |
| One-Class SVM | 46.67% | 100.00% | 33.33% | 0.5000 | 0.00% | 66.67% |
| PCA reconstruction | 79.99% | 100.00% | 74.99% | 0.8571 | 0.00% | 25.01% |

### Key Findings
1. **No single layer is sufficient:** ML-only recall is 5.17%, semantic-only is 61.01%, and the joint decision is the only configuration that combines 76.93% recall with 0.00% FPR.
2. **Invariants close the coordinated-weak gap:** recall rises to 94.40% and F1 to 0.9712 while FPR stays at zero; replay remains the hardest class (56.81% static / 66.37% with invariants).
3. **Replay is a provenance problem:** replay evasion is 100% at full strength for every detector. Cryptographic freshness is required; passive analytics cannot fix it.
4. **Real-data calibration is open:** on 600 unmodified Hohenheim observations the current envelope/spatial rules produced 84.0% alert states. Use the synthetic benchmark for the controlled comparison and a stable step (e.g., step 30) for the real-data demo.
