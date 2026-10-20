# OPTIMUS Project: Miss-Driven Self-Hardening Final Verification Report

**Document Title:** Empirical Verification, Latency Fairness Remediation, and Security Boundary Audit of the Miss-Driven Self-Hardening Purple-Team Loop  
**Repository:** `optimus-main`  
**Date:** October 20, 2026  
**Evaluation Scope:** Code Inspection, Latency Fairness Remediation, Held-Out Test Set Verification, Security Invariants, Test Suite Execution  
**Readiness Verdict:** **READY FOR REVIEW 2 SELF-HARDENING REQUIREMENT (VERIFIED & AUDITED)**

---

## 1. Executive Summary

This report documents the final, focused verification of the **Miss-Driven Self-Hardening Purple-Team Loop** in the OPTIMUS platform. The verification audited the source code against all functional and security claims, resolved the latency experiment fairness flaw through symmetric warmup and paired interleaved benchmarking, verified mathematical consistency of classification metrics on the identical 12,000 held-out test observations, confirmed security boundaries, and executed the full test suite.

### Key Verification Highlights:
1. **Source Code Audited:** Verified `app/defender/hardening.py`, `app/defender/service.py`, `app/api/routes/security.py`, `app/api/routes/attacker.py`, and `evaluate_hardening.py` against active code.
2. **Latency Fairness Fixed:** Corrected the cold-start caching asymmetry. Using symmetric 200-sample warmup and paired interleaved measurement across 12,000 observations under identical environmental conditions, the hardened pipeline exhibits a negligible latency overhead of **+0.053 ms** (+0.65% over baseline).
3. **Classification Metrics Mathematically Confirmed:** Verified on the identical held-out test split (12,000 samples: 2,400 normal, 9,600 attacks across 6 classes). Detection recall increased from **76.93% to 93.61%** (+16.68 percentage points), accuracy from **81.54% to 94.89%** (+13.35 percentage points), and F1-score from **86.96% to 96.70%** (+9.74 percentage points), while maintaining **0.00% False-Positive Rate** (0 false alarms on 2,400 normal observations).
4. **Security Controls Verified:** Explicit operator approval is strictly enforced before proposal activation (`PermissionError` on unauthorized activation). Attacker input through `/api/attacker/attack` can only queue candidate proposals in `PENDING_VALIDATION` state without modifying production rules. Rollback cleanly restores baseline parameters. Cryptographic SHA-256 audit chaining detects any payload alteration or reordering.
5. **Full Test Suite:** 100% passing rate across all test suites (**224 passed, 0 failed in 15.82s**, Exit Code: 0).

---

## 2. Experimental Setup & Latency Fairness Remediation

### 2.1 The Latency Measurement Fairness Problem
The initial evaluation run reported an apparent latency reduction for the hardened system (Baseline: 14.134 ms vs. Hardened: 9.119 ms). As noted in the preliminary report, this discrepancy was caused by an experimental fairness defect:
- The baseline system was measured first immediately after process startup, absorbing all one-time Python imports, JIT caching, memory allocator warmup, and OS page fault penalties (cold-start).
- The hardened system was evaluated second in the same process, benefiting from amortized memory caches and warm code paths.

### 2.2 The Remediation Protocol
To guarantee empirical rigor and fairness:
1. **Symmetric Warm-up:** Both `baseline_service` and `hardened_service` undergo an identical, unmeasured warm-up phase of 200 inference iterations using normal observations from `splits.train`.
2. **Buffer Sanitization:** Following warmup, runtime telemetry buffers (`observation_history`, `alerts`, `events`, `latest_event_hash = GENESIS_HASH`, `temporal_engine.reset()`) are cleared while preserving engine parameters and warm memory/JIT states.
3. **Paired & Interleaved Execution:** Rather than running in sequential blocks, observations are evaluated in paired interleaved order on each of the 12,000 test observations:
   - On even observation indices ($i \pmod 2 == 0$): Baseline is timed first, then Hardened.
   - On odd observation indices ($i \pmod 2 == 1$): Hardened is timed first, then Baseline.
   This guarantees that both systems experience identical background CPU scheduling slices, memory locality, and thermal conditions.
4. **Data Partition Discipline:** Detector parameters and proposal selections are derived strictly from `splits.val`. The held-out test split (`splits.test`) is never used to tune parameters or select proposals.

---

## 3. Empirical Results: Baseline vs. Hardened System

### 3.1 Overall Classification Performance (12,000 Held-Out Observations)

| Metric | Original Baseline | Hardened System | Delta (Absolute) | Delta (%) |
| :--- | :---: | :---: | :---: | :---: |
| **Total Test Observations** | 12,000 | 12,000 | 0 | 0.00% |
| **True Positives (TP)** | 7,385 | 8,987 | +1,602 | +21.69% |
| **True Negatives (TN)** | 2,400 | 2,400 | 0 | 0.00% |
| **False Positives (FP)** | 0 | 0 | 0 | 0.00% |
| **False Negatives (FN)** | 2,215 | 613 | -1,602 | -72.33% |
| **Overall Accuracy** | **81.54%** | **94.89%** | **+13.35%** | **+16.37%** |
| **Detection Recall** | **76.93%** | **93.61%** | **+16.68%** | **+21.68%** |
| **Precision** | **100.00%** | **100.00%** | **+0.00%** | **+0.00%** |
| **F1-Score** | **86.96%** | **96.70%** | **+9.74%** | **+11.20%** |
| **False-Positive Rate (FPR)** | **0.00%** | **0.00%** | **+0.00%** | **0.00%** |

### 3.2 Mathematical Verification of Metrics
- **Accuracy:** $(TP + TN) / \text{Total} = (8,987 + 2,400) / 12,000 = 11,387 / 12,000 = 0.948916... \approx 94.89\%$
- **Recall:** $TP / (TP + FN) = 8,987 / 9,600 = 0.936145... \approx 93.61\%$
- **Precision:** $TP / (TP + FP) = 8,987 / 8,987 = 1.0000 = 100.00\%$
- **F1-Score:** $2 \times (\text{Prec} \times \text{Rec}) / (\text{Prec} + \text{Rec}) = 2 \times 0.936145 / 1.936145 = 0.967020... \approx 96.70\%$
- **FPR:** $FP / (FP + TN) = 0 / 2,400 = 0.0000 = 0.00\%$

### 3.3 Per-Attack-Class Recall Breakdown (1,600 Samples Each)

| Attack Class | Original Baseline | Hardened System | Absolute Change | Detected / Total |
| :--- | :---: | :---: | :---: | :---: |
| **`capacity_manipulation`** | 100.00% | 100.00% | +0.00% | 1,600 / 1,600 |
| **`inventory_manipulation`** | 100.00% | 100.00% | +0.00% | 1,600 / 1,600 |
| **`sensor_spoofing`** | 100.00% | 100.00% | +0.00% | 1,600 / 1,600 |
| **`multi_source`** | 100.00% | 100.00% | +0.00% | 1,600 / 1,600 |
| **`replay_attack`** | 56.81% | 61.69% | +4.87% | 987 / 1,600 (+78) |
| **`coordinated_weak`** | 4.75% | 100.00% | +95.25% | 1,600 / 1,600 (+1,524) |

### 3.4 Corrected Fair Processing Latency Benchmark (Paired Interleaved, N = 12,000)

| Latency Metric | Original Baseline | Hardened System | Overhead (Delta) | Percentage Delta |
| :--- | :---: | :---: | :---: | :---: |
| **Mean Latency** | 8.189 ms | 8.242 ms | **+0.053 ms** | **+0.65%** |
| **Median Latency** | 7.939 ms | 7.962 ms | **+0.023 ms** | **+0.29%** |
| **95th Percentile (P95)** | 9.662 ms | 9.730 ms | **+0.068 ms** | **+0.70%** |
| **99th Percentile (P99)** | 11.516 ms | 11.606 ms | **+0.090 ms** | **+0.78%** |

*Empirical Finding:* Under fair paired measurement with identical warmup, the hardened system introduces a negligible processing overhead of **53 microseconds per observation** (+0.65%). Tightening invariant tolerances adds zero computational complexity, as scalar comparisons remain identical operations.

---

## 4. Implementation & Security Controls Verification

### 4.1 Root Cause Diagnosis & Proposal Generation (`app/defender/hardening.py`)
- **Diagnosis Mechanism:** Ingests unflagged observations (`NORMAL` classification on ground-truth attacks) and evaluates multi-layer evidence.
  - Detects `STEALTHY_CAPACITY_SLACK_BELOW_C1_TOLERANCE` when discrepancy $0 < \Delta \le \text{tol}_{c1}$.
  - Detects `STEALTHY_FLOW_DISCREPANCY_BELOW_C2_TOLERANCE` when discrepancy $0 < \Delta \le \text{tol}_{c2}$.
  - Detects `COMPOSITE_RISK_BELOW_PRIMARY_THRESHOLD` when risk is elevated ($\ge 0.20$) but below threshold.
  - Falls back to `MULTI_STAGE_CORROBORATION_GAP`.
- **Safety Bounds Enforcement:** Parameter adjustments are clamped strictly within `PARAMETER_BOUNDS`:
  - `c1_tolerance`: $[0.10, 0.50]$
  - `c2_tolerance`: $[0.10, 0.50]$
  - `primary_risk_threshold`: $[0.25, 0.50]$
  - `suspicious_risk_threshold`: $[0.10, 0.30]$
- **Validation Gate:** Candidate proposals are tentatively simulated against `splits.val`. Any proposal causing $\text{FPR} > 0.001$ or failing to improve detection recall/F1 is marked `REJECTED`.

### 4.2 Human-in-the-Loop Operator Approval Boundary
- **Code Inspection:** In `HardeningEngine.activate_proposal(proposal_id)`:
  ```python
  if not proposal.operator_approved or proposal.status != "APPROVED":
      raise PermissionError("explicit operator approval is required.")
  ```
- **API Guard:** In `app/api/routes/security.py`, endpoint `POST /api/security/hardening/proposals/{proposal_id}/approve` requires operator authentication (`Depends(verify_operator_access)`) and an explicit `approved=True` payload.
- **Verification:** Unit tests confirm that direct calls to `activate_proposal` without prior operator approval trigger a `PermissionError`.

### 4.3 Attacker Isolation & Integrity Protection (`app/api/routes/attacker.py`)
- **Code Inspection:** The external attacker gateway exposes only `/api/attacker/*`, authenticated via Bearer token (`verify_gateway_token`).
- **One-Way Ingestion:** When an attack is undetected (`detection_status == "UNDETECTED"`), the gateway calls `engine.record_miss()` and `engine.generate_proposal()`. The resulting proposal is placed in `PENDING_VALIDATION` state with `operator_approved=False`.
- **Verification:** The attacker route contains no code paths to approve proposals, call `activate_proposal`, or mutate runtime configuration parameters.

### 4.4 Rollback & Baseline Preservation
- **Code Inspection:** `HardeningEngine.rollback()` restores parameters from `self.baseline_config` (`c1_tolerance=0.50`, `c2_tolerance=0.50`, `primary_risk_threshold=0.40`). Live engines in `DefenderService` are updated immediately, active proposal IDs are cleared, and proposal status is updated to `ROLLED_BACK`.
- **Audit Verification:** Rollback emits a `HARDENING_ROLLED_BACK` security event linked into the SHA-256 audit chain.

### 4.5 SHA-256 Cryptographic Audit Chaining (`app/defender/audit.py`)
- **Hash Chaining:** Every hardening lifecycle event (`HARDENING_MISS_RECORDED`, `HARDENING_PROPOSAL_GENERATED`, `HARDENING_PROPOSAL_VALIDATED`, `HARDENING_PROPOSAL_REJECTED`, `HARDENING_PROPOSAL_APPROVED`, `HARDENING_PROPOSAL_ACTIVATED`, `HARDENING_ROLLED_BACK`) computes `event_hash = SHA256(canonical(event, prev_hash))`.
- **Integrity Verification:** Tested via `test_sha256_audit_chain_links_all_hardening_events`. Modifying any event payload invalidates the chain, identifying the exact tampering index.

---

## 5. Distinction: Measured Facts, Limitations, and Unestablished Claims

### 5.1 Measured Facts (Empirically Verified)
1. **Recall Improvement:** Hardened system achieves **93.61% recall** on 12,000 test observations (+16.68% absolute improvement over baseline).
2. **Zero False-Positive Rate:** 0 false positives observed across 2,400 normal held-out test observations and continuous normal warehouse operations.
3. **Coordinated Weak Attack Elimination:** Recall on `coordinated_weak` attacks increased from **4.75% to 100.00%** (+1,524 detected attacks out of 1,600).
4. **Latency Overhead:** Fair paired measurement demonstrates a negligible mean latency increase of **+0.053 ms** (+0.65%).
5. **Deterministic Reproduction:** All metrics reproduce identically with random seed 42.

### 5.2 Documented Operational Limitations
1. **Replay Attack Residual Misses:** 38.31% of replay attacks (613 out of 1,600) evade primary detection. When warehouse inventory is stationary (zero inbound/outbound flow) and sensor temperature/humidity fall within natural ambient drift tolerances, replaying authentic historical observations creates zero semantic invariant discrepancies. Complete elimination of replay attacks requires hardware cryptographic primitives (monotonic counters, edge HMACs, TLS nonces) rather than passive application-layer monitoring.
2. **In-Memory Audit Chain Lifespan:** The cryptographic audit chain is maintained in-process memory. While tamper-evident against runtime modification, it does not survive process restarts and does not replace write-once-read-many (WORM) external storage.
3. **Parameter Scope:** Hardening proposals in this phase are bounded adjustments to invariant tolerances ($C_1, C_2$) and decision thresholds. Dynamic Daikon-style invariant grammar synthesis is not currently implemented.

### 5.3 Claims Not Established / Out of Scope
1. **Adaptive Fusion Weights:** Dynamic online weight adjustment (reinforcement-based or gradient-based fusion weight adaptation) is **NOT** implemented in this phase. Weights remain static hyperparameters.
2. **Distributed Multi-Tenant Consensus:** The current implementation is designed for single-organization cold-storage monitoring and does not provide multi-region Byzantine fault tolerance.

---

## 6. Automated Test Suite Results

Full automated test suite executed via `python -m pytest tests/`:
- **Command:** `python -m pytest tests/`
- **Result:** **224 passed, 1 warning in 15.82s**
- **Exit Code:** `0`
- **Coverage Summary:**
  - `tests/test_hardening.py`: 11 passed (miss capture, validation, FP rejection, approval gate, rollback, audit chaining, API endpoints)
  - `tests/test_audit_chain.py`: 19 passed (canonical serialization, hash linking, tampering detection, empty chain)
  - `tests/test_attacker_gateway.py`: 20 passed (gateway security, rate limiting, isolation)
  - `tests/test_defender_service.py`: 8 passed (multi-stage pipeline, alert dispatch)
  - `tests/test_fusion_integration.py`: 8 passed (multi-layer fusion, corroboration)
  - All other tests (simulator, evaluation, reset, API): 158 passed

---

## 7. Files Changed in This Verification

1. **`evaluate_hardening.py`**:
   - Implemented `warmup_pipeline()` to perform symmetric 200-sample warmup on training data before timing.
   - Implemented `evaluate_paired_pipelines_on_split()` with alternating execution order to eliminate order and caching bias.
   - Added overall accuracy computation and export to JSON/CSV.
2. **`evaluation_results/hardening_comparison.json`**:
   - Updated with fair paired latency measurements and confirmed classification metrics.
3. **`evaluation_results/hardening_comparison.csv`**:
   - Updated with fair paired latency measurements, overall accuracy, and deltas.
4. **`docs/HARDENING_VERIFICATION_REPORT.md`**:
   - Complete technical audit report documenting code verification, latency fairness correction, empirical metrics, limitations, and security controls.

---

## 8. Final Readiness Verdict

**Verdict:** **READY FOR OPERATOR REVIEW & SUBSEQUENT PHASE APPROVAL**

The Miss-Driven Self-Hardening Purple-Team Loop is thoroughly verified, mathematically consistent, latency-fair, and backed by robust security boundaries. No subsequent features (such as adaptive fusion weights) have been introduced. The codebase is halted and awaiting operator approval.
