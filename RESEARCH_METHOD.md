# RESEARCH METHOD

## 1. Problem

Distributed IoT-enabled operational systems combine heterogeneous sources such as sensors, inventory systems, operational ledgers, and historical records.

An attacker may manipulate individual sources while maintaining values that appear statistically plausible.

Therefore conventional anomaly detection may fail to identify integrity attacks.

---

## 2. Proposed Approach

The proposed system combines:

1. ML anomaly detection;
2. semantic constraint verification;
3. temporal evidence;
4. structural evidence;
5. joint escalation.

---

## 3. Semantic Verification

The system checks whether observations satisfy known operational relationships.

### Capacity

inventory + free capacity ≈ total capacity

### Inventory Flow

current inventory ≈ previous inventory + inbound - outbound

### Historical

current observations should remain compatible with an appropriate historical operating envelope.

---

## 4. Temporal Escalation

Repeated violations are aggregated across a time window.

Persistence and recurrence increase the significance of otherwise weak observations.

---

## 5. Structural Escalation

Related sources and entities are represented structurally.

Suspicious activity involving related components contributes additional evidence.

---

## 6. Joint Decision

The final decision combines the available evidence.

This avoids depending exclusively on ML or any single source.

### 6.1 Trusted-Label Adaptive Fusion

The static fusion vector can be replaced by a bounded vector learned offline from an independent validation split.

Constraints:

* non-negative weights that sum to 1.0;
* per-layer safety bounds so no layer can be silenced or dominate;
* optimisation against weighted-risk F1 under a hard false-positive-rate ceiling;
* static weights retained unless the candidate is at least as good on validation;
* only trusted validation labels, never attacker claims or live feedback.

The deterministic classification pathways are not changed. Adaptive fusion therefore targets the continuous risk score, not the rule labels.

### 6.2 Dynamic Invariant Mining

Candidate residual, envelope, slew, and shipment-rate rules are discovered from clean training telemetry.

A candidate is activated only if it:

* preserves normal coverage above the configured minimum;
* stays below the false-positive-rate ceiling;
* has stable coverage across validation halves;
* discriminates known attacks above the minimum detection rate;
* is not redundant with C1/C2 or a stronger accepted rule;
* is explicitly approved by an operator.

Rollback removes active mined rules and restores baseline semantics.

---

## 7. Evaluation

Evaluate:

* normal traffic;
* individual integrity attacks;
* weak attacks;
* coordinated attacks;
* replay;
* collusion;
* varying attack severity.

Metrics:

* precision;
* recall;
* F1;
* false-positive rate;
* detection delay;
* evasion rate across attack magnitudes.

Independent One-Class SVM and PCA baselines are fitted on normal training data only, calibrated on validation data, and evaluated once on held-out test data. The evasion frontier sweeps attack magnitude across all six attack classes and compares static OPTIMUS, adaptive fusion, mined invariants, the combined system, and both baselines.

All splits, manifests, and artifact checksums are exported so results can be reproduced.

---

## 8. Ablation

Compare:

ML only
Semantic only
Semantic + Temporal
Semantic + Structural
Full System
Full System + adaptive fusion
Full System + mined invariants
Full System + both
One-Class SVM
PCA

The purpose is to determine which components contribute to detection.

---

## 9. Adversarial Evaluation

After Part 1 is stable, an LLM-based attacker generates controlled attack proposals.

The attacker is evaluated as an adversarial test generator rather than as the core security contribution.

The evasion frontier provides a separate, deterministic severity sweep so attack-magnitude effects can be measured without relying on LLM variability.
