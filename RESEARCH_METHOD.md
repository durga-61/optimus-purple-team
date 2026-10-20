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
* detection delay.

---

## 8. Ablation

Compare:

ML only
Semantic only
Semantic + Temporal
Semantic + Structural
Full System

The purpose is to determine which components contribute to detection.

---

## 9. Adversarial Evaluation

After Part 1 is stable, an LLM-based attacker generates controlled attack proposals.

The attacker is evaluated as an adversarial test generator rather than as the core security contribution.
