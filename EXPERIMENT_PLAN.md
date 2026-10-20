# EXPERIMENT PLAN

## Experiment 1 — Normal Baseline

Run the system without attacks.

Measure:

* false-positive rate;
* baseline ML behavior;
* semantic violations;
* temporal alerts;
* structural alerts.

---

## Experiment 2 — Capacity Manipulation

Manipulate reported free capacity.

Measure:

* ML detection;
* semantic detection;
* final detection;
* detection delay.

---

## Experiment 3 — Inventory Manipulation

Manipulate inventory independently.

Evaluate inventory-flow consistency.

---

## Experiment 4 — Sensor Spoofing

Manipulate telemetry.

Evaluate cross-source and semantic consistency.

---

## Experiment 5 — Replay

Replay previously valid observations.

Evaluate whether freshness/state continuity detects the replay.

If not detected, document the limitation.

---

## Experiment 6 — Coordinated Weak Attack

Introduce small manipulations across multiple related sources.

Evaluate:

* ML;
* semantic;
* temporal;
* structural;
* joint system.

---

## Experiment 7 — Collusion

Manipulate multiple sources consistently.

Determine the boundary at which the framework cannot distinguish false consistency from truth.

---

## Experiment 8 — Severity Sweep

Vary attack magnitude.

Calculate metrics independently for every severity.

Do not reuse metrics from another experiment.

---

## Experiment 9 — Ablation

Compare:

A. ML
B. Semantic
C. Semantic + Temporal
D. Semantic + Structural
E. Full

Report:

* precision;
* recall;
* F1;
* detection delay.

---

## Experiment 10 — AI Attacker

Evaluate LLM-generated attacks.

Measure:

* number of proposals;
* valid proposal rate;
* executed attacks;
* detected attacks;
* successful evasions;
* attack severity;
* adaptation behavior.

AI attacker results must be reported separately from the core defender evaluation.

---

## Experiment 11 — Trusted-Label Adaptive Fusion

Learn bounded fusion weights on the validation split and compare static vs adaptive weights on held-out test data.

Report:

* selected weights and bounds;
* validation F1/FPR and threshold;
* held-out rule classification;
* held-out risk-threshold classification;
* whether the adapted vector was adopted or the static vector was retained.

---

## Experiment 12 — Dynamic Invariant Mining

Discover candidates from training normals, validate them on independent validation normals/attacks, and activate approved rules.

Report:

* candidates discovered, validated, rejected, and active;
* rejection reasons;
* per-class attack detection and normal false-positive rate;
* held-out effect of mined invariants alone and combined with adaptive fusion;
* audit-chain validity and rollback result.

---

## Experiment 13 — Independent Baselines and Evasion Frontier

Fit One-Class SVM and PCA on normal training data only, calibrate on validation data, and evaluate on held-out test data.

Then sweep attack magnitude across every attack class and compare:

* static OPTIMUS;
* adaptive fusion;
* mined invariants;
* combined system;
* One-Class SVM;
* PCA.

Report:

* precision, recall, F1, false-positive rate, and evasion rate;
* evasion at each attack strength;
* mean evasion across strengths;
* limitations that cannot be resolved by passive monitoring.
