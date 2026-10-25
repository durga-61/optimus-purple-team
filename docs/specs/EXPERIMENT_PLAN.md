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
