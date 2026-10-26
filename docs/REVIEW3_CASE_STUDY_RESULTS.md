# Review 3 — Scaled-Down Case-Study Attack Results

> Part of the Review 3 final report: [`docs/REVIEW3_FINAL_REPORT.md`](REVIEW3_FINAL_REPORT.md) §3.6.

Generated: 2026-10-26T08:37:01.685738+00:00  
Dataset: University of Hohenheim cold-storage telemetry ([Zenodo 15130001](https://zenodo.org/records/15130001), DOI `10.5281/zenodo.15130001`)  
Live pipeline: `DefenderService` + `ExperimentEngine`  
Baseline step: 30  
Commit: `8b57f16`


> Ground-truth labels are retained only in the experiment record and are not passed to the Defender. The attack transformations are the same ones used by the Attack Simulator portal.


## 1. Summary

| Case | Stage | Steps | Detected? | Max classification | Max risk |
|---|---|---|---:|---|---:|
| `baseline_normal` | normal operation | 30 | CORRECT (no alert) | NORMAL | 0.035 |
| `sustained_setpoint_runaway` | controller setpoint / actuator manipulation | 30, 31, 32 | DETECTED | POTENTIAL_ATTACK | 0.473 |
| `subtle_in_envelope_change` | stealthy setpoint manipulation | 30, 31, 32, 33, 34, 35 | MISSED | NORMAL | 0.029 |
| `localized_cross_sensor_spoof` | sensor spoofing | 30 | DETECTED | SUSPICIOUS | 0.325 |
| `valid_frame_replay` | replay | 30 | MISSED | NORMAL | 0.061 |
| `telemetry_suppression` | telemetry suppression | 30 | MISSED | NORMAL | 0.052 |
| `hidden_hot_telemetry_replay` | telemetry substitution | 30 | MISSED | NORMAL | 0.061 |

## 2. Step-by-step results


### `baseline_normal` — normal operation

Clean recorded observation; no manipulation. Ground truth NORMAL.

| Step | Prediction | Outcome | Risk | Semantic | Temporal | Structural | Contributing layers |
|---:|---|---|---:|---|---|---|---|
| 30 | NORMAL | TRUE_NEGATIVE | 0.035 | NORMAL (0.0) | STABLE (p=0) | ISOLATED (0.0) | Baseline Conformity (All Invariants Passed) |

### `sustained_setpoint_runaway` — controller setpoint / actuator manipulation

Sustained +25 degC on SENSOR01 for three consecutive observations, simulating a refrigeration controller driven to ~46 degC.

Configuration: `{"drift_rate": null, "drift_steps": null, "magnitude": 25.0, "replay_step": null, "scenario": "temperature_manipulation", "seed": 42, "target_sensor": "SENSOR01"}`

| Step | Prediction | Outcome | Risk | Semantic | Temporal | Structural | Contributing layers |
|---:|---|---|---:|---|---|---|---|
| 30 | SUSPICIOUS | TRUE_POSITIVE | 0.384 | WARNING (0.3) | STABLE (p=1) | CORRELATED (0.5) | ML Outlier Detector (Score: 0.557); C3 Historical Consistency (WARNING); C4 Spatial Sensor Consistency (WARNING); Temporal Analysis (Persistence: 1, Score: 0.32); Structural Graph Correlation (Score: 0.50) |
| 31 | POTENTIAL_ATTACK | TRUE_POSITIVE | 0.433 | WARNING (0.3) | ESCALATING (p=2) | CORRELATED (0.5) | ML Outlier Detector (Score: 0.551); C3 Historical Consistency (WARNING); C4 Spatial Sensor Consistency (WARNING); Temporal Analysis (Persistence: 2, Score: 0.52); Structural Graph Correlation (Score: 0.50) |
| 32 | POTENTIAL_ATTACK | TRUE_POSITIVE | 0.473 | WARNING (0.3) | ESCALATING (p=3) | CORRELATED (0.5) | ML Outlier Detector (Score: 0.551); C3 Historical Consistency (WARNING); C4 Spatial Sensor Consistency (WARNING); Temporal Analysis (Persistence: 3, Score: 0.68); Structural Graph Correlation (Score: 0.50) |

### `subtle_in_envelope_change` — stealthy setpoint manipulation

Sustained +1.5 degC on SENSOR01 for six observations. The value remains inside the 4–16 degC semantic envelope, but is enough to compromise a cold chain over hours.

Configuration: `{"drift_rate": null, "drift_steps": null, "magnitude": 1.5, "replay_step": null, "scenario": "temperature_manipulation", "seed": 42, "target_sensor": "SENSOR01"}`

| Step | Prediction | Outcome | Risk | Semantic | Temporal | Structural | Contributing layers |
|---:|---|---|---:|---|---|---|---|
| 30 | NORMAL | FALSE_NEGATIVE | 0.025 | NORMAL (0.0) | STABLE (p=0) | ISOLATED (0.0) | Baseline Conformity (All Invariants Passed) |
| 31 | NORMAL | FALSE_NEGATIVE | 0.025 | NORMAL (0.0) | STABLE (p=0) | ISOLATED (0.0) | Baseline Conformity (All Invariants Passed) |
| 32 | NORMAL | FALSE_NEGATIVE | 0.029 | NORMAL (0.0) | STABLE (p=0) | ISOLATED (0.0) | Baseline Conformity (All Invariants Passed) |
| 33 | NORMAL | FALSE_NEGATIVE | 0.022 | NORMAL (0.0) | STABLE (p=0) | ISOLATED (0.0) | Baseline Conformity (All Invariants Passed) |
| 34 | NORMAL | FALSE_NEGATIVE | 0.026 | NORMAL (0.0) | STABLE (p=0) | ISOLATED (0.0) | Baseline Conformity (All Invariants Passed) |
| 35 | NORMAL | FALSE_NEGATIVE | 0.022 | NORMAL (0.0) | STABLE (p=0) | ISOLATED (0.0) | Baseline Conformity (All Invariants Passed) |

### `localized_cross_sensor_spoof` — sensor spoofing

+8 degC on SENSOR04 only, creating a spatial inconsistency.

Configuration: `{"drift_rate": null, "drift_steps": null, "magnitude": 8.0, "replay_step": null, "scenario": "cross_sensor_inconsistency", "seed": 42, "target_sensor": "SENSOR04"}`

| Step | Prediction | Outcome | Risk | Semantic | Temporal | Structural | Contributing layers |
|---:|---|---|---:|---|---|---|---|
| 30 | SUSPICIOUS | TRUE_POSITIVE | 0.325 | WARNING (0.15) | STABLE (p=1) | CORRELATED (0.5) | ML Outlier Detector (Score: 0.564); C4 Spatial Sensor Consistency (WARNING); Temporal Analysis (Persistence: 1, Score: 0.32); Structural Graph Correlation (Score: 0.50) |

### `valid_frame_replay` — replay

Replay SENSOR01 from step 0 under the step-30 timestamp.

Configuration: `{"drift_rate": null, "drift_steps": null, "magnitude": null, "replay_step": 0, "scenario": "replay_substitution", "seed": 42, "target_sensor": "SENSOR01"}`

| Step | Prediction | Outcome | Risk | Semantic | Temporal | Structural | Contributing layers |
|---:|---|---|---:|---|---|---|---|
| 30 | NORMAL | FALSE_NEGATIVE | 0.061 | NORMAL (0.0) | STABLE (p=0) | ISOLATED (0.0) | ML Outlier Detector (Score: 0.409) |

### `telemetry_suppression` — telemetry suppression

Suppress SENSOR01 entirely (forced dropout).

Configuration: `{"drift_rate": null, "drift_steps": null, "magnitude": null, "replay_step": null, "scenario": "sensor_dropout", "seed": 42, "target_sensor": "SENSOR01"}`

| Step | Prediction | Outcome | Risk | Semantic | Temporal | Structural | Contributing layers |
|---:|---|---|---:|---|---|---|---|
| 30 | NORMAL | FALSE_NEGATIVE | 0.052 | NORMAL (0.0) | STABLE (p=0) | ISOLATED (0.0) | Baseline Conformity (All Invariants Passed) |

### `hidden_hot_telemetry_replay` — telemetry substitution

Actual plant temperature is 46.2 degC (+25 degC), but the controller reports a valid historical 21.2 degC frame from step 0. The Defender sees only the reported frame.

Configuration: `{"actual": {"magnitude": 25.0, "scenario": "temperature_manipulation", "target_sensor": "SENSOR01"}, "reported": {"replay_step": 0, "scenario": "replay_substitution", "target_sensor": "SENSOR01"}}`

| Step | Prediction | Outcome | Risk | Semantic | Temporal | Structural | Contributing layers |
|---:|---|---|---:|---|---|---|---|
| 30 | NORMAL | FALSE_NEGATIVE | 0.061 | NORMAL (0.0) | STABLE (p=0) | ISOLATED (0.0) | Replay substitution: reported frame is a valid historical frame |

Actual physical temperature: **46.2 °C**; reported temperature: **21.2 °C**.


## 3. Audit-chain evidence

- Chain valid after the escalation sequence: **True** (33 events, tip `a28e5bbe7977efe6…`).
- Tampered copy detected: **True** (`HASH_MISMATCH` at event index 3).


## 4. Unmodified real-data playback (limitation evidence)

Sequential playback of 600 unmodified observations produced 504 alert states (84.0%). First alert: `{"classification": "SUSPICIOUS", "risk_score": 0.251, "step": 93, "temperature": 21.1}`.

This is a calibration limitation of the current Hohenheim envelope/spatial rules, not a successful attack. It is reported in the Review 3 limitations section and is why the controlled evaluation uses the synthetic ledger benchmark and a stable real-data baseline segment.
