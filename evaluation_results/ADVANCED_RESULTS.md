# OPTIMUS Advanced Experiment Results

Generated: 2026-10-20T17:11:03.023924+00:00

## Dataset provenance

- Seed: 42
- Normal generated: 12000
- Attack generated per class: 2000

| Split | Records | Normal | Attack | SHA-256 |
|---|---:|---:|---:|---|
| train | 7200 | 7200 | 0 | `d3acc0e816aa0181…` |
| val | 4800 | 2400 | 2400 | `bf245d682d47f8d1…` |
| test | 12000 | 2400 | 9600 | `11ff544c47a509fb…` |

## Adaptive fusion

- Static weights: `{'semantic': 0.4, 'temporal': 0.25, 'structural': 0.2, 'ml': 0.15}`
- Adapted weights: `{'semantic': 0.49092757, 'temporal': 0.11031382, 'structural': 0.34875861, 'ml': 0.05}`
- Adopted: True

| Configuration | Precision | Recall | F1 | FPR | Evasion |
|---|---:|---:|---:|---:|---:|
| optimus_static_rule | 1.0000 | 0.7693 | 0.8696 | 0.0000 | 0.2307 |
| optimus_adaptive_rule | 1.0000 | 0.7693 | 0.8696 | 0.0000 | 0.2307 |
| optimus_static_risk | 1.0000 | 0.7691 | 0.8695 | 0.0000 | 0.2309 |
| optimus_adaptive_risk | 1.0000 | 0.7689 | 0.8693 | 0.0000 | 0.2311 |

## Dynamic invariant mining

- Discovered: 9
- Validated: 8
- Rejected: 1
- Active: 8
- Mining audit chain valid: True

| Configuration | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|
| optimus_static | 1.0000 | 0.7693 | 0.8696 | 0.0000 |
| optimus_invariants | 1.0000 | 0.9440 | 0.9712 | 0.0000 |
| optimus_combined | 1.0000 | 0.9440 | 0.9712 | 0.0000 |

## Independent baselines

| Detector | Precision | Recall | F1 | FPR | Evasion |
|---|---:|---:|---:|---:|---:|
| optimus_static | 1.0000 | 0.7693 | 0.8696 | 0.0000 | 0.2307 |
| one_class_svm | 1.0000 | 0.3333 | 0.5000 | 0.0000 | 0.6667 |
| pca | 1.0000 | 0.7499 | 0.8571 | 0.0000 | 0.2501 |

## Evasion frontier

| Configuration | Mean evasion | Evasion at full strength |
|---|---:|---:|
| optimus_static | 0.4453 | 0.3542 |
| optimus_adaptive | 0.4453 | 0.3542 |
| optimus_invariants | 0.1667 | 0.1667 |
| optimus_combined | 0.1667 | 0.1667 |
| one_class_svm | 0.7778 | 0.6667 |
| pca | 0.2235 | 0.1667 |

## Audit lifecycle

- Chain valid: True
- Events: 13
- Unauthorized activation blocked: True
- Rejected proposal logged: True
- Tamper detected: True
- Full lifecycle present: True

## Limitations

- Evasion frontier thresholds are calibrated on the validation split; test/frontier data is never used for tuning.
- The audit chain is in-memory and does not survive process restart; durable tamper-evidence requires append-only external storage.
- Mined invariants are statistical hypotheses validated on independent normal/attack data. They still require domain review before production use.
- Replay attacks with stationary inventory and in-envelope drift remain a passive-monitoring limitation requiring cryptographic freshness.
