# Cold-Storage Warehouse Cybersecurity Monitoring & AI Attack Platform (OPTIMUS)

An industrial cybersecurity monitoring platform and sandboxed AI attack simulation suite with a closed-loop **Miss-Driven Self-Hardening Purple-Team Loop** and **SHA-256 Cryptographic Audit Chaining** for a simulated cold-storage warehouse facility (Facility W01).

The platform continuously verifies operational data integrity across IoT physical sensors, warehouse inventory counts, and shipment ledgers using a multi-stage defense-in-depth pipeline. It is coupled with an isolated adversarial evaluation application (Part 2) that formulates, validates, and simulates attack strategies against the defender system under human-in-the-loop oversight.

---

## 1. System Architecture & Detection Pipeline

```text
Warehouse Observation (IoT Telemetry, Physical Inventory, Shipment Ledgers)
                                  │
             1. Preprocessing and Boundary Validation
                                  │
             2. ML Anomaly Detection (Isolation Forest)
                                  │
             3. Semantic Invariant Verification (C1, C2, C3)
                                  │
             4. Temporal Trend and Decay Tracking
                                  │
             5. Structural Graph Blast-Radius Correlation
                                  │
             6. Joint Security Decision and Alert Posture
                                  │
             7. SHA-256 Cryptographic Audit Chaining
                                  │
             8. Miss-Driven Self-Hardening Purple-Team Loop
```

### Invariants Checked
- **C1 (Capacity Balance):** `inventory + free_capacity == total_capacity` (Tolerance: default $0.50\text{t}$, hardened $0.40\text{t}$)
- **C2 (Inventory Flow Balance):** `current_inventory == previous_inventory + inbound_shipments - outbound_shipments` (Tolerance: default $0.50\text{t}$, hardened $0.25\text{t}$)
- **C3 (Physical Operating Bounds):** Temperature (1.0°C to 7.0°C) and Relative Humidity (60.0% to 85.0%) strictly maintained inside acceptable cold-chain operating thresholds.

---

## 2. Core Security & Self-Hardening Features

### 2.1 Miss-Driven Self-Hardening Purple-Team Loop
- **Root-Cause Diagnosis (`app/defender/hardening.py`)**: Automatically captures confirmed missed attacks and diagnoses evasion causes (`STEALTHY_CAPACITY_SLACK_BELOW_C1_TOLERANCE`, `STEALTHY_FLOW_DISCREPANCY_BELOW_C2_TOLERANCE`, `COMPOSITE_RISK_BELOW_PRIMARY_THRESHOLD`, `MULTI_STAGE_CORROBORATION_GAP`).
- **Bounded Safety Proposals**: Proposes parameter adjustments bounded by strict safety envelopes ($0.10 \le \text{tolerance} \le 0.50$).
- **Validation Gate**: Simulates proposals on independent validation data (`splits.val`). Rejects proposals that cause false-positive regressions ($\text{FPR} > 0.001$) or fail to improve detection.
- **Human Operator Approval Boundary**: Enforces explicit human operator approval before activating any proposal in production (`PermissionError` on unapproved activation). Attacker input cannot directly modify production rules or weights.
- **One-Click Rollback**: Restores original baseline parameters cleanly and logs rollback events into the audit chain.

### 2.2 SHA-256 Cryptographic Audit Chaining
- Every security lifecycle event (data ingestion, ML detection, alerts, miss recording, proposal approval, activation, rollback) computes:
  $$\text{event\_hash} = \text{SHA256}(\text{canonical}(\text{event}, \text{prev\_hash}))$$
- Chained from a deterministic `GENESIS_HASH`.
- Verified via `GET /api/security/audit-chain/verify`. Detects any payload modification, insertion, deletion, or reordering.

---

## 3. Quick Start

### 3.1 Prerequisites
- Python 3.10+ (tested on Python 3.12 and 3.13)
- Git & pip

### 3.2 Installation
```bash
# Clone the repository
git clone https://github.com/durga-61/optimus-purple-team.git
cd optimus-purple-team

# Install dependencies
pip install -r requirements.txt
```

### 3.3 Configuration
Copy the template configuration:
```bash
cp .env.example .env
```

Key configuration variables in `.env`:
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `LOCAL_DEMO_MODE` | `true` | Allows unauthenticated loopback access (`127.0.0.1`) for local demonstrations. Set `false` for strict production authentication. |
| `OPERATOR_TOKEN` | `dev-operator-token-change-in-prod` | Bearer token for state-changing Defender operations and proposal approvals. |
| `ATTACK_GATEWAY_TOKEN` | `dev-gateway-token-change-in-prod` | Shared token required by Attacker client to inject payloads into Defender gateway. |
| `ATTACKER_API_KEY` | `dev-attacker-key-change-in-prod` | Access token for Part 2 Attacker Console endpoints. |
| `LLM_PROVIDER` | `mock` | LLM planning provider (`mock`, `openai`, `anthropic`). Mock mode operates offline without API keys. |

---

## 4. Running the Applications

### 4.1 Part 1 — Organization Defender Platform
Launch the primary defender service (port 8000):
```bash
python run.py
```
* **Security Portal Dashboard:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
* **Live Sensor Operations:** [http://127.0.0.1:8000/operations](http://127.0.0.1:8000/operations)
* **Interactive API Documentation:** [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs)

### 4.2 Part 2 — AI Attacker Console
Launch the isolated attacker service (port 8001):
```bash
python run_attacker.py
```
* **AI Attacker Console:** [http://127.0.0.1:8001](http://127.0.0.1:8001)
* **Attacker API Documentation:** [http://127.0.0.1:8001/docs](http://127.0.0.1:8001/docs)

---

## 5. Automated Test Suite

The test suite contains **224 automated test cases** verifying all components:
```bash
# Run complete test suite
python -m pytest tests/ -v
```

Specialized test suites:
```bash
# Miss-Driven Self-Hardening Purple-Team loop tests
pytest tests/test_hardening.py -v

# SHA-256 cryptographic audit chain & tamper detection
pytest tests/test_audit_chain.py -v

# Attacker isolation & boundary security
pytest tests/test_attacker_gateway.py -v
pytest tests/test_attacker_app.py -v

# Dataset determinism & anti-leakage temporal split tests
pytest tests/test_dataset_generator.py -v
```

---

## 6. Reproducible Experiments & Evaluation

### 6.1 Self-Hardening Comparison (12,000 Held-Out Test Samples)
Run the reproducible baseline vs. hardened comparative experiment with symmetric warm-up and paired interleaved execution:
```bash
python evaluate_hardening.py
```

#### Empirical Results:
| Metric | Original Baseline | Hardened System | Delta |
| :--- | :---: | :---: | :---: |
| **Overall Accuracy** | 81.54% | **94.89%** | **+13.35%** |
| **Detection Recall** | 76.93% | **93.61%** | **+16.68%** |
| **Precision** | 100.00% | **100.00%** | +0.00% |
| **F1-Score** | 86.96% | **96.70%** | **+9.74%** |
| **False-Positive Rate** | 0.00% | **0.00%** | +0.00% |
| **Mean Latency (Overhead)** | 8.189 ms | 8.242 ms | **+0.053 ms (+0.65%)** |

#### Per-Attack-Class Recall Breakdown (1,600 samples each):
* `capacity_manipulation`: $100.00\% \rightarrow 100.00\%$ ($+0.00\%$)
* `inventory_manipulation`: $100.00\% \rightarrow 100.00\%$ ($+0.00\%$)
* `sensor_spoofing`: $100.00\% \rightarrow 100.00\%$ ($+0.00\%$)
* `multi_source`: $100.00\% \rightarrow 100.00\%$ ($+0.00\%$)
* `replay_attack`: $56.81\% \rightarrow 61.69\%$ ($+4.87\%$)
* `coordinated_weak`: $4.75\% \rightarrow 100.00\%$ ($+95.25\%$)

### 6.2 Standard 24k Benchmark Evaluation CLI
```bash
python evaluate.py --split test --output-dir evaluation_results
```
Outputs exported to `evaluation_results/`:
- `benchmark_summary.csv`, `per_class_metrics.csv`, `ablation_metrics.csv`
- `hardening_comparison.json`, `hardening_comparison.csv`
- Publication figures: `confusion_matrix.png`, `attack_class_performance.png`, `detection_latency.png`, `stage_ablation.png`

---

## 7. Operational Limitations & Threat Boundary

1. **Replay Attack Residual Misses**: 38.31% of replay attacks evade passive monitoring when inventory is stationary and environmental drift remains within natural variance. Eliminating passive replay evasion requires hardware cryptographic primitives (monotonic counters, edge HMACs, TLS nonces) rather than application-layer monitoring.
2. **Audit Chain Lifespan**: The in-memory SHA-256 audit chain provides tamper-evidence against runtime tampering, but does not survive process restarts. Production deployment requires external append-only write-once-read-many (WORM) syslog storage.
3. **Adaptive Fusion Weights**: Fusion weights are currently static hyperparameters ($w_{ml}=0.40, w_{sem}=0.25, w_{temp}=0.20, w_{struct}=0.15$); online dynamic weight adaptation is out of scope for this release.

---

## 8. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
