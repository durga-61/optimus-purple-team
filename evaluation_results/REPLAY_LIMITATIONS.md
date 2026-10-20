# Empirical Analysis of Replay Attack Detection & Architectural Limitations

**Evaluation Split:** test  
**Replay Detection Rate:** 56.81%  
**Mean Replay Latency:** 0.34 steps  

---

## 1. Executive Summary

Replay attacks represent a fundamental challenge for passive telemetry and semantic monitoring systems. In a replay attack, an adversary captures authentic, historically valid sensor telemetry and ledger records, and subsequently retransmits them into the monitoring stream.

Because individual replayed observations originally passed all physical and mathematical constraints, detecting them relies entirely on **temporal state continuity**, **sequence freshness**, and **environmental drift**.

---

## 2. When Replay Attacks Are Successfully Detected

The Optimus defender pipeline successfully detects replay attacks under the following conditions:

1. **Inventory Flow Desynchronization ($C_2$ Violation):**
   - If the warehouse has engaged in legitimate inbound or outbound shipment flows between the original recording and the replayed timestamp, replaying the old inventory count induces an instantaneous discrepancy against the ledger ($C_2$: $\text{inventory}_t \neq \text{inventory}_{t-1} + \text{inbound}_t - \text{outbound}_t$).
2. **Environmental Discontinuity:**
   - Sudden discrete jumps in temperature or relative humidity between the current ambient state and the replayed snapshot trigger the **Temporal Engine** and **Isolation Forest ML** anomaly detector.
3. **Out-of-Order Sequence Counters:**
   - Transmitting duplicate or retrograde step numbers triggers the pipeline's **Sequence Freshness Check** (`SEQUENCE_ANOMALY`).

---

## 3. Structural Limitations & Undetected Replay Scenarios

Despite multi-stage defenses, replay attacks can successfully evade detection under specific operational boundaries:

1. **Static Warehouse Quiescence:**
   - If warehouse inventory is stationary (zero inbound, zero outbound) and the adversary updates the step counter monotonically, replaying an observation from 5 steps prior creates zero mathematical or physical invariant discrepancy.
2. **In-Envelope Environmental Drift:**
   - If the replayed sensor temperature and humidity fall within plausible short-term ambient drift tolerances (e.g. 4.2°C replayed as 4.3°C), the ML detector cannot statistically distinguish replay noise from true physical walk noise.
3. **Passive Ingestion Boundary:**
   - Passive application-layer monitors cannot independently verify sensor authenticity without cryptographic verification primitives.

---

## 4. Recommended Production Countermeasures

To achieve complete mitigation against replay attacks in production:

1. **Cryptographic Nonce / Challenge-Response:**
   - Require IoT gateway devices to sign observations with monotonic hardware nonces or asymmetric private keys.
2. **Authenticated Timestamps & TLS Integrity:**
   - Enforce synchronized Network Time Protocol (NTP) with strict drift rejection thresholds (< 500ms).
3. **HMAC Message Authentication Codes:**
   - Attach keyed HMAC digests over `(warehouse_id, step, timestamp, payload)` at the hardware sensor edge.
