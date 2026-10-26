# Known Limitations and Operational Assumptions

## 0. Dataset Is Fetched, Not Vendored

- **No Data in Git:** Only the small provenance files (`overview.csv`, `experiment_actions.csv`, `data/DATASET_MANIFEST.json`) are committed. `Preprocessed.zip`, the extracted per-sensor CSVs, and the SQLite cache are gitignored.
- **One-Time Setup:** run `python scripts/fetch_dataset.py` after cloning, or start with `DATA_SOURCE_MODE=simulator`. Without either, the app exits at startup with instructions.
- **Tests:** dataset-dependent tests skip automatically when the dataset is absent (they are marked with `tests.markers.requires_hohenheim`).

---

## 1. Recorded Historical Telemetry vs Live Hardware Feeds

- **Recorded Playback:** The primary environmental data source is the University of Hohenheim cold-storage dataset recorded between September 2 and September 11, 2024.
- **Physical Connection Disclaimer:** The application operates in **Recorded Playback Mode** and does not establish a live network socket or Serial/GPIO connection to physical DHT22 hardware sensors in real-time.
- **Playback Speed:** Playback can be advanced step-by-step or automatically at accelerated rates, but individual observation timestamps reflect the historical recording dates.

---

## 2. Absence of Empirical ERP Ledgers in the Real Dataset

- **No Field Fabrication:** The University of Hohenheim dataset does not record inventory counts, total capacity, free capacity, or inbound/outbound shipment manifests.
- **Semantic Handling:** Constraints C1 (Capacity Invariant) and C2 (Inventory Flow Invariant) return `NOT_APPLICABLE` when reading Hohenheim telemetry.
- **Validation Scope:** Validating C1 and C2 attacks requires switching to the preserved cold-storage warehouse simulator (`DATA_SOURCE_MODE=simulator`).

---

## 3. Cryptographic Audit Log Persistence

- **In-Memory Chain:** The SHA-256 cryptographic audit chain (`app/defender/audit.py`) operates in-memory.
- **Process Lifetime:** The audit chain validates runtime tamper-evidence and sequencing integrity while the process is active. It does not persist across application server restarts unless integrated with an external append-only database or write-once ledger.
- **Threat Boundary:** The hash chain prevents undetected retroactive alteration of security records via API endpoints, but cannot defend against an attacker possessing raw process memory write access.

---

## 4. DHT22 Hardware Sensor Characteristics

- **Measurement Resolution:** DHT22 sensors exhibit typical measurement accuracy of $\pm 0.5^\circ\text{C}$ for temperature and $\pm 2\text{–}5\%$ for relative humidity.
- **Sampling Interval:** The physical sensor hardware has a minimum readout cycle time of 2.0 seconds; the recorded Hohenheim dataset uses 5.0-second intervals.
- **Missing Data (Dropouts):** Sensors SENSOR03, SENSOR05, and SENSOR09 exhibit missing data segments due to transient bus failures or partial experiment deployments. The system treats these as data quality dropouts rather than cyberattacks.

---

## 5. Real-Data Calibration Gap (Review 3)

- **Observed behaviour:** on 600 unmodified observations from the Hohenheim dataset, the current envelope and spatial rules produced 504 alert states (84.0%), with the first alert at step 93.
- **Cause:** the primary `temperature` field is SENSOR01 (cold-room entry / ambient), while other sensors are in colder zones; C3 uses a hard-coded 4–16 °C Hohenheim envelope; C4 uses a global `max(T) − min(T)` rule across zones; and the environmental IsolationForest is fitted on the first 120 rows.
- **Consequence:** the 84.0% figure is a false-alarm/calibration measurement, not an attack result. The controlled benchmark in `evaluation_results/final_benchmark/` uses the synthetic ERP-linked simulator, where the detectors are calibrated to the simulated cold room.
- **Status:** open engineering issue. See `docs/REVIEW3_FINAL_REPORT.md` §2.10 and §4.1 for the remediation plan (zone-aware C4, per-sensor envelopes, representative ML baseline, drift monitoring).

---

## 6. Passive Monitoring — No Command or Actuator Integrity

- **Scope:** OPTIMUS observes telemetry and ledger data. It does not authenticate controller commands, inspect OT network traffic, or control actuators.
- **Consequence:** the system cannot prevent a controller compromise or a setpoint change. It can only detect the physical effect if the controller reports the truth.
- **Case-study evidence:** a replayed normal frame that hid an actual 46.2 °C reading was classified `NORMAL`; a forced sensor dropout was also `NORMAL`.
- **Needed:** controller login/setpoint/configuration audit logs, signed telemetry and device attestation, OT network monitoring, and independent safety interlocks.

---

## 7. Replay and Telemetry Authenticity

- **Measured limitation:** replay recall is 56.81% (static) and 66.37% (with mined invariants); replay evasion is 100% at full strength for every detector tested.
- **Why:** the current freshness check only compares `step` values. A replayed frame can carry a new step and a valid historical payload.
- **Needed:** nonces, monotonic counters, a bounded timestamp window, and edge HMAC/signature verification. Passive statistical detection cannot establish provenance.

---

## 8. Case-Study Scope and Uncertainty

- **Incident:** the October 2026 French supermarket refrigeration-controller campaign, sourced to CERT-FR advisory `CERTFR-2026-ALE-012`.
- **Uncertainty:** the exact initial access vector and whether CVE-2025-41450/41451/41452 were the exploited path have not been confirmed by the authorities. Store counts, the 50 °C figure, and fire reports come from press/retailer statements.
- **What the case study is:** a scaled-down, deterministic simulation on real Hohenheim telemetry that reproduces the observable attack stages (large excursion, in-envelope change, replay, hidden-hot replay, suppression, cross-sensor spoof). It is not a replay of the actual campaign.
