# Known Limitations and Operational Assumptions

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
