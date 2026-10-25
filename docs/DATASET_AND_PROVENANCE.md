# Dataset Ingestion and Provenance Report

## 1. Dataset Overview and Authoritative Citation

- **Title:** Temperature and Humidity Time Series of Cold Storage Room Monitoring
- **Author/Institution:** University of Hohenheim, Department of Agricultural Engineering
- **Authoritative Repository URL:** [https://zenodo.org/records/15130001](https://zenodo.org/records/15130001)
- **Authoritative DOI:** `10.5281/zenodo.15130001`
- **License:** Creative Commons Attribution 4.0 International ([CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/))
- **Publication Date:** 2024
- **Academic Context:** Monitored cold-storage room facility operating at 4°C to 16°C nominal range with experimental product loading and door opening activities.

---

## 2. Ingested Authoritative Files and Cryptographic Checksums

The authoritative distribution was downloaded directly from Zenodo into `data/raw/hohenheim/`:

| File Name | File Size (Bytes) | MD5 Checksum | Description |
| :--- | :--- | :--- | :--- |
| `Preprocessed.zip` | 5,819,018 | `952eb73cdbc03f5d6319aaf8607c98e6` | Archive containing preprocessed time series for 9 DHT22 sensors |
| `experiment_actions.csv` | 5,362 | `63507fe89c3ff8047baba0d279735a93` | 127 timestamped operator actions (door events, product movements) |
| `overview.csv` | 73,881 | `05f16806d675999cce6614f19589c3a4` | Summary statistics and operating conditions |

---

## 3. Telemetry Schema and Sensor Inventory

The dataset comprises **9 DHT22 digital temperature and humidity sensors** positioned in distinct microclimate zones throughout the cold storage facility:

| Sensor ID | Monitored Zone / Function | Preprocessed CSV File | Total Aligned Rows | Missing Values (NaN) | Availability % |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SENSOR01** | Primary Cold Room Entry / Ambient | `SENSOR01_preprocessed.csv` | 156,835 | 966 | 99.38% |
| **SENSOR02** | Evaporator Intake / Circulation | `SENSOR02_preprocessed.csv` | 156,835 | 0 | 100.00% |
| **SENSOR03** | Shelf Zone Lower Tier | `SENSOR03_preprocessed.csv` | 156,835 | 84,498 | 46.12% |
| **SENSOR04** | Shelf Zone Upper Tier | `SENSOR04_preprocessed.csv` | 156,835 | 24,015 | 84.69% |
| **SENSOR05** | Portable Unit (Phase 1) | `SENSOR05_preprocessed.csv` | 156,835 | 52,190 | 66.72% |
| **SENSOR06** | Evaporator Exhaust Fan | `SENSOR06_preprocessed.csv` | 156,835 | 0 | 100.00% |
| **SENSOR07** | Rear Storage Wall Bottom | `SENSOR07_preprocessed.csv` | 156,835 | 0 | 100.00% |
| **SENSOR08** | Rear Storage Wall Top | `SENSOR08_preprocessed.csv` | 156,835 | 0 | 100.00% |
| **SENSOR09** | Portable Unit (Phase 2) | `SENSOR09_preprocessed.csv` | 156,835 | 70,899 | 54.79% |

### Exact CSV Schema
Each sensor file uses a semicolon (`;`) delimited format with header:
```text
timestamp;temperature;humidity
```
- **Timestamps:** ISO 8601 normalized strings `YYYY-MM-DDTHH:MM:SSZ` (original raw format: `DD.MM.YYYY HH:MM:SS`).
- **Interval:** Uniform 5.0-second intervals spanning **2024-09-02 09:35:25** to **2024-09-11 11:28:15** (total 9.08 calendar days).
- **Units:** Temperature in degrees Celsius (°C), Relative Humidity in percent (% RH).

---

## 4. Preprocessing and Optimized SQLite Synchronization

To enable sub-millisecond seek, replay, and random access without high memory overhead or complex Parquet C-extensions, the 9 raw CSVs and the experimental actions log were consolidated into a single indexed SQLite database:
- **Database Path:** `data/processed/hohenheim/hohenheim_synchronized.db`
- **Database Size:** ~29.91 MB
- **Table Schema:**
  ```sql
  CREATE TABLE observations (
      step INTEGER PRIMARY KEY,
      timestamp TEXT NOT NULL,
      temp_s1 REAL, hum_s1 REAL,
      temp_s2 REAL, hum_s2 REAL,
      temp_s3 REAL, hum_s3 REAL,
      temp_s4 REAL, hum_s4 REAL,
      temp_s5 REAL, hum_s5 REAL,
      temp_s6 REAL, hum_s6 REAL,
      temp_s7 REAL, hum_s7 REAL,
      temp_s8 REAL, hum_s8 REAL,
      temp_s9 REAL, hum_s9 REAL,
      active_action TEXT
  );
  CREATE INDEX idx_obs_timestamp ON observations(timestamp);
  ```
- **Query Performance:** Exact single-step random seek query execution time is **~0.0002 seconds**.

---

## 5. Treatment of Missing Operational Ledger Fields

> [!IMPORTANT]
> The University of Hohenheim dataset is an empirical physical microclimate time series. It contains **no ERP inventory ledgers, warehouse capacity records, inbound shipment tallies, or outbound shipment tallies**.

To maintain absolute academic and scientific integrity:
1. **Zero Fabrication:** The platform strictly refuses to synthesize, fabricate, or hallucinate missing warehouse capacity or inventory figures when playing back the Hohenheim dataset.
2. **Explicit Semantic Marking (`NOT_APPLICABLE`):**
   - **C1 (Capacity Invariant:** `inventory + free_capacity == total_capacity`): Evaluated as `NOT_APPLICABLE` when inventory/capacity fields are `None`.
   - **C2 (Inventory Flow Invariant:** `inventory_t == inventory_{t-1} + inbound - outbound`): Evaluated as `NOT_APPLICABLE` when flow ledgers are `None`.
   - **Zero Penalty:** `NOT_APPLICABLE` constraints contribute **0.0 penalty** to the composite security risk calculation, ensuring the system never penalizes the cold storage facility for missing ledgers.
3. **Dedicated Environmental Constraint (C4 Spatial Consistency):**
   - Evaluates multi-sensor spatial delta: `max(T) - min(T) <= 5.0°C` across active sensors.
   - Cross-checks with documented door openings to distinguish normal physical loading transients from sensor spoofing.

---

## 6. Physical Operational Events vs Cyberattacks

The dataset includes **127 documented physical experiment events** from `experiment_actions.csv`:
- `Door opened`: 56 events
- `Door closed`: 51 events
- `Products in`: 9 events
- `Products out`: 9 events
- `Begin`: 1 event (step 115)
- `End`: 1 event (step 156,798)

> [!NOTE]
> Physical temperature and humidity spikes following door openings are natural thermodynamic phenomena. The Defender engine correlates physical events (`active_action == 'Door opened'`) with temperature transients, classifying them as operational physical events rather than false cyberattacks.
