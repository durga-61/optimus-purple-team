# Threat and Security Model

## 1. System Scope and Domain Context

- **Academic Context:** VIT, SCOPE / CSBS, Information Security Domain, Team 12.
- **Monitored Facility:** Cold-Storage Warehouse W01.
- **System Role:** The Defender platform is the authoritative monitor for operational records, inventory ledgers, and IoT microclimate telemetry.

---

## 2. Threat Model and Adversary Capabilities

The system defends against adversaries with the following capabilities:
1. **IoT Sensor Spoofing:** An attacker compromises one or more digital sensor channels (e.g. DHT22 communication bus or gateway) to report false temperature or humidity readings.
2. **Administrative Record Tampering:** An attacker modifies database records of total capacity, inventory, or shipment flows to mask inventory shrinkage or theft.
3. **Coordinated Stealth Manipulation:** An attacker subtly alters multiple fields simultaneously (e.g. shifting inventory and free capacity by small increments) to evade single-variable threshold alerts.
4. **Replay Attacks:** An attacker intercepts valid historical observations from previous days and replays them to mask an ongoing cooling failure or inventory loss.
5. **Multi-Source Attacks:** An attacker simultaneously alters physical sensors and warehouse ledgers to create plausible but structurally contradictory states.

---

## 3. Assumptions and Trust Boundaries

- **Defender Integrity:** The Defender runtime environment (FastAPI application and in-memory execution) is assumed initially authentic.
- **Attacker Gateway Boundary:** The AI Attacker component (`attacker_app/`) is strictly confined to external client interactions. The attacker has **zero access** to internal DefenderService instances, detection weights, ML model parameters, or secret cryptographic salts.
- **Read-Only Attacker Observation:** The attacker can only query filtered, public operational telemetry via `/api/attacker/observation`. Internal security scores and alert thresholds are strictly withheld.
- **Operator Approval Gate:** No defensive hardening configuration change or mined invariant can be activated without explicit human operator authentication and approval.

---

## 4. Attack Taxonomy and Defensive Mechanisms

| Attack Class | Targeted Vector | Attack Description | Primary Detection Layer | Secondary Defense |
| :--- | :--- | :--- | :--- | :--- |
| **Capacity Manipulation** | `capacity`, `free_capacity` | Violates capacity summation invariant | **Semantic (C1)** | Structural graph (`inventory_ledger` $\leftrightarrow$ `capacity_management`) |
| **Inventory Tampering** | `inventory`, `occupancy` | Alters inventory without inbound/outbound shipments | **Semantic (C2)** | Structural correlation (`inventory_ledger` $\leftrightarrow$ `occupancy_sensor`) |
| **Sensor Spoofing** | `temperature`, `humidity` | Reports values outside safe operating envelope | **Semantic (C3, C4)** | ML Anomaly Detector (IsolationForest) |
| **Multi-Sensor Spoofing** | Individual DHT22 zones | Injects localized false readings into individual sensors | **Semantic (C4 Spatial Delta)** | ML Spatial IsolationForest |
| **Replay Attack** | Full telemetry frame | Submits previous clean frame under current timestamp | **Temporal Engine** | Recurrence tracking & EWMA memory |
| **Coordinated Weak** | Sub-threshold multi-variable | Small perturbations across multiple variables | **ML Anomaly Detector** | Joint Decision Fusion |
| **Multi-Source Compromise** | Sensors + Ledgers | Simultaneous manipulation of environmental and ERP data | **Structural Correlation** | Tier 2 Rule Classification (`MULTI_SOURCE`) |

---

## 5. Physical Operational Events vs Cyberattacks

A fundamental requirement in physical security monitoring is avoiding false alarms caused by natural facility operations:

1. **Door Opening Events:**
   - Physical cold rooms experience transient temperature spikes (up to 2–5°C) and humidity shifts when heavy insulated doors are opened for loading.
   - The Defender correlates empirical `experiment_actions` (`Door opened`, `Products in`) with C3 and C4 constraint evaluations, suppressing false tampering alarms during documented activities.
2. **Sensor Dropouts and Communication Faults:**
   - Physical DHT22 sensors occasionally experience communication bus dropouts resulting in missing values (`NaN`).
   - The platform tracks sensor availability as a **Data Quality Metric** rather than classifying sensor dropouts as malicious cyberattacks.
