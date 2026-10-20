# API SPECIFICATION — OPTIMUS CYBERSECURITY PLATFORM

This document defines the formal REST API contract for both applications in the Optimus Cybersecurity Platform:
1. **Part 1: Defender Application & Monitoring Platform** (Default port `8000`)
2. **Part 2: AI Attacker & Adversarial Evaluation Console** (Default port `8001`)

---

## 1. Defender APIs (Part 1)

- **Base URL:** `http://127.0.0.1:8000`
- **Interactive Swagger Documentation:** `http://127.0.0.1:8000/api/docs`
- **OpenAPI 3.0 Schema:** `http://127.0.0.1:8000/api/openapi.json`
- **Frontend Dashboards:**
  - `GET /` — Organization Security Portal & Pipeline Visualizer
  - `GET /operations` — Warehouse Operations & IoT Sensor Monitor

### Authentication & Access Control
- **Operator Endpoints:** State-changing endpoints (`POST /api/warehouse/step`, `POST /api/warehouse/reset`, `POST /api/security/reset`, `POST /api/scenarios/{scenario_name}`) are protected by `verify_operator_access()`.
  - When `LOCAL_DEMO_MODE=true`, loopback clients (`127.0.0.1`, `::1`, `localhost`) are permitted unauthenticated for interactive UI demonstration.
  - Non-loopback requests or when `LOCAL_DEMO_MODE=false` strictly require `Authorization: Bearer <OPERATOR_TOKEN>` or `X-API-Key: <OPERATOR_TOKEN>`.
- **Attack Gateway Endpoints:** `POST /api/attacker/inject` and `POST /api/attacker/reset` require a shared token configured via `ATTACK_GATEWAY_TOKEN`.
  - Enforced via constant-time cryptographic verification (`hmac.compare_digest`).
  - Requests without `Authorization: Bearer <ATTACK_GATEWAY_TOKEN>` return HTTP 401 Unauthorized.

### Endpoints

#### Health
* **`GET /api/health`**
  - **Description:** Returns service readiness and component health.
  - **Response (200 OK):**
    ```json
    {
      "status": "healthy",
      "service": "organization-security-platform",
      "simulator": "running",
      "defender": "ready"
    }
    ```

#### Warehouse Simulator
* **`GET /api/warehouse/status`**
  - **Description:** Returns current telemetry and operational state for facility W01.
* **`GET /api/warehouse/inventory`**
  - **Description:** Returns inventory levels and item details.
* **`GET /api/warehouse/metrics`**
  - **Description:** Returns key operational metrics (temperature, humidity, occupancy).
* **`POST /api/warehouse/step`** *(Protected)*
  - **Description:** Advances warehouse simulation by one tick, producing fresh telemetry.
* **`POST /api/warehouse/reset`** *(Protected)*
  - **Description:** Resets warehouse simulator to clean baseline configuration.

#### Security Decision & Analysis
* **`GET /api/security/analysis`**
  - **Description:** Returns the complete 6-stage detection pipeline analysis:
    - ML Anomaly Detector (`IsolationForest` score & anomaly flag)
    - Semantic Invariants (C1 capacity, C2 inventory flow, C3 environmental bounds)
    - Temporal Trend Tracker (persistence, recurrence, decay)
    - Structural Graph Correlation (blast radius, cross-component risk)
    - Joint Decision Engine (confidence, risk level, threat category, recommended action)
* **`GET /api/security/events`**
  - **Description:** Returns chronological security audit log events with `prev_hash` and `event_hash` cryptographic links.
* **`GET /api/security/audit-chain/verify`** *(Operator Protected)*
  - **Description:** Cryptographically verifies the SHA-256 hash chain of all in-memory security events from genesis.
  - **Access Control:** Protected by `verify_operator_access()` (Loopback authorized in local demo mode; Bearer token or session cookie required for remote callers).
  - **Response (200 OK):**
    ```json
    {
      "valid": true,
      "total_events": 14,
      "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "latest_event_hash": "7f73c5800326d60c98ff1834941b7244a8f7170ef4b12c4d2847ab0293580689",
      "verified_at": "2026-10-20T14:22:29.567046+00:00",
      "error": null,
      "failed_event_index": null,
      "details": {
        "verified_count": 14
      },
      "disclaimer": "In-memory cryptographic chain. Verifies runtime integrity and tamper-evidence in active memory. Does not survive process restarts and cannot prevent an attacker with full memory write access from recalculating the entire chain. Durable tamper-proofing requires persistent append-only storage."
    }
    ```
  - **Threat Model Disclosure:** An in-memory chain guarantees tamper-evidence against runtime tampering, item omission, or sequence reordering, but resets upon server restarts. Durable non-repudiation requires persistent append-only ledger integration.
* **`GET /api/security/status`**
  - **Description:** Returns aggregated threat level, active alert counters, and system security posture.
* **`GET /api/security/hardening/proposals`** *(Operator Protected)*
  - **Description:** Returns the active hardening engine status, current and baseline parameter settings, generated candidate proposals, and recent captured missed attacks.
  - **Access Control:** Guarded by `verify_operator_access()`.
* **`POST /api/security/hardening/proposals/{proposal_id}/approve`** *(Operator Protected)*
  - **Description:** Explicit operator approval gate to approve and activate a candidate hardening proposal.
  - **Access Control:** Guarded by `verify_operator_access()`. Enforces human confirmation before activating any candidate invariant or threshold adjustment in production.
  - **Payload:**
    ```json
    {
      "approved": true,
      "operator_name": "SecurityOperator"
    }
    ```
* **`POST /api/security/hardening/rollback`** *(Operator Protected)*
  - **Description:** Restores production detector parameters to original baseline settings, recording a `HARDENING_ROLLED_BACK` cryptographic event in the audit chain.
  - **Access Control:** Guarded by `verify_operator_access()`.
* **`POST /api/security/reset`** *(Protected)*
  - **Description:** Resets security detectors, history buffers, alert state, and re-anchors the audit chain to genesis root.

#### Deterministic Scenarios
* **`GET /api/scenarios/`**
  - **Description:** Returns list of supported attack scenarios (`capacity_manipulation`, `inventory_manipulation`, `sensor_spoofing`, `replay`, `coordinated_weak`, `multi_source`).
* **`POST /api/scenarios/{scenario_name}`** *(Protected)*
  - **Description:** Injects deterministic attack scenario for evaluation.

#### Attack Gateway (Defender Ingress for Attacker)
* **`GET /api/attacker/status`**
  - **Description:** Reports attack gateway connectivity and authentication status.
* **`POST /api/attacker/inject`** *(Bearer Token Required)*
  - **Description:** Ingress endpoint through which the AI Attacker application delivers sandboxed attack payloads.
  - **Header:** `Authorization: Bearer <ATTACK_GATEWAY_TOKEN>`
  - **Payload:**
    ```json
    {
      "attack_type": "sensor_spoofing",
      "target": "humidity",
      "value": 92.5,
      "parameters": {}
    }
    ```
  - **Response (200 OK):** Attack execution feedback and post-attack warehouse state.
* **`POST /api/attacker/reset`** *(Bearer Token Required)*
  - **Description:** Gateway simulation reset endpoint callable by the attacker client.

---

## 2. Attacker APIs (Part 2)

- **Base URL:** `http://127.0.0.1:8001`
- **Interactive Swagger Documentation:** `http://127.0.0.1:8001/docs`
- **OpenAPI 3.0 Schema:** `http://127.0.0.1:8001/openapi.json`
- **Frontend Console:** `GET /` — AI Attacker & Adversarial Evaluation Console

### Authentication & Access Control
- All `/api/attacker/*` endpoints are protected by `verify_attacker_access()`.
  - When `LOCAL_DEMO_MODE=true`, loopback callers (`127.0.0.1`, `::1`, `localhost`) are permitted unauthenticated for interactive console use.
  - Remote callers or when `LOCAL_DEMO_MODE=false` strictly require `Authorization: Bearer <ATTACKER_API_KEY>` or `X-API-Key: <ATTACKER_API_KEY>`.
- **Human-in-the-Loop Approval:** Direct attack execution without approval is strictly blocked.
  - `POST /api/attacker/execute` requires `approved: true` with a matching `proposal_id`.

### Endpoints

* **`GET /api/attacker/status`**
  - **Description:** Returns attacker runtime configuration, target defender gateway URL, active LLM provider, and pending proposal metadata.
* **`GET /api/attacker/observation`**
  - **Description:** Fetches current simulated warehouse observation from the defender gateway.
* **`POST /api/attacker/propose`**
  - **Description:** Generates an attack proposal using heuristic or configured LLM provider (OpenAI, Anthropic, or Mock).
  - **Payload:**
    ```json
    {
      "mode": "autonomous",
      "objective": "evade_detection",
      "custom_strategy": null
    }
    ```
  - **Response (200 OK):** Validated attack proposal with `proposal_id`, strategy reasoning, attack type, target, and parameters.
* **`POST /api/attacker/execute`** *(Human Approval Required)*
  - **Description:** Executes a previously generated proposal against the defender gateway.
  - **Payload:**
    ```json
    {
      "proposal_id": "prop_12345678",
      "approved": true
    }
    ```
  - **Response (200 OK):** Execution outcome, defender detection response, and evasion status.
  - **Error (400 Bad Request):** If `approved: false` or `proposal_id` does not match pending proposal.
* **`POST /api/attacker/discard`**
  - **Description:** Discards the currently pending attack proposal without executing it.
* **`GET /api/attacker/history`**
  - **Description:** Returns chronological audit log of attack proposals, executions, and defender responses.
* **`DELETE /api/attacker/history/clear`**
  - **Description:** Clears the attacker's local proposal and execution history.
* **`GET /api/attacker/experiments`**
  - **Description:** Returns pre-packaged adversarial experiment matrices and comparative evaluations.
* **`POST /api/attacker/reset`**
  - **Description:** Granular reset endpoint. Supports `scope`: `"all"`, `"history_only"`, `"attacker_only"`, `"defender_only"`.
  - **Response:** Accurate status reporting. If defender gateway is offline during a defender-scoped reset, returns `success: false` and HTTP 502 with diagnostic details.

---

## 3. Attack Matrix & Whitelisted Parameters

The Attack Gateway strictly accepts the following attack types and targets:

| Attack Type | Supported Targets | Description & Boundaries |
| :--- | :--- | :--- |
| `sensor_spoofing` | `temperature`, `humidity`, `environmental_sensors` | Value restricted to physical ranges (-40 to 60 deg C, 0 to 100% RH). Modifies only specified target. |
| `capacity_manipulation` | `total_capacity`, `free_capacity`, `capacity` | Value restricted to 0 to 50,000 units. Precise target update without collateral field modification. |
| `inventory_manipulation` | `inventory_count`, `inventory`, `stock` | Modifies inventory without corresponding ledger entries. |
| `replay_attack` | `telemetry_stream`, `inventory`, `observation`, `state` | Injects stale observation records into the live environment. |
| `coordinated_weak` | `all`, `sensors_and_inventory` | Applies subtle sub-threshold drift across multiple sensors and ledger values simultaneously. |
| `multi_source` | `all`, `sensors_and_ledger` | Corrupts physical IoT telemetry and logical ledger state in a single payload. |

---

## 4. Security Boundaries

All requests are validated on the backend at the HTTP boundary:
1. **No Code Execution:** Arbitrary Python code, eval/exec strings, shell scripts, and SQL statements are rejected.
2. **Strict Whitelist:** Unrecognized attack types or unsupported target attributes are rejected with HTTP 422 / 400.
3. **Network Isolation:** Attacker application communicates with Defender exclusively via HTTP client; no shared memory or internal library imports between Part 1 and Part 2 are permitted.
