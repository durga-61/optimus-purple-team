# API SPECIFICATION

## Defender APIs

### GET /api/status

Returns current organization security status.

### GET /api/live-data

Returns current simulated operational data.

### GET /api/security-analysis

Returns latest ML, semantic, temporal, structural and joint results.

### GET /api/events

Returns security event history.

### GET /api/alerts

Returns active and historical alerts.

### GET /api/system-health

Returns backend component health.

### POST /api/analyze

Processes a controlled observation through the complete defender pipeline.

---

# Attacker APIs

### GET /api/attacker/state

Returns the controlled organization snapshot available to the attacker.

### POST /api/attacker/propose

Receives an attack proposal.

### POST /api/attacker/validate

Validates the proposal.

### POST /api/attacker/execute

Executes an approved proposal.

### GET /api/attacker/history

Returns attacker action history.

---

# Security Rules

The attacker API must reject:

* arbitrary code;
* SQL;
* shell commands;
* filesystem operations;
* unsupported fields;
* invalid data types;
* out-of-range values;
* security-engine modifications.

The backend, not the frontend, performs validation.
