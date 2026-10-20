# Comprehensive Deployment and Operations Guide

**Project:** Optimus Cybersecurity Monitoring and AI Attack Simulation Platform  
**Target Systems:** Part 1 (Defender Platform, Port 8000) & Part 2 (AI Attacker Application, Port 8001)  
**Author:** Senior Systems Architect & Security Engineering  

---

## 1. System Architecture & Component Overview

The platform consists of two architecturally isolated applications operating in tandem:

```text
       ┌────────────────────────────────────────────────────────┐
       │                BROWSER / OPERATOR WORKSTATION          │
       └────────────────────────┬───────────────────────┬───────┘
                                │                       │
            Port 8000           │                       │  Port 8001
      HttpOnly: optimus_operator_session     HttpOnly: optimus_attacker_session
                                │                       │
                                ▼                       ▼
  ┌─────────────────────────────────────────┐  ┌────────────────────────────────────┐
  │   PART 1: DEFENDER PLATFORM (:8000)     │  │  PART 2: AI ATTACKER APP (:8001)   │
  │                                         │  │                                    │
  │ • FastAPI Application & Security Engine │  │ • FastAPI Attacker Controller      │
  │ • IoT Telemetry & Invariant Checks (C1-C3) │ • Heuristic & LLM Planner (Mock/AI) │
  │ • Scikit-learn Isolation Forest ML      │  │ • Human-in-the-Loop Approval Gate  │
  │ • Temporal Tracker & Blast Graph        │  │ • Static Attacker Web Console      │
  │ • Static Dashboards (/ & /operations)   │  │ • Whitelist Boundary Validator     │
  │ • Protected Attack Gateway (/api/attacker) │                                    │
  └────────────────────▲────────────────────┘  └─────────────────┬──────────────────┘
                       │                                         │
                       └──────── HTTP REST (Shared Token) ───────┘
                                 ATTACK_GATEWAY_TOKEN
```

---

## 2. Prerequisites & Installation

### 2.1 System Requirements
- **Operating System:** Linux (Ubuntu 20.04+, Debian 11+), macOS (12+), or Windows 10/11 / Windows Server 2022.
- **Python Version:** Python 3.10, 3.11, 3.12, or 3.13.
- **Network Interfaces:** Minimum 2 local ports available: `8000` (Defender) and `8001` (Attacker).

### 2.2 Installation Steps
```bash
# 1. Clone repository and navigate to root directory
cd optimus-main

# 2. Create and activate a Python virtual environment
python -m venv venv
# On Linux / macOS:
source venv/bin/activate
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1

# 3. Install required dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 3. Configuration & Environment Variables

All settings are managed via environment variables and loaded through `pydantic-settings` or `.env`.

Initialize your environment configuration:
```bash
cp .env.example .env
```

### 3.1 Configuration Reference

| Variable | Default Value | Production Requirement | Purpose |
| :--- | :--- | :--- | :--- |
| `LOCAL_DEMO_MODE` | `true` | Set to `false` in production | When `true`, loopback calls (`127.0.0.1`, `::1`) bypass token requirements for frictionless local demonstration. In strict mode (`false`), every state-changing endpoint mandates authentication. |
| `OPERATOR_TOKEN` | `dev-operator-token-change-in-prod` | Generate cryptographically secure secret (`openssl rand -hex 32`) | Secret token for authorized Defender operations. |
| `ATTACK_GATEWAY_TOKEN` | `dev-gateway-token-change-in-prod` | Generate cryptographically secure secret (`openssl rand -hex 32`) | **Shared secret** used by Attacker client (`gateway_client.py`) to authenticate requests to Defender Attack Gateway. Both apps must share this value. |
| `ATTACKER_API_KEY` | `dev-attacker-key-change-in-prod` | Generate cryptographically secure secret (`openssl rand -hex 32`) | Secret key required to access Attacker Console endpoints. |
| `CORS_ORIGINS` | `http://localhost:8000,http://127.0.0.1:8000,http://localhost:8001,http://127.0.0.1:8001` | Set to explicit production FQDNs | Trusted CORS origins for browser fetch requests. |
| `LLM_PROVIDER` | `mock` | `mock`, `openai`, or `anthropic` | Planner engine. `mock` operates fully offline without API keys or costs. |
| `OPENAI_API_KEY` | *(empty)* | Optional (Required if `LLM_PROVIDER=openai`) | API key for OpenAI GPT-4o / GPT-4 models. |
| `ANTHROPIC_API_KEY` | *(empty)* | Optional (Required if `LLM_PROVIDER=anthropic`) | API key for Anthropic Claude models. |

> [!CAUTION]
> **Never commit `.env` or production API tokens into version control.** Ensure `.env` is listed in `.gitignore`.

---

## 4. Application Startup Procedures

### 4.1 Running Part 1: Organization Defender Platform
Launch the primary defender service on port 8000:
```bash
python run.py
```
- **Defender Security Dashboard:** `http://127.0.0.1:8000`
- **Warehouse Operations Monitor:** `http://127.0.0.1:8000/operations`
- **Interactive OpenAPI Documentation:** `http://127.0.0.1:8000/api/docs`

#### CLI Demonstration Mode (Headless / Non-Browser)
To run an automated command-line demonstration showing pipeline detection of capacity manipulation, sensor spoofing, and inventory corruption:
```bash
python run.py --demo
```

### 4.2 Running Part 2: AI Attacker Application
In a separate terminal window, launch the attacker service on port 8001:
```bash
python run_attacker.py
```
- **AI Attacker Console:** `http://127.0.0.1:8001`
- **Attacker OpenAPI Documentation:** `http://127.0.0.1:8001/docs`

---

## 5. Frontend & Browser Authentication Architecture

### 5.1 Same-Origin Session Architecture
To avoid storing long-lived privileged API tokens in vulnerable browser storage (`localStorage` / `sessionStorage`), the platform provides secure, dedicated session endpoints:

1. **Defender Authentication:**
   - `POST /api/auth/login`: Accepts `{"token": "<OPERATOR_TOKEN>"}`. Sets an `HttpOnly`, `SameSite=Lax` cookie (`optimus_operator_session`).
   - `POST /api/auth/logout`: Clears the session cookie.
   - `GET /api/auth/session`: Checks whether the current browser session or loopback client is authorized.

2. **Attacker Authentication:**
   - `POST /api/attacker/auth/login`: Accepts `{"token": "<ATTACKER_API_KEY>"}`. Sets an `HttpOnly`, `SameSite=Lax` cookie (`optimus_attacker_session`).
   - `POST /api/attacker/auth/logout`: Clears the session cookie.
   - `GET /api/attacker/auth/session`: Checks authorization status.

3. **In-Memory Closure Token Support:**
   - Frontends (`app.js`, `operations.js`, `attacker.js`) encapsulate runtime token state within private JavaScript closures.
   - If a privileged API call returns HTTP 401, the user is prompted to authenticate via the session endpoint or provide an in-memory token. Tokens are **never** persisted to `localStorage`.

### 5.2 Loopback Demo Mode vs. Strict Production Mode
- **Local Demo Mode (`LOCAL_DEMO_MODE=true`):** Requests originating from loopback interfaces (`127.0.0.1`, `::1`, `localhost`) are permitted unauthenticated to facilitate immediate evaluation and classroom demonstration. Remote or forwarded requests (`X-Forwarded-For`) are strictly rejected.
- **Strict Mode (`LOCAL_DEMO_MODE=false`):** Unauthenticated access is rejected with HTTP 401 across all interfaces. Operators and Attacker console users must log in via the session endpoints or provide credentials via `Authorization: Bearer <TOKEN>`.

---

## 6. Production Hardening & Reverse Proxy Deployment

In a production environment, neither service should be directly exposed to public networks. Deploy behind a reverse proxy (e.g. Nginx, Caddy, or Cloudflare Tunnel) terminating TLS.

### 6.1 Sample Nginx Configuration
```nginx
# Defender Platform Reverse Proxy with TLS Termination
server {
    listen 443 ssl http2;
    server_name defender.warehouse.internal;

    ssl_certificate     /etc/ssl/certs/optimus_defender.crt;
    ssl_certificate_key /etc/ssl/private/optimus_defender.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        # Ensure SameSite cookies and secure transport
        proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Lax";
    }
}

# Attacker Console (Restricted Management Network Only)
server {
    listen 443 ssl http2;
    server_name attacker.warehouse.internal;

    ssl_certificate     /etc/ssl/certs/optimus_attacker.crt;
    ssl_certificate_key /etc/ssl/private/optimus_attacker.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Restrict attacker console to administrative bastion hosts
    allow 10.0.10.0/24;
    deny all;

    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Lax";
    }
}
```

---

## 7. Verification & Automated Test Procedures

Run the full verification suite before deploying any changes:

```bash
# 1. Run all 170 automated test cases
pytest tests/ -v

# 2. Verify complete Python syntax and compilation
python -m compileall app attacker_app tests

# 3. Verify specific browser and session regression tests
pytest tests/test_browser_auth.py -v

# 4. Verify inter-service security protection
pytest tests/test_security_protection.py -v
```

---

## 8. Operating Boundaries & Production Limitations

1. **In-Memory Warehouse State:** The cold-storage warehouse simulator and detection history reside in process memory. Terminating or restarting the Python process resets the simulation state to step 0. For persistent production state, a persistent datastore (PostgreSQL/Redis) is required.
2. **External Model Requirements:** When `LLM_PROVIDER` is set to `openai` or `anthropic`, the application requires external outbound internet egress to vendor API endpoints. In air-gapped environments, use `LLM_PROVIDER=mock`.
3. **Simulation Boundary:** The Attacker Application is strictly constrained by a whitelist validator (`attacker_app/validator.py`) and an isolated gateway client. It cannot execute arbitrary network scans or lateral attacks against external hosts.
4. **Human Approval Enforcement:** The Attacker Application cannot autonomously execute attacks against the Defender without a human operator explicitly clicking `[ APPROVE & EXECUTE ]` or issuing an approved execution payload (`approved: true`).

---

## 9. Troubleshooting

| Symptom | Cause | Resolution |
| :--- | :--- | :--- |
| **HTTP 401 on Attack Execution** | `ATTACK_GATEWAY_TOKEN` mismatch between Defender and Attacker `.env` files. | Ensure both applications load identical `ATTACK_GATEWAY_TOKEN` values from `.env`. |
| **HTTP 401 on Operator Actions** | `LOCAL_DEMO_MODE=false` and browser session is unauthenticated. | Authenticate via `POST /api/auth/login` or supply `Authorization: Bearer <TOKEN>` header. |
| **Port Conflict (`[Errno 10048]`)** | A previous Python or Uvicorn instance is still bound to port 8000 or 8001. | Terminate the existing process via task manager or PowerShell (`Stop-Process -Id <PID> -Force`). |
| **Gateway Offline Warning in Attacker UI** | Defender is not running or running on a non-default host/port. | Ensure `python run.py` is running on port 8000 and accessible via `http://127.0.0.1:8000`. |
