"""Manual API verification script executing and recording responses from all Section 12 endpoints."""

import json
import sys
from fastapi.testclient import TestClient
from app.api.main import app

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")


def run_manual_verification():
    client = TestClient(app)

    endpoints_to_test = [
        ("GET", "/api/health"),
        ("GET", "/api/warehouse/current"),
        ("GET", "/api/security/status"),
        ("GET", "/api/security/latest"),
        ("GET", "/api/security/alerts"),
        ("GET", "/api/security/events?limit=5"),
        ("GET", "/api/security/audit-chain/verify"),
        ("GET", "/api/scenarios"),
        ("POST", "/api/warehouse/step"),
        ("POST", "/api/scenarios/capacity_manipulation"),
        ("GET", "/api/docs"),
    ]

    print("\n" + "=" * 80)
    print(" PHASE 4: MANUAL API ENDPOINT VERIFICATION")
    print("=" * 80)

    for method, path in endpoints_to_test:
        print(f"\n>>> {method} {path}")
        if method == "GET":
            response = client.get(path)
        else:
            response = client.post(path)

        print(f"Status: {response.status_code}")
        if path == "/api/docs":
            print(f"Response: HTML Document Loaded Successfully (Content Length: {len(response.text)} bytes, Content-Type: {response.headers.get('content-type')})")
        else:
            try:
                formatted = json.dumps(response.json(), indent=2)
                print(f"Response Body:\n{formatted}")
            except Exception:
                print(f"Response Body: {response.text}")
        print("-" * 80)


if __name__ == "__main__":
    run_manual_verification()
