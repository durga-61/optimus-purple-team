"""HTTP Attack Gateway Client for Part 2 AI Attacker Application.

This client is the ONLY network egress allowed from the Attacker Application.
It strictly connects to the Part 1 Attack Gateway endpoints. Arbitrary URL calls
are blocked by design.
"""

import logging
from typing import Any, Dict, Optional
import httpx

from attacker_app.config import config
from attacker_app.schemas import AttackFeedback, AttackProposal, AttackerObservation

logger = logging.getLogger("attacker.gateway_client")


class GatewayClientError(Exception):
    """Base exception for Attack Gateway communication issues."""
    pass


class AttackGatewayClient:
    """Restricted HTTP client that communicates only with the Part 1 Attack Gateway."""

    APPROVED_ENDPOINTS = {"observation", "attack", "reset"}

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
        token: Optional[str] = None,
    ):
        self.base_url = (base_url or config.GATEWAY_BASE_URL).rstrip("/")
        self.timeout = timeout or config.REQUEST_TIMEOUT
        self.token = token if token is not None else config.GATEWAY_TOKEN

    def _get_headers(self) -> Dict[str, str]:
        """Construct request headers including server-side Bearer authentication token."""
        headers: Dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _build_url(self, path: str) -> str:
        """Construct an absolute gateway URL strictly within the gateway prefix.

        Rejects arbitrary path or URL construction. Only 4 approved endpoints allowed:
        - observation
        - attack
        - result/{attack_id}
        - reset
        """
        clean_path = path.strip().lstrip("/")
        parts = clean_path.split("/")
        is_result = len(parts) == 2 and parts[0] == "result" and bool(parts[1])
        if clean_path not in self.APPROVED_ENDPOINTS and not is_result:
            raise GatewayClientError(
                f"Arbitrary URL construction rejected: path '{path}' is not an approved gateway endpoint."
            )
        return f"{self.base_url}/{clean_path}"

    def get_observation(self) -> AttackerObservation:
        """Fetch current restricted operational observation from Part 1 gateway."""
        url = self._build_url("observation")
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(url, headers=self._get_headers())
                if res.status_code == 401:
                    raise GatewayClientError(f"Gateway Authentication Failed (HTTP 401): {res.text}")
                if res.status_code != 200:
                    raise GatewayClientError(
                        f"Gateway returned status {res.status_code}: {res.text}"
                    )
                return AttackerObservation(**res.json())
        except httpx.RequestError as exc:
            raise GatewayClientError(f"Failed to connect to Attack Gateway at {url}: {exc}") from exc

    def execute_attack(self, proposal: AttackProposal) -> AttackFeedback:
        """Submit a validated attack proposal to Part 1 gateway for execution."""
        url = self._build_url("attack")
        payload = proposal.model_dump(exclude_none=True)
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(url, json=payload, headers=self._get_headers())
                if res.status_code == 401:
                    raise GatewayClientError(f"Gateway Authentication Failed (HTTP 401): {res.text}")
                if res.status_code == 429:
                    raise GatewayClientError(f"Gateway Rate Limit Exceeded (HTTP 429): {res.text}")
                if res.status_code != 200:
                    raise GatewayClientError(
                        f"Gateway rejected attack (HTTP {res.status_code}): {res.text}"
                    )
                return AttackFeedback(**res.json())
        except httpx.RequestError as exc:
            raise GatewayClientError(f"Failed to execute attack via Gateway at {url}: {exc}") from exc

    def get_result(self, attack_id: str) -> AttackFeedback:
        """Retrieve historical attack feedback from gateway by attack ID."""
        url = self._build_url(f"result/{attack_id}")
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(url, headers=self._get_headers())
                if res.status_code == 401:
                    raise GatewayClientError(f"Gateway Authentication Failed (HTTP 401): {res.text}")
                if res.status_code == 404:
                    raise GatewayClientError(f"Attack ID '{attack_id}' not found on gateway.")
                if res.status_code != 200:
                    raise GatewayClientError(
                        f"Gateway returned status {res.status_code}: {res.text}"
                    )
                return AttackFeedback(**res.json())
        except httpx.RequestError as exc:
            raise GatewayClientError(f"Failed to query result at {url}: {exc}") from exc

    def reset_gateway(self) -> Dict[str, Any]:
        """Request reset of the simulator baseline and attack history on Part 1."""
        url = self._build_url("reset")
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(url, headers=self._get_headers())
                if res.status_code == 401:
                    raise GatewayClientError(f"Gateway Authentication Failed (HTTP 401): {res.text}")
                if res.status_code != 200:
                    raise GatewayClientError(
                        f"Gateway reset failed (HTTP {res.status_code}): {res.text}"
                    )
                return res.json()
        except httpx.RequestError as exc:
            raise GatewayClientError(f"Failed to connect to reset endpoint at {url}: {exc}") from exc
