"""In-memory state management for Part 2 AI Attacker Application."""

import datetime
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from attacker_app.gateway_client import AttackGatewayClient, GatewayClientError
from attacker_app.planner import AIPlanner, DeterministicPlanner, LLMPlanner
from attacker_app.schemas import (
    AttackFeedback,
    AttackProposal,
    AttackerHistoryItem,
    AttackerObservation,
    ExperimentRecord,
    ProposalValidationResult,
)


class AttackerAppState:
    """Thread-safe state manager for the Attacker application."""

    def __init__(self, gateway_client: Optional[AttackGatewayClient] = None):
        self._lock = threading.RLock()
        self.gateway_client = gateway_client or AttackGatewayClient()
        self.current_observation: Optional[AttackerObservation] = None
        self.pending_proposal: Optional[AttackProposal] = None
        self.pending_proposal_id: Optional[str] = None
        self.pending_planner_label: Optional[str] = None
        self.pending_strategy_rationale: Optional[str] = None
        self.pending_observed_telemetry: Optional[AttackerObservation] = None
        self.pending_validation: Optional[ProposalValidationResult] = None
        self.history: List[AttackerHistoryItem] = []
        self.experiments: List[ExperimentRecord] = []
        self._proposal_counter = 0
        self._experiment_counter = 0

        # Registered planners
        self.deterministic_planner = DeterministicPlanner()
        self.llm_planner = LLMPlanner()

    def get_planner(self, planner_type: str) -> AIPlanner:
        if planner_type == "llm":
            return self.llm_planner
        return self.deterministic_planner

    def fetch_observation(self) -> AttackerObservation:
        """Query observation from gateway and cache locally."""
        with self._lock:
            obs = self.gateway_client.get_observation()
            self.current_observation = obs
            return obs

    def generate_proposal(
        self, planner_type: str = "deterministic", objective_hint: Optional[str] = None
    ) -> Tuple[
        Optional[AttackProposal],
        ProposalValidationResult,
        str,
        str,
        Optional[AttackerObservation],
    ]:
        """Generate candidate proposal via selected planner without executing."""
        with self._lock:
            if not self.current_observation:
                self.fetch_observation()

            planner = self.get_planner(planner_type)
            history_dicts = [h.model_dump() for h in self.history]
            proposal, planner_label, rationale, val_res = planner.propose(
                self.current_observation, history_dicts, objective_hint
            )

            self._proposal_counter += 1
            prop_id = f"PROP-{self._proposal_counter:04d}"

            self.pending_proposal = proposal
            self.pending_proposal_id = prop_id
            self.pending_planner_label = planner_label
            self.pending_strategy_rationale = rationale
            self.pending_observed_telemetry = self.current_observation
            self.pending_validation = val_res

            return (
                self.pending_proposal,
                val_res,
                planner_label,
                rationale,
                self.pending_observed_telemetry,
            )

    def execute_pending_proposal(
        self, proposal_id: Optional[str] = None, approved: bool = True
    ) -> AttackFeedback:
        """Human-in-the-loop: Send approved pending proposal to the gateway."""
        with self._lock:
            if not approved:
                raise ValueError("Proposal execution rejected: explicit human approval confirmation is required.")

            if not self.pending_proposal:
                raise ValueError("No pending attack proposal to execute.")

            if proposal_id and self.pending_proposal_id and proposal_id != self.pending_proposal_id:
                raise ValueError(
                    f"Proposal ID mismatch: specified '{proposal_id}' but active pending proposal is '{self.pending_proposal_id}'."
                )

            if not self.pending_validation or not self.pending_validation.valid:
                raise ValueError("Pending proposal failed local validation and cannot be executed.")

            # Transmit to Part 1 Attack Gateway and measure detection delay
            start_time = time.time()
            feedback = self.gateway_client.execute_attack(self.pending_proposal)
            detection_delay_ms = round((time.time() - start_time) * 1000.0, 2)

            # Record in local history
            history_entry = AttackerHistoryItem(
                proposal_id=self.pending_proposal_id or f"PROP-{self._proposal_counter:04d}",
                proposal=self.pending_proposal,
                planner=self.pending_planner_label or "UNKNOWN",
                validation=self.pending_validation,
                strategy_rationale=self.pending_strategy_rationale,
                observed_telemetry_snapshot=self.pending_observed_telemetry,
                executed=True,
                result=feedback,
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            )
            self.history.append(history_entry)

            # Create immutable Experiment Record
            self._experiment_counter += 1
            exp_id = f"EXP-{self._experiment_counter:04d}"
            exp_record = ExperimentRecord(
                experiment_id=exp_id,
                attack_id=feedback.attack_id,
                timestamp=feedback.timestamp,
                attack_type=self.pending_proposal.attack_type,
                target=self.pending_proposal.target,
                value=self.pending_proposal.value,
                execution_status=feedback.execution,
                detection_status=feedback.detection,
                classification=feedback.classification,
                detection_delay_ms=detection_delay_ms,
            )
            self.experiments.append(exp_record)

            # Clear pending proposal
            self.pending_proposal = None
            self.pending_proposal_id = None
            self.pending_planner_label = None
            self.pending_strategy_rationale = None
            self.pending_observed_telemetry = None
            self.pending_validation = None

            # Refresh observation after attack
            try:
                self.current_observation = self.gateway_client.get_observation()
            except Exception:
                pass

            return feedback

    def discard_pending_proposal(self) -> None:
        """Discard current candidate proposal without executing."""
        with self._lock:
            self.pending_proposal = None
            self.pending_proposal_id = None
            self.pending_planner_label = None
            self.pending_strategy_rationale = None
            self.pending_observed_telemetry = None
            self.pending_validation = None

    def clear_history(self) -> Dict[str, Any]:
        """Clear attacker proposal history and evaluation experiment logs."""
        with self._lock:
            self.history.clear()
            self.experiments.clear()
            self._experiment_counter = 0
            return {
                "success": True,
                "history_cleared": True,
                "experiments_cleared": True,
            }

    def reset_attacker(self) -> Dict[str, Any]:
        """Reset attacker local state, pending proposals, and history."""
        with self._lock:
            self.discard_pending_proposal()
            self.clear_history()
            self.current_observation = None
            self._proposal_counter = 0
            return {
                "success": True,
                "attacker_reset": True,
            }

    def reset_defender(self) -> Dict[str, Any]:
        """Reset Part 1 warehouse simulator and defender pipeline via Attack Gateway."""
        gateway_res = self.gateway_client.reset_gateway()
        return {
            "success": True,
            "defender_reset": True,
            "gateway_response": gateway_res,
        }

    def reset(self, scope: str = "all") -> Dict[str, Any]:
        """Reset simulation environment based on specified scope with accurate reporting."""
        with self._lock:
            if scope == "history_only":
                res = self.clear_history()
                res["scope"] = "history_only"
                return res

            if scope == "attacker_only":
                res = self.reset_attacker()
                res["scope"] = "attacker_only"
                return res

            if scope == "defender_only":
                try:
                    res = self.reset_defender()
                    res["scope"] = "defender_only"
                    return res
                except GatewayClientError as e:
                    return {
                        "success": False,
                        "scope": "defender_only",
                        "error": str(e),
                        "message": f"Defender Gateway reset failed: {e}",
                    }

            # scope == "all"
            gateway_res = None
            gateway_success = False
            gateway_err = None
            try:
                gateway_res = self.gateway_client.reset_gateway()
                gateway_success = True
            except GatewayClientError as e:
                gateway_err = str(e)

            # Local attacker state is always cleaned
            self.reset_attacker()

            if gateway_success:
                try:
                    self.fetch_observation()
                except Exception:
                    pass

                return {
                    "success": True,
                    "scope": "all",
                    "attacker_reset": True,
                    "gateway_success": True,
                    "gateway_response": gateway_res,
                    "message": "Complete simulation (Defender & Attacker) successfully reset to baseline.",
                }
            else:
                return {
                    "success": False,
                    "scope": "all",
                    "attacker_reset": True,
                    "gateway_success": False,
                    "gateway_error": gateway_err,
                    "message": f"Attacker state reset locally, but Defender Gateway reset failed: {gateway_err}",
                }


# Singleton instance for the attacker application
attacker_state = AttackerAppState()
