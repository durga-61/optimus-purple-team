"""AI Planner abstraction and implementations for Part 2 AI Attacker Application.

Provides:
- AIPlanner base class
- DeterministicPlanner (explicitly labeled 'DETERMINISTIC FALLBACK')
- LLMPlanner (parses structured JSON, zero raw execution, falls back if unconfigured)
"""

import abc
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError

from attacker_app.config import config
from attacker_app.providers import LLMProvider, LLMProviderError, get_llm_provider
from attacker_app.schemas import (
    AttackProposal,
    AttackerObservation,
    LLMPlanResponse,
    ProposalValidationResult,
)
from attacker_app.validator import validate_proposal

logger = logging.getLogger("attacker.planner")

SYSTEM_PLANNER_PROMPT = """You are an adversarial attack strategy planner for an organization security evaluation.
Analyze the limited operational telemetry provided and formulate a targeted attack proposal.
You must respond with valid JSON ONLY matching this exact schema:
{
  "strategy_rationale": "A concise 1-3 sentence explanation of why this vector was chosen",
  "attack_type": "one of: capacity_manipulation, inventory_manipulation, sensor_spoofing, replay_attack, coordinated_weak, multi_source",
  "target": "target metric name matching the attack type",
  "value": 45.0,
  "objective": "specific tactical objective of the maneuver"
}

Whitelisted attack types and target requirements:
- capacity_manipulation: target must be "free_capacity" (value: positive float)
- inventory_manipulation: target must be "inventory" (value: positive float)
- sensor_spoofing: target must be "temperature" (value: -50.0 to 80.0) or "humidity" (value: 0.0 to 100.0)
- replay_attack: target must be "inventory" (value: float or null)
- coordinated_weak: target must be "multi_metric" (value: float or null)
- multi_source: target must be "facility" (value: float or null)

Do NOT execute code, shell commands, or scripts.
Do NOT output markdown blocks, backticks, or extra commentary. Output pure JSON only."""


class AIPlanner(abc.ABC):
    """Abstract base class for attack proposal planners."""

    @property
    @abc.abstractmethod
    def label(self) -> str:
        """User-facing label for the planner."""
        pass

    @abc.abstractmethod
    def propose(
        self,
        observation: AttackerObservation,
        history: List[Dict[str, Any]],
        objective_hint: Optional[str] = None,
    ) -> Tuple[Optional[AttackProposal], str, str, ProposalValidationResult]:
        """Generate a candidate attack proposal based strictly on the limited observation.

        Returns:
            (AttackProposal or None, planner_label, strategy_rationale, validation_result)
        """
        pass


class DeterministicPlanner(AIPlanner):
    """Deterministic fallback planner operating without external LLM access.

    Uses cyclic heuristic strategies over the restricted observation fields.
    """

    @property
    def label(self) -> str:
        return "DETERMINISTIC FALLBACK"

    def propose(
        self,
        observation: AttackerObservation,
        history: List[Dict[str, Any]],
        objective_hint: Optional[str] = None,
    ) -> Tuple[Optional[AttackProposal], str, str, ProposalValidationResult]:
        step_idx = len(history)
        strategy_idx = step_idx % 6

        # Generate proposal based on current observation values
        if strategy_idx == 0:
            proposed_free = round(observation.free_capacity + 30.0, 1)
            proposal = AttackProposal(
                attack_type="capacity_manipulation",
                target="free_capacity",
                value=proposed_free,
                objective=objective_hint or "Desynchronize reported free capacity from physical volume.",
            )
            rationale = "Targeting storage volume discrepancy by manipulating free capacity independent of inventory level."
        elif strategy_idx == 1:
            target_inv = max(0.0, round(observation.inventory - 15.0, 1))
            proposal = AttackProposal(
                attack_type="inventory_manipulation",
                target="inventory",
                value=target_inv,
                objective=objective_hint or "Introduce inventory loss discrepancy in storage ledger.",
            )
            rationale = "Injecting inventory flow mismatch to evaluate conservation check sensitivity."
        elif strategy_idx == 2:
            spoofed_temp = round(observation.temperature + 18.0, 1)
            proposal = AttackProposal(
                attack_type="sensor_spoofing",
                target="temperature",
                value=spoofed_temp,
                objective=objective_hint or "Spoof cold-chain temperature beyond operating envelope.",
            )
            rationale = "Elevating reported cold storage temperature above safe operating baseline."
        elif strategy_idx == 3:
            proposal = AttackProposal(
                attack_type="replay_attack",
                target="inventory",
                value=observation.inventory,
                objective=objective_hint or "Replay stale inventory readings across consecutive intervals.",
            )
            rationale = "Replaying static inventory telemetry across dynamic operational intervals."
        elif strategy_idx == 4:
            proposal = AttackProposal(
                attack_type="coordinated_weak",
                target="multi_metric",
                value=-1.0,
                objective=objective_hint or "Execute coordinated sub-threshold drift across multiple metrics.",
            )
            rationale = "Applying distributed subtle variations across multiple metrics simultaneously."
        else:
            proposal = AttackProposal(
                attack_type="multi_source",
                target="facility",
                value=1.0,
                objective=objective_hint or "Trigger simultaneous physical sensor and ledger divergence.",
            )
            rationale = "Creating cross-subsystem discrepancy between physical telemetry and ledger logs."

        is_valid, val_res, parsed = validate_proposal(proposal)
        return parsed, self.label, rationale, val_res


class LLMPlanner(AIPlanner):
    """LLM-assisted attack planner.

    Parses LLM structured responses into strict AttackProposal schemas.
    Never executes raw LLM code or commands. Falls back to DeterministicPlanner
    when no provider or API key is available.
    """

    def __init__(self, provider: Optional[LLMProvider] = None):
        self.provider = provider or get_llm_provider()
        self._fallback_planner = DeterministicPlanner()

    @property
    def label(self) -> str:
        if not self.provider:
            return "DETERMINISTIC FALLBACK (No LLM Provider Configured)"
        return f"LLM PLANNER ({self.provider.provider_name} {self.provider.model_name})"

    def _build_user_prompt(
        self,
        observation: AttackerObservation,
        history: List[Dict[str, Any]],
        objective_hint: Optional[str] = None,
    ) -> str:
        recent_feedback = []
        for h in history[-3:]:
            if h.get("result"):
                res = h["result"]
                recent_feedback.append({
                    "type": h["proposal"].get("attack_type"),
                    "detection": res.get("detection"),
                    "classification": res.get("classification"),
                })

        return (
            "Observed Operational Telemetry:\n"
            f"- Facility Target: {observation.target}\n"
            f"- Inventory Level: {observation.inventory} tons\n"
            f"- Free Capacity: {observation.free_capacity} tons\n"
            f"- Cold Storage Temperature: {observation.temperature} C\n"
            f"- Facility Humidity: {observation.humidity} %\n"
            f"- Area Occupancy: {observation.occupancy} %\n\n"
            f"Strategic Objective Hint: {objective_hint or 'Evade detection while disrupting facility metrics'}\n"
            f"Recent Attempts Feedback: {json.dumps(recent_feedback)}\n\n"
            "Formulate your adversarial strategy proposal in pure JSON:"
        )

    def propose(
        self,
        observation: AttackerObservation,
        history: List[Dict[str, Any]],
        objective_hint: Optional[str] = None,
    ) -> Tuple[Optional[AttackProposal], str, str, ProposalValidationResult]:
        if not self.provider:
            logger.info("No LLM provider available. Routing to deterministic fallback planner.")
            prop, _, rat, val = self._fallback_planner.propose(observation, history, objective_hint)
            return prop, self.label, rat, val

        user_prompt = self._build_user_prompt(observation, history, objective_hint)

        try:
            raw_response = self.provider.generate(prompt=user_prompt, system_prompt=SYSTEM_PLANNER_PROMPT)
        except LLMProviderError as e:
            logger.warning(f"LLM Provider Error: {e}. Falling back to deterministic planner.")
            prop, _, rat, val = self._fallback_planner.propose(observation, history, objective_hint)
            return prop, f"{self.label} (Provider Error - Fallback Active)", f"Provider error: {e}. Defaulted to deterministic fallback.", val
        except Exception as e:
            logger.error(f"Unexpected error in LLM generation: {e}")
            prop, _, rat, val = self._fallback_planner.propose(observation, history, objective_hint)
            return prop, f"{self.label} (Fallback Active)", f"Unexpected error: {e}. Defaulted to fallback.", val

        # Clean JSON markdown wrapper if present
        clean_text = raw_response.strip()
        if "```json" in clean_text:
            clean_text = clean_text.split("```json")[1].split("```")[0].strip()
        elif "```" in clean_text:
            clean_text = clean_text.split("```")[1].split("```")[0].strip()

        # Attempt JSON parse
        try:
            parsed_dict = json.loads(clean_text)
            if not isinstance(parsed_dict, dict):
                raise ValueError("Parsed JSON is not an object dictionary.")
        except Exception as json_err:
            logger.warning(f"Malformed LLM output: not valid JSON ({json_err}). Raw output: {clean_text[:100]}")
            val_res = ProposalValidationResult(
                valid=False,
                errors=[f"Malformed LLM output: response is not valid JSON ({json_err})"],
            )
            return None, self.label, "Failed to parse structured JSON from LLM response.", val_res

        # Attempt strict LLMPlanResponse schema parse
        try:
            plan_response = LLMPlanResponse(**parsed_dict)
        except ValidationError as val_err:
            errors = []
            for err in val_err.errors():
                loc = ".".join(str(p) for p in err.get("loc", []))
                errors.append(f"Schema violation at '{loc}': {err.get('msg')}")
            val_res = ProposalValidationResult(valid=False, errors=errors)
            rationale = parsed_dict.get("strategy_rationale", "Schema validation rejected LLM output.")
            return None, self.label, str(rationale), val_res

        # Validate proposal with local validator
        proposal_candidate = AttackProposal(
            attack_type=plan_response.attack_type,
            target=plan_response.target,
            value=plan_response.value,
            objective=plan_response.objective,
        )
        is_valid, val_res, parsed_proposal = validate_proposal(proposal_candidate)
        if not is_valid:
            return None, self.label, plan_response.strategy_rationale, val_res

        return parsed_proposal, self.label, plan_response.strategy_rationale, val_res
