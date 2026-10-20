"""Dynamic operational invariant mining for OPTIMUS.

Discovers candidate relationships from clean historical telemetry, measures
their coverage on trusted normal data and their discrimination against known
attacks, rejects unstable/redundant/overly-restrictive rules, and activates
only explicitly approved invariants through ``SemanticEngine``.

Mined rules are hypotheses, not proof of security.  Domain review plus an
independent validation split are required before activation.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
from pydantic import BaseModel, Field

from app.config import settings
from app.defender.models import ConstraintResult
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("defender.invariant_miner")


class InvariantCandidate(BaseModel):
    """A candidate operational invariant with its measured validation evidence."""

    candidate_id: str
    name: str
    family: str
    kind: str = Field(description="residual, envelope, slew, or rate")
    description: str = ""
    tolerance: float = 0.0
    parameters: Dict[str, Any] = Field(default_factory=dict)
    field: Optional[str] = None
    duplicate_of: Optional[str] = None
    status: str = Field(default="CANDIDATE")
    discovery_coverage: float = 1.0
    validation_coverage: float = 0.0
    attack_detection_rate: float = 0.0
    false_positive_rate: float = 1.0
    per_class_detection: Dict[str, float] = Field(default_factory=dict)
    stability_gap: float = 0.0
    rejection_reason: Optional[str] = None
    validated_at: Optional[str] = None
    activated_at: Optional[str] = None


class ActiveInvariant(BaseModel):
    """A validated invariant installed in the semantic detection layer."""

    candidate_id: str
    name: str
    family: str
    kind: str
    tolerance: float
    parameters: Dict[str, Any] = Field(default_factory=dict)
    field: Optional[str] = None
    active: bool = True

    @classmethod
    def from_candidate(cls, candidate: InvariantCandidate) -> "ActiveInvariant":
        return cls(
            candidate_id=candidate.candidate_id,
            name=candidate.name,
            family=candidate.family,
            kind=candidate.kind,
            tolerance=candidate.tolerance,
            parameters=dict(candidate.parameters),
            field=candidate.field,
        )

    def check(
        self,
        observation: WarehouseObservation,
        previous_observation: Optional[WarehouseObservation] = None,
    ) -> ConstraintResult:
        """Evaluate the invariant and return a semantic-layer ConstraintResult."""
        expected: Any
        actual: Any
        difference = 0.0

        if self.kind == "residual":
            if self.family == "capacity":
                expected = observation.capacity
                actual = round(observation.inventory + observation.free_capacity, 4)
                difference = abs(actual - expected)
            elif self.family == "flow":
                if previous_observation is None:
                    return self._passed("No prior observation for flow invariant.")
                expected = round(
                    previous_observation.inventory + observation.inbound - observation.outbound, 4
                )
                actual = observation.inventory
                difference = abs(actual - expected)
            elif self.family == "occupancy":
                expected = round(100.0 * observation.inventory / observation.capacity, 4)
                actual = observation.occupancy
                difference = abs(actual - expected)
            else:
                raise ValueError(f"Unknown residual invariant family '{self.family}'")

        elif self.kind == "envelope":
            field = self.field or ""
            value = float(getattr(observation, field))
            low = float(self.parameters["min"])
            high = float(self.parameters["max"])
            expected = [low, high]
            actual = value
            difference = max(low - value, value - high, 0.0)

        elif self.kind == "slew":
            if previous_observation is None:
                return self._passed("No prior observation for slew invariant.")
            field = self.field or ""
            current = float(getattr(observation, field))
            previous = float(getattr(previous_observation, field))
            expected = f"|delta {field}| <= {self.tolerance:.4f}"
            actual = abs(current - previous)
            difference = actual

        elif self.kind == "rate":
            expected = f"max(inbound,outbound) <= {self.tolerance:.4f}"
            actual = max(observation.inbound, observation.outbound)
            difference = actual

        else:
            raise ValueError(f"Unknown invariant kind '{self.kind}'")

        passed = difference <= self.tolerance + 1e-9
        if passed:
            message = (
                f"{self.candidate_id} passed: discrepancy {difference:.4f} "
                f"<= tolerance {self.tolerance:.4f}."
            )
        else:
            message = (
                f"{self.candidate_id} violation: discrepancy {difference:.4f} "
                f"> tolerance {self.tolerance:.4f}."
            )
        return ConstraintResult(
            constraint=self.candidate_id,
            name=self.name,
            status="PASSED" if passed else "VIOLATED",
            expected=expected,
            actual=actual,
            difference=round(float(difference), 4),
            tolerance=round(float(self.tolerance), 4),
            message=message,
        )

    def _passed(self, message: str) -> ConstraintResult:
        return ConstraintResult(
            constraint=self.candidate_id,
            name=self.name,
            status="PASSED",
            expected="not applicable",
            actual="not applicable",
            difference=0.0,
            tolerance=self.tolerance,
            message=message,
        )


def _as_observations(records: Sequence[Any]) -> List[WarehouseObservation]:
    observations = []
    for record in records:
        observations.append(
            record.get_inference_observation()
            if hasattr(record, "get_inference_observation")
            else getattr(record, "observation", record)
        )
    return observations


def _learn_tolerance(
    residuals: Sequence[float],
    floor: float,
    quantile: float = 0.995,
    margin: float = 1.25,
) -> float:
    if not residuals:
        return float(floor)
    value = float(np.quantile(np.asarray(residuals, dtype=float), quantile)) * margin
    return round(max(floor, value), 4)


def _jaccard(left: Sequence[bool], right: Sequence[bool]) -> float:
    if len(left) != len(right):
        return 0.0
    union = sum(1 for a, b in zip(left, right) if a or b)
    if union == 0:
        return 1.0
    intersection = sum(1 for a, b in zip(left, right) if a and b)
    return intersection / union


class InvariantMiner:
    """Discover, validate, activate, and roll back mined semantic invariants."""

    def __init__(
        self,
        service: Optional[Any] = None,
        min_normal_coverage: float = settings.INVARIANT_MIN_NORMAL_COVERAGE,
        max_fpr: float = settings.INVARIANT_MAX_FPR,
        min_attack_detection: float = settings.INVARIANT_MIN_ATTACK_DETECTION,
        redundancy_jaccard: float = settings.INVARIANT_REDUNDANCY_JACCARD,
        max_stability_gap: float = 0.01,
    ):
        self.service = service
        self.min_normal_coverage = min_normal_coverage
        self.max_fpr = max_fpr
        self.min_attack_detection = min_attack_detection
        self.redundancy_jaccard = redundancy_jaccard
        self.max_stability_gap = max_stability_gap
        self.candidates: Dict[str, InvariantCandidate] = {}

    def _log(self, event_type: str, severity: str, message: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        if self.service is not None and hasattr(self.service, "_log_event"):
            self.service._log_event(
                event_type=event_type,
                severity=severity,
                message=message,
                step=0,
                metadata=metadata or {},
            )
        else:
            logger.info("[%s] %s", event_type, message)

    def discover(self, normal_records: Sequence[Any]) -> List[InvariantCandidate]:
        """Mine candidate relationships from trusted normal observations."""
        if any(int(getattr(record, "ground_truth_label", 0)) == 1 for record in normal_records):
            raise ValueError("Invariant discovery requires normal records only")
        observations = _as_observations(normal_records)
        if len(observations) < 10:
            raise ValueError("At least 10 clean observations are required for mining")

        capacity_residuals = [
            abs(obs.inventory + obs.free_capacity - obs.capacity) for obs in observations
        ]
        flow_residuals = [
            abs(
                obs.inventory
                - (observations[i - 1].inventory + obs.inbound - obs.outbound)
            )
            for i, obs in enumerate(observations)
            if i > 0
        ]
        occupancy_residuals = [
            abs(obs.occupancy - 100.0 * obs.inventory / obs.capacity) for obs in observations
        ]
        temperature_slew = [
            abs(obs.temperature - observations[i - 1].temperature)
            for i, obs in enumerate(observations)
            if i > 0
        ]
        humidity_slew = [
            abs(obs.humidity - observations[i - 1].humidity)
            for i, obs in enumerate(observations)
            if i > 0
        ]
        inventory_slew = [
            abs(obs.inventory - observations[i - 1].inventory)
            for i, obs in enumerate(observations)
            if i > 0
        ]
        max_shipment_rate = max(max(obs.inbound, obs.outbound) for obs in observations)

        temp_values = [obs.temperature for obs in observations]
        humidity_values = [obs.humidity for obs in observations]

        candidates = [
            InvariantCandidate(
                candidate_id="INV-CAPACITY-RESIDUAL",
                name="Learned capacity balance",
                family="capacity",
                kind="residual",
                description="inventory + free_capacity approximately equals total_capacity",
                tolerance=_learn_tolerance(capacity_residuals, floor=0.10),
                duplicate_of="C1",
            ),
            InvariantCandidate(
                candidate_id="INV-FLOW-RESIDUAL",
                name="Learned inventory flow balance",
                family="flow",
                kind="residual",
                description="inventory equals prior inventory plus inbound minus outbound",
                tolerance=_learn_tolerance(flow_residuals, floor=0.10),
                duplicate_of="C2",
            ),
            InvariantCandidate(
                candidate_id="INV-OCCUPANCY-IDENTITY",
                name="Occupancy identity",
                family="occupancy",
                kind="residual",
                description="reported occupancy matches inventory / capacity",
                tolerance=_learn_tolerance(occupancy_residuals, floor=0.25),
            ),
            InvariantCandidate(
                candidate_id="INV-TEMP-ENVELOPE",
                name="Learned temperature envelope",
                family="temperature",
                kind="envelope",
                description="temperature stays inside the historical normal envelope",
                tolerance=0.0,
                field="temperature",
                parameters={
                    "min": round(min(temp_values) - 0.10, 3),
                    "max": round(max(temp_values) + 0.10, 3),
                },
            ),
            InvariantCandidate(
                candidate_id="INV-HUMIDITY-ENVELOPE",
                name="Learned humidity envelope",
                family="humidity",
                kind="envelope",
                description="humidity stays inside the historical normal envelope",
                tolerance=0.0,
                field="humidity",
                parameters={
                    "min": round(min(humidity_values) - 0.50, 3),
                    "max": round(max(humidity_values) + 0.50, 3),
                },
            ),
            InvariantCandidate(
                candidate_id="INV-TEMP-SLEW",
                name="Temperature slew limit",
                family="temperature",
                kind="slew",
                description="single-step temperature changes stay within normal slew bounds",
                tolerance=_learn_tolerance(temperature_slew, floor=0.20, quantile=0.995, margin=1.30),
                field="temperature",
            ),
            InvariantCandidate(
                candidate_id="INV-HUMIDITY-SLEW",
                name="Humidity slew limit",
                family="humidity",
                kind="slew",
                description="single-step humidity changes stay within normal slew bounds",
                tolerance=_learn_tolerance(humidity_slew, floor=0.80, quantile=0.995, margin=1.30),
                field="humidity",
            ),
            InvariantCandidate(
                candidate_id="INV-INVENTORY-SLEW",
                name="Inventory slew limit",
                family="inventory",
                kind="slew",
                description="single-step inventory changes stay within normal shipment bounds",
                tolerance=_learn_tolerance(inventory_slew, floor=1.00, quantile=0.995, margin=1.30),
                field="inventory",
            ),
            InvariantCandidate(
                candidate_id="INV-SHIPMENT-RATE",
                name="Shipment rate envelope",
                family="shipment",
                kind="rate",
                description="inbound and outbound rates stay within the historical maximum",
                tolerance=round(max(settings.MAX_SHIPMENT_RATE, max_shipment_rate * 1.05), 4),
            ),
        ]

        for candidate in candidates:
            self.candidates[candidate.candidate_id] = candidate
            candidate.discovery_coverage = 1.0
            self._log(
                "INVARIANT_CANDIDATE_DISCOVERED",
                "INFO",
                f"Discovered invariant candidate {candidate.candidate_id} "
                f"(tolerance={candidate.tolerance:.4f}).",
                metadata={
                    "candidate_id": candidate.candidate_id,
                    "family": candidate.family,
                    "tolerance": candidate.tolerance,
                },
            )
        logger.info("Mined %d candidate invariants from %d observations.", len(candidates), len(observations))
        return candidates

    def _coverage(self, candidate: InvariantCandidate, observations: Sequence[WarehouseObservation]) -> float:
        active = ActiveInvariant.from_candidate(candidate)
        failed = 0
        previous = None
        for observation in observations:
            result = active.check(observation, previous)
            if result.status == "VIOLATED":
                failed += 1
            previous = observation
        return 1.0 - (failed / len(observations) if observations else 0.0)

    def _signature(
        self,
        candidate: InvariantCandidate,
        observations: Sequence[WarehouseObservation],
    ) -> List[bool]:
        active = ActiveInvariant.from_candidate(candidate)
        signature = []
        previous = None
        for observation in observations:
            signature.append(active.check(observation, previous).status == "VIOLATED")
            previous = observation
        return signature

    def _base_signatures(
        self,
        attack_observations: Sequence[WarehouseObservation],
    ) -> Dict[str, List[bool]]:
        c1_signature = []
        c2_signature = []
        previous = None
        for observation in attack_observations:
            c1_signature.append(
                abs(observation.inventory + observation.free_capacity - observation.capacity)
                > settings.C1_CAPACITY_TOLERANCE
            )
            if previous is None:
                c2_signature.append(False)
            else:
                expected = previous.inventory + observation.inbound - observation.outbound
                c2_signature.append(abs(observation.inventory - expected) > settings.C2_FLOW_TOLERANCE)
            previous = observation
        return {"C1": c1_signature, "C2": c2_signature}

    def validate(
        self,
        candidates: Optional[Sequence[InvariantCandidate]] = None,
        normal_records: Optional[Sequence[Any]] = None,
        attack_records: Optional[Sequence[Any]] = None,
    ) -> List[InvariantCandidate]:
        """Validate candidates on independent normal and attack observations."""
        if normal_records is None or attack_records is None:
            raise ValueError("Independent normal and attack validation records are required")
        normal_observations = _as_observations(normal_records)
        attack_observations = _as_observations(attack_records)
        if not normal_observations or not attack_observations:
            raise ValueError("Validation requires both normal and attack observations")

        candidates = list(candidates) if candidates is not None else list(self.candidates.values())
        base_signatures = self._base_signatures(attack_observations)

        for candidate in candidates:
            coverage = self._coverage(candidate, normal_observations)
            attack_signature = self._signature(candidate, attack_observations)
            detection = sum(attack_signature) / len(attack_signature)
            fpr = 1.0 - coverage

            # Stability: both halves of the normal validation set must hold.
            midpoint = max(1, len(normal_observations) // 2)
            first_coverage = self._coverage(candidate, normal_observations[:midpoint])
            second_coverage = self._coverage(candidate, normal_observations[midpoint:])
            stability_gap = abs(first_coverage - second_coverage)

            per_class: Dict[str, List[bool]] = {}
            for record, flagged in zip(attack_records, attack_signature):
                attack_type = getattr(record, "attack_type", None) or "unknown"
                per_class.setdefault(attack_type, []).append(flagged)

            candidate.validation_coverage = round(coverage, 6)
            candidate.false_positive_rate = round(fpr, 6)
            candidate.attack_detection_rate = round(detection, 6)
            candidate.stability_gap = round(stability_gap, 6)
            candidate.per_class_detection = {
                attack_type: round(sum(flags) / len(flags), 4) if flags else 0.0
                for attack_type, flags in sorted(per_class.items())
            }
            candidate.validated_at = datetime.now(timezone.utc).isoformat()

            if coverage < self.min_normal_coverage or fpr > self.max_fpr:
                candidate.status = "REJECTED"
                candidate.rejection_reason = (
                    f"Unstable or overly restrictive: normal coverage {coverage:.4f} "
                    f"(minimum {self.min_normal_coverage:.4f}) implies FPR {fpr:.4f}."
                )
            elif stability_gap > self.max_stability_gap:
                candidate.status = "REJECTED"
                candidate.rejection_reason = (
                    f"Unstable coverage across normal validation halves (gap {stability_gap:.4f})."
                )
            elif detection < self.min_attack_detection:
                candidate.status = "REJECTED"
                candidate.rejection_reason = (
                    f"Does not discriminate known attacks (detection {detection:.4f} "
                    f"< minimum {self.min_attack_detection:.4f})."
                )
            else:
                candidate.status = "VALIDATED"
                candidate.rejection_reason = None

            self._log(
                "INVARIANT_CANDIDATE_VALIDATED" if candidate.status == "VALIDATED" else "INVARIANT_CANDIDATE_REJECTED",
                "INFO" if candidate.status == "VALIDATED" else "WARNING",
                f"Candidate {candidate.candidate_id}: status={candidate.status}, "
                f"coverage={coverage:.4f}, attack_detection={detection:.4f}.",
                metadata={
                    "candidate_id": candidate.candidate_id,
                    "status": candidate.status,
                    "coverage": coverage,
                    "attack_detection": detection,
                    "rejection_reason": candidate.rejection_reason,
                },
            )

        # Redundancy pass: drop rules that merely duplicate a stronger accepted
        # rule or an existing hard constraint on the same validation attacks.
        accepted: List[InvariantCandidate] = []
        ordered = sorted(
            [c for c in candidates if c.status == "VALIDATED"],
            key=lambda c: c.attack_detection_rate,
            reverse=True,
        )
        accepted_signatures: Dict[str, List[bool]] = {}
        for candidate in ordered:
            signature = self._signature(candidate, attack_observations)
            duplicate_of = candidate.duplicate_of
            if duplicate_of in base_signatures:
                if _jaccard(signature, base_signatures[duplicate_of]) >= self.redundancy_jaccard:
                    candidate.status = "REJECTED"
                    candidate.rejection_reason = (
                        f"Redundant with existing {duplicate_of} constraint on validation attacks."
                    )
                    continue
            redundant_with = None
            for existing in accepted:
                if _jaccard(signature, accepted_signatures[existing.candidate_id]) >= self.redundancy_jaccard:
                    redundant_with = existing.candidate_id
                    break
            if redundant_with is not None:
                candidate.status = "REJECTED"
                candidate.rejection_reason = f"Redundant with accepted invariant {redundant_with}."
                continue
            accepted.append(candidate)
            accepted_signatures[candidate.candidate_id] = signature

        for candidate in candidates:
            if candidate.status == "VALIDATED":
                self._log(
                    "INVARIANT_CANDIDATE_ACCEPTED",
                    "INFO",
                    f"Candidate {candidate.candidate_id} passed validation and redundancy gates.",
                    metadata={"candidate_id": candidate.candidate_id},
                )
        return candidates

    def get_candidates(self, status: Optional[str] = None) -> List[InvariantCandidate]:
        values = list(self.candidates.values())
        if status is None:
            return values
        return [candidate for candidate in values if candidate.status == status]

    def activate(
        self,
        semantic_engine: Optional[Any] = None,
        candidate_ids: Optional[Sequence[str]] = None,
        operator_approved: bool = False,
    ) -> List[ActiveInvariant]:
        """Install validated invariants after explicit operator approval."""
        if not operator_approved:
            raise PermissionError(
                "Invariant activation requires explicit operator approval (operator_approved=True)."
            )
        selected = [
            candidate
            for candidate in self.candidates.values()
            if candidate.status == "VALIDATED"
            and (candidate_ids is None or candidate.candidate_id in candidate_ids)
        ]
        if not selected:
            raise ValueError("No validated invariant candidates available for activation")

        active_invariants = []
        for candidate in selected:
            active = ActiveInvariant.from_candidate(candidate)
            if semantic_engine is not None:
                semantic_engine.add_invariant(active)
            candidate.status = "ACTIVE"
            candidate.activated_at = datetime.now(timezone.utc).isoformat()
            active_invariants.append(active)
            self._log(
                "INVARIANT_ACTIVATED",
                "ALERT",
                f"Operator activated mined invariant {candidate.candidate_id}.",
                metadata={
                    "candidate_id": candidate.candidate_id,
                    "tolerance": candidate.tolerance,
                    "validation_coverage": candidate.validation_coverage,
                    "attack_detection_rate": candidate.attack_detection_rate,
                },
            )
        return active_invariants

    def rollback(self, semantic_engine: Optional[Any] = None) -> List[str]:
        """Remove all active mined invariants and restore baseline semantics."""
        rolled_back = []
        for candidate in self.candidates.values():
            if candidate.status == "ACTIVE":
                candidate.status = "ROLLED_BACK"
                rolled_back.append(candidate.candidate_id)
        if semantic_engine is not None and hasattr(semantic_engine, "clear_invariants"):
            semantic_engine.clear_invariants()
        self._log(
            "INVARIANT_ROLLED_BACK",
            "WARNING",
            f"Rolled back {len(rolled_back)} active mined invariant(s).",
            metadata={"candidate_ids": rolled_back},
        )
        return rolled_back
